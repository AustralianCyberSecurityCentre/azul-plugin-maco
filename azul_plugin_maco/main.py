"""Extract malware configuration with scripts using the maco framework.

https://github.com/CybercentreCanada/Maco
"""

import datetime
import glob
import os
import tempfile
import traceback
from shutil import copytree, rmtree
from typing import Any

from azul_runner import (
    FV,
    BinaryPlugin,
    Event,
    Feature,
    FeatureType,
    Job,
    State,
    add_settings,
    cmdline_run,
)
from maco import collector

from . import mapper


class ExtractorOtherMappingException(Exception):
    """Exception for error while mapping 'other'."""

    pass


class ExtractorNoneFoundException(Exception):
    """There were no maco extractors loaded."""

    pass


_FEATURE_NAMES = [v.value for v in FeatureType]


def _load_dynamic_features(raw_features: dict[str, str]) -> list[Feature]:
    """Loads dynamic features from the environment, if any are defined."""
    # A pipe ('|') delimits the description of the feature and the type of the feature
    # Feature types are lower case
    # Example environmental variable:
    #   PLUGIN_CUSTOM_FEATURES =
    #     {
    #       "BADMALWARE_EXEC_PATH": "Where bad malware stores executables|filepath"
    #     }

    features = []

    for name, value in raw_features.items():
        lower_name = name.lower()
        desc, feat_type = value.split("|")

        # Attempt to match the feature type
        lower_feat_type = feat_type.lower()
        if lower_feat_type not in _FEATURE_NAMES:
            print("Available feature types: ", _FEATURE_NAMES)
            raise Exception("Failed to find feature type for environmental variable: " + name)

        feat_type = FeatureType(lower_feat_type)

        features.append(Feature(lower_name, desc, type=feat_type))

    return features


class AzulPluginMaco(BinaryPlugin):
    """Extract malware configuration with scripts using the maco framework."""

    CONTACT = "ASD's ACSC"
    VERSION = "2025.06.18"
    SETTINGS = add_settings(
        filter_data_types={"content": []},  # run on any content type
        filter_max_content_size="1GiB",  # max file size to process
        scripts=(str, ""),
        exclude=(list[str], []),
        include=(list[str], []),
        security_map=(dict[str, str], {}),
        custom_features=(dict, {}),
        jobs_between_clearing_pycs=(int, 1000),
        create_venv=(bool, True),
    )

    # Features common to multiple extractors only
    # See above on how to specify custom features
    _BASE_FEATURES = [
        # basic
        Feature("family", desc="family of malware that was detected", type=FeatureType.String),
        Feature("file_format_legacy", desc="legacy format of a file from maco", type=FeatureType.String),
        Feature("version", desc="version/variant of malware", type=FeatureType.String),
        Feature("category", desc="capability/purpose of the malware", type=FeatureType.String),
        Feature("attack", desc="mitre att&ck reference ids, e.g. 'T1129'", type=FeatureType.String),
        Feature(
            "capability_enabled",
            desc="capabilities of the malware enabled in config",
            type=FeatureType.String,
        ),
        Feature(
            "capability_disabled",
            desc="capabilities of the malware disabled in config",
            type=FeatureType.String,
        ),
        Feature("campaign_id", desc="server/campaign id for malware", type=FeatureType.String),
        Feature("identifier", desc="uuid/identifiers for deployed instance", type=FeatureType.String),
        Feature("decoded_strings", desc="decoded strings from within malware", type=FeatureType.String),
        Feature("password", desc="Any password extracted from the binary", type=FeatureType.String),
        Feature("mutex", desc="mutex to prevent multiple instances", type=FeatureType.String),
        Feature("pipe", desc="pipe name used for communication", type=FeatureType.String),
        Feature("sleep_delay", desc="time to sleep/delay execution (milliseconds)", type=FeatureType.Integer),
        Feature(
            "sleep_delay_jitter",
            desc="additional time applied to sleep_delay (milliseconds)",
            type=FeatureType.Integer,
        ),
        Feature("inject_exe", desc="name of executable to inject into", type=FeatureType.String),
        # connections
        Feature("connection", desc="all connections", type=FeatureType.Uri),
        Feature("connection_c2", desc="a connection for c2", type=FeatureType.Uri),
        Feature("connection_upload", desc="a connection for upload", type=FeatureType.Uri),
        Feature("connection_download", desc="a connection for download", type=FeatureType.Uri),
        Feature("connection_propagate", desc="a connection to propagate", type=FeatureType.Uri),
        Feature("connection_tunnel", desc="a connection to tunnel", type=FeatureType.Uri),
        Feature("connection_ransom", desc="a connection for payment of a ransom", type=FeatureType.Uri),
        Feature("connection_decoy", desc="a decoy connection to obfuscate malware operations", type=FeatureType.Uri),
        Feature("connection_other", desc="a connection for any custom/specific purpose", type=FeatureType.Uri),
        # credentials
        # specific protocol information
        # smtp
        Feature("mail", desc="email addresses", type=FeatureType.String),
        Feature("mail_to", desc="receivers of email", type=FeatureType.String),
        Feature("mail_from", desc="sender of email", type=FeatureType.String),
        Feature("mail_subject", desc="subject of email", type=FeatureType.String),
        # http
        Feature("user_agent", desc="user agent of http request/response", type=FeatureType.String),
        Feature("method", desc="http method of request", type=FeatureType.String),
        Feature("headers", desc="http headers", type=FeatureType.String),
        Feature("header_fields", desc="http header fields", type=FeatureType.String),
        Feature("header_values", desc="http header values", type=FeatureType.String),
        Feature("max_size", desc="max size of http body", type=FeatureType.Integer),
        # dns
        Feature("record_type", desc="the DNS record type being queried", type=FeatureType.String),
        Feature("dns_hostname", desc="the hostname being queried", type=FeatureType.String),
        # icmp
        Feature("icmp_type", desc="ICMP header type byte", type=FeatureType.Integer),
        Feature("icmp_code", desc="ICMP header code byte", type=FeatureType.Integer),
        Feature("icmp_header", desc="ICMP header", type=FeatureType.String),
        # generic connection
        Feature("client", desc="client connection information for a protocol", type=FeatureType.Uri),
        # encryption
        Feature("algorithm", desc="all encryption algorithms", type=FeatureType.String),
        Feature("algorithm_config", desc="algorithm of encrypted config", type=FeatureType.String),
        Feature("algorithm_communication", desc="algorithm of encrypted communications", type=FeatureType.String),
        Feature("algorithm_binary", desc="algorithm of encrypted binary data", type=FeatureType.String),
        Feature("algorithm_ransom", desc="algorithm of encrypting user data", type=FeatureType.String),
        Feature("algorithm_other", desc="algorithm of other encrypted data", type=FeatureType.String),
        Feature("public_key", desc="public key", type=FeatureType.String),
        Feature("key", desc="private/symmetric key", type=FeatureType.String),
        Feature("provider", desc="provider or library providing encryption", type=FeatureType.String),
        Feature("mode", desc="block or stream encryption mode", type=FeatureType.String),
        Feature("iv", desc="Initialization Vector used to seed cryptographic operations", type=FeatureType.String),
        Feature("seed", desc="Seed value used for initalizing a random process.", type=FeatureType.String),
        Feature("nonce", desc="Initialization for cryptographic operations.", type=FeatureType.String),
        Feature("constants", desc="Constant values used during encryption.", type=FeatureType.String),
        # service
        Feature("service", desc="windows service ID", type=FeatureType.String),
        Feature("service_dll", desc="windows service dll", type=FeatureType.String),
        Feature("service_display", desc="windows service display name", type=FeatureType.String),
        Feature("service_description", desc="windows service description", type=FeatureType.String),
        # crypto
        Feature("coin", desc="all cryptocurrency coin exchange names", type=FeatureType.String),
        Feature(
            "coin_ransomware",
            desc="exchange name of cryptocurrency coin used for ransom payment",
            type=FeatureType.String,
        ),
        Feature("coin_miner", desc="exchange name of cryptocurrency coin mined by malware", type=FeatureType.String),
        Feature(
            "coin_other",
            desc="exchange name of cryptocurrency coin used for specific purpose",
            type=FeatureType.String,
        ),
        Feature("coin_address", desc="cryptocurrency wallet or address", type=FeatureType.String),
        Feature("ransom_amount", desc="amount requested for ransom payment", type=FeatureType.Float),
        # path
        Feature("path", desc="a path to a file/folder", type=FeatureType.Filepath),
        Feature("path_c2", desc="file/folder issues commands to malware", type=FeatureType.Filepath),
        Feature("path_config", desc="config is loaded from this path", type=FeatureType.Filepath),
        Feature("path_install", desc="install directory/filename for malware", type=FeatureType.Filepath),
        Feature("path_plugins", desc="load new capability from this directory", type=FeatureType.Filepath),
        Feature("path_logs", desc="location to log activity", type=FeatureType.Filepath),
        Feature("path_storage", desc="location to store/backup copied files", type=FeatureType.Filepath),
        Feature(
            "path_other",
            desc="a path to a file/folder for other purposes",
            type=FeatureType.Filepath,
        ),
        # registry
        Feature("registry", desc="a registry key", type=FeatureType.String),
        Feature("registry_persistence", desc="a registry key for persistence", type=FeatureType.String),
        Feature("registry_store_data", desc="a registry key for data", type=FeatureType.String),
        Feature("registry_store_payload", desc="a registry key for payload", type=FeatureType.String),
        Feature("registry_read", desc="a registry key for reading", type=FeatureType.String),
        Feature("registry_other", desc="a registry key for other purposes", type=FeatureType.String),
        # mappings for 'other' / 'binaries.other' features
        Feature(
            "config_offset", desc="file offset to the beginning of the configuration block", type=FeatureType.Integer
        ),
        Feature("config_size", desc="size of the configuration block", type=FeatureType.Integer),
        Feature("config_type", desc="type of the configuration block", type=FeatureType.String),
        Feature("config_marker", desc="marker used to indicate start/end of config", type=FeatureType.String),
        Feature("payload_type", desc="type of payload", type=FeatureType.String),
        Feature("detected_processes", desc="processes the malware searches for", type=FeatureType.String),
        Feature("task_scheduler_name", desc="name of scheduled task", type=FeatureType.String),
        Feature("task_scheduler_path", desc="path of scheduled task", type=FeatureType.String),
        Feature("task_scheduler_start_date", desc="start date and time for scheduled task", type=FeatureType.String),
        Feature(
            "task_scheduler_repeat_interval",
            desc="repeat interval of scheduled task once started",
            type=FeatureType.String,
        ),
        Feature(
            "task_scheduler_arguments", desc="arguments passed through to the scheduled task", type=FeatureType.String
        ),
        Feature(
            "network_timeout",
            desc="how long network traffic is waited for before timeout (in ms)",
            type=FeatureType.Integer,
        ),
        Feature(
            "loop_delay",
            desc="delay time before looping through functionality again (in ms)",
            type=FeatureType.Integer,
        ),
        Feature("unknown_config", desc="config data which is unused or has unknown purpose", type=FeatureType.Integer),
        Feature(
            "config_section_name", desc="name of the file section used to store the config", type=FeatureType.String
        ),
        Feature("c2_instructions", desc="modifications applied to comms structure", type=FeatureType.String),
        Feature("http_get_metadata", desc="modifications applied to http get requests", type=FeatureType.String),
        Feature(
            "http_post_metadata",
            desc="modifications applied to http post requests",
            type=FeatureType.String,
        ),
        Feature("ssh_banner", desc="ssh protocol version string", type=FeatureType.String),
        Feature("watermark", desc="licensing watermark", type=FeatureType.String),
        Feature("kill_date", desc="date the implant will cease functioning", type=FeatureType.Datetime),
        Feature(
            "bytes_inject_prepend_append_x86",
            desc="bytes inserted into the implant, either before and after the main body is executed",
            type=FeatureType.String,
        ),
        Feature(
            "bytes_inject_prepend_append_x64",
            desc="bytes inserted into the implant, either before and after the main body is executed",
            type=FeatureType.String,
        ),
        Feature("builder_hash", desc="hash of the implant builder", type=FeatureType.String),
        Feature("release_notes_hash", desc="hash of the release notes text", type=FeatureType.String),
        Feature("smb_frame_data", desc="data to append to smb packets", type=FeatureType.String),
        Feature("tcp_frame_data", desc="date to append to tcp packets", type=FeatureType.String),
        # intended to hold variable names extracted from scripts
        Feature(
            "script_variable",
            desc="name of interesting variables used within a script file",
            type=FeatureType.String,
        ),
        # E.g. base64 string, binary data, hex strings
        Feature("language", desc="detected programming language", type=FeatureType.String),
        Feature("payload_format", desc="Data format of the payload", type=FeatureType.String),
        Feature("payload_filename", desc="Filename of the payload", type=FeatureType.Filepath),
        Feature("compression", desc="Compression algorithm", type=FeatureType.String),
        Feature("app_domain", desc=".NET application domain", type=FeatureType.String),
        Feature("clr_version", desc=".NET CLR version", type=FeatureType.String),
        Feature("runtime_parameters", desc="Parameters passed to the binary at runtime", type=FeatureType.String),
        Feature("runtime_method", desc="Method invoked at runtime", type=FeatureType.String),
        Feature("runtime_class", desc="Class invoked at runtime", type=FeatureType.String),
        Feature("config_file_extensions", desc="File extensions targeted by the binary", type=FeatureType.String),
        Feature("payload_parent_filename", desc="Name of file which spawned the payload.", type=FeatureType.Filepath),
        Feature("config_layout", desc="Configuration layout format string", type=FeatureType.String),
    ]

    # This is defined here to configure the MRO; this gets dynamically updated each invocation even if
    # it is "static"
    FEATURES = []

    def __init__(self, config: dict[str, dict[str, Any]] = None) -> None:
        # Update features with anything that is dynamically configured by the environment
        # (do this each time to make testing easier)
        # This needs to happen before the parent init as that probes features
        AzulPluginMaco.FEATURES = AzulPluginMaco._BASE_FEATURES
        custom_features = []
        if config:
            # The config may or may not be parsed yet:
            if isinstance(config, dict):
                if "custom_features" in config:
                    custom_features = _load_dynamic_features(config["custom_features"])
            else:
                custom_features = _load_dynamic_features(config.custom_features)

            AzulPluginMaco.FEATURES += custom_features

        super().__init__(config)

        self.logger.info(f"Loaded {len(custom_features)} custom features")

        self.job_count = 0

        self._FEATURE_TYPES = dict([(feature.name, feature.type) for feature in self.FEATURES])

        # different MACO repos may have different security/sharing lables than those configured in Azul
        self.logger.debug(f"{self.cfg.security_map=}")

        # copy scripts to tmp dir (venv creation triggers runner watch restart)
        script_path = os.path.join(tempfile.gettempdir(), "azul-maco")
        if os.path.exists(script_path):
            rmtree(script_path)
        # ignore_dangling_symlinks to allow late creation of symlinked files
        copytree(self.cfg.scripts, script_path, ignore_dangling_symlinks=True)

        # venv config exposed only to support quicker testing.
        self.collected = collector.Collector(
            script_path, include=self.cfg.include, exclude=self.cfg.exclude, create_venv=self.cfg.create_venv
        )
        self.runs = {}

        def gen(_script):
            """We have to 'cook' the lambda to lock the decoder variable."""
            return lambda x: self.execute_script(_script, x)

        if not self.collected.extractors:
            raise ExtractorNoneFoundException(
                f"No maco extractors found with {script_path=} {self.cfg.include=} {self.cfg.exclude=}"
            )

        for name, extr_details in self.collected.extractors.items():
            try:
                extr = extr_details["metadata"]
                self.logger.info(f"found extractor {name}")
                if extr["sharing"]:
                    sharing_label = extr["sharing"].upper()
                    security = self.cfg.security_map.get(sharing_label, sharing_label)
                    self.logger.info(f"extractor {name} has custom security {security}")
                else:
                    security = self.SECURITY
                    self.logger.info(f"extractor {name} has base security {security}")

                # use maco extractor description if specified
                descr = f"Maco extractor for {extr['family']}."
                if extr["description"]:
                    try:
                        descr = (extr["description"].partition(".")[0] + ".")[:100].replace("\n", "")
                    except Exception as e:
                        self.logger.error(f"could not generate description for {name} {str(e)}")

                self.register_multiplugin(name, None, gen(name), description=descr, security=security)
            except Exception:
                self.logger.error(f"could not register extractor {name}: {traceback.format_exc()}")
                continue

    def _clear_pycs(self):
        """Clear pyc files that build up in tmp overtime due to issues with maco."""
        remove_count = 0
        for pyc_path in glob.glob(os.path.join(tempfile.gettempdir(), "**", "*.pyc"), recursive=True):
            if "/venv/" not in pyc_path:
                try:
                    os.remove(pyc_path)
                    remove_count += 1
                except Exception:  # noqa: S110
                    pass
        self.logger.info(f"Cleaned up {remove_count} pyc files.")

    def execute(self, job: Job):
        """Determine which malware config extractor scripts should run."""
        data = job.get_data()
        self.runs = self.collected.match(data)

        self.job_count += 1
        if self.job_count > self.cfg.jobs_between_clearing_pycs:
            self.job_count = 0
            self._clear_pycs()

        if not self.runs:
            # FUTURE completed-empty when multi-plugins are supported
            return State(
                label=State.Label.OPT_OUT,
                failure_name="no_match_all",
                message="Failed to match with any maco extractors.",
            )

        return State.Label.COMPLETED

    def execute_script(self, name: str, job: Job):
        """Execute a specific malware config extractor script."""
        if name not in self.runs:
            return State(
                label=State.Label.OPT_OUT,
                failure_name="no_match_single",
                message="Failed to match with this maco extractor.",
            )

        # execute the actual script
        data = job.get_data()
        result = self.collected.extract(data, name)
        if not result:
            # FUTURE completed-empty when multi-plugins are supported
            return State(
                label=State.Label.OPT_OUT,
                failure_name="no_results",
                message="Maco extractor ran but returned no results.",
            )

        # map all feature and children
        mappedData: mapper.MappedData = mapper.map_config(result)
        if mappedData.features:
            self.add_many_feature_values(mappedData.features)

        if mappedData.children:
            # default parent is the submitted binary
            found_binaries = {None: self}
            for child in mappedData.children:
                parent_id = None
                # get parent if in child other dict, otherwise default to primary entity
                if child.other.get("version", None) == "azul_v1":
                    parent_id = child.other.pop("child_of", None)
                if parent := found_binaries.get(parent_id):
                    event = parent.add_child_with_data(child.relationship, child.data)
                    event.add_many_feature_values(child.features)
                    self._process_other(child.other, event)
                    # allow for grandchildren and deeper relationships
                    found_binaries[event.sha256] = event
                else:
                    raise Exception(f"Could not find parent {parent_id} in {list(found_binaries.keys())}")
        if mappedData.other:
            self._process_other(mappedData.other, self._event_main)

    def _transform_generic_value(self, type: FeatureType, value):
        """Hydrate a feature value into a native type."""
        if type == FeatureType.Datetime:
            # Transform a datetime into a proper object
            return datetime.datetime.fromisoformat(value)
        else:
            # Pass through other values is-is
            return value

    def _map_generic_values(self, type: FeatureType, values):
        """Transform input into list of Azul FeatureValues."""
        # turn everything into a list
        if not isinstance(values, list):
            values = [values]
        # generate a FV for each element
        out = []
        for y in values:
            if not isinstance(y, dict):
                out.append(FV(self._transform_generic_value(type, y)))
            else:
                y.update(value=self._transform_generic_value(type, y["value"]))
                out.append(FV(**y))
        return out

    def _process_other(self, other: dict, target: Event):
        """Add properties as defined in 'other'."""
        # if the version is azul_v1, all 'other' entries are expected to be mapped to azul.
        # if the version is not azul_v1, 'other' is ignored.
        if other.pop("version", None) == "azul_v1":
            try:
                # map feature values
                other_features = other.pop("features", {})

                # Map any maco feature values
                mapped, remaining_features = mapper.map_child_maco_features(other_features)
                if mapped.features:
                    target.add_many_feature_values(mapped.features)

                # Map the remaining feature values
                for k, v in remaining_features.items():
                    target.add_feature_values(k, self._map_generic_values(self._FEATURE_TYPES[k], v))

                # map a text report generated by decoder
                if report := other.pop("report", None):
                    target.add_text(report)

                if len(other) > 0:
                    raise Exception(f"'other' contains unmapped data: {other}")
            except Exception as e:
                raise ExtractorOtherMappingException(
                    f"Mapping of maco azul-formatted 'other' dictionary failed: ({str(e)})"
                ) from e


def main():
    """Plugin command-line entrypoint."""
    cmdline_run(plugin=AzulPluginMaco)


if __name__ == "__main__":
    main()
