"""Test cases for plugin output."""

import datetime
import os
import tempfile

from azul_runner import (
    Event,
    EventData,
    EventParent,
    FeatureValue,
    Filepath,
    JobResult,
    State,
    Uri,
    test_template,
)
from maco import extractor
from maco.collector import ExtractorLoadError

from azul_plugin_maco.main import AzulPluginMaco

FV = FeatureValue
FVU = lambda x: FeatureValue(Uri(x))
FVP = lambda x: FeatureValue(Filepath(x))


class Basic(extractor.Extractor):
    author = "me"
    family = "evil"
    last_modified = "2020-02-02"
    yara_rule = """
    rule TmpScript
    {
        condition:
            true
    }
    """


_TDIR = os.path.dirname(os.path.realpath(__file__))


class TestExecute(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginMaco

    def setUp(self):
        super().setUp()
        os.environ["plugin_scripts"] = os.path.join(_TDIR, "extractors", "basic")

    def test_none(self):
        """Test optout of main is only thing returned."""
        with tempfile.TemporaryDirectory() as tempdir:
            self.assertRaises(ExtractorLoadError, AzulPluginMaco, config={"create_venv": "false", "scripts": tempdir})

    def test_registration(self):
        """Test registration variants."""

        # apply security mapping to prepend official if only tlp is defined
        config = {
            "scripts": os.path.join(_TDIR, "extractors", "mapping", "registration"),
            "security_map": {"TLP:CLEAR": "OFFICIAL TLP:CLEAR"},
        }

        inst = AzulPluginMaco(config=config)
        self.assertEqual(
            [None, "Base", "Clear", "Description", "PartialMatch", "UnknownMapping", "UnspecifiedSharing"],
            list(inst._multiplugins.keys()),
        )
        self.assertEqual("Maco extractor for evil.", inst._multiplugins["Clear"].description)
        self.assertEqual("OFFICIAL TLP:CLEAR", inst._multiplugins["Clear"].security)

        # Description edge case
        self.assertEqual("My lazy description with no fullstop.", inst._multiplugins["Description"].description)

        # when plugin base security configured
        class APE(AzulPluginMaco):
            SECURITY = "OFFICIAL"

        inst = APE(config=config)
        self.assertEqual(
            [None, "Base", "Clear", "Description", "PartialMatch", "UnknownMapping", "UnspecifiedSharing"],
            list(inst._multiplugins.keys()),
        )
        self.assertEqual("Maco extractor for evil.", inst._multiplugins["Clear"].description)
        self.assertEqual("OFFICIAL TLP:CLEAR", inst._multiplugins["Clear"].security)

        # Use plugin security if extractor unspecified
        self.assertEqual("OFFICIAL", inst._multiplugins["UnspecifiedSharing"].security)

        # Extractor classification unchanged if there is no mapping for it
        self.assertEqual("FISHFINGERS TLP:CLEAR", inst._multiplugins["UnknownMapping"].security)

        # Extractor classification unchanged if there is a partial mapping for it
        self.assertEqual("OFFICIAL TLP:AMBER", inst._multiplugins["PartialMatch"].security)

    def test_optout(self):
        """Test optout of main is only thing returned."""

        data = b"a normal run"

        result = self.do_execution(
            data_in=[("content", data)],
            config={"create_venv": "false", "scripts": os.path.join(_TDIR, "extractors", "mapping", "optout")},
            no_multiprocessing=True,
        )

        self.assertJobResult(
            result,
            JobResult(
                state=State(
                    State.Label.OPT_OUT,
                    failure_name="no_match_all",
                    message="Failed to match with any maco extractors.",
                )
            ),
        )

    def test_trivial(self):
        """Test a simple result."""
        data = b"a normal run"

        result = self.do_execution(
            data_in=[("content", data)],
            config={"create_venv": "false", "scripts": os.path.join(_TDIR, "extractors", "mapping", "trivial")},
            no_multiprocessing=True,
        )

        self.assertJobResult(result[None], JobResult(state=State(State.Label.COMPLETED_EMPTY)))
        self.assertJobResult(
            result["Trivial"],
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="874b79e5e72899321c28e872d892a957ff8141d6f21128b69dd7da25bc558fb7",
                        features={"family": [FV("random")]},
                    )
                ],
            ),
        )

    def test_feature_list(self):
        """Test that multiple features with the same key can be added."""

        data = b"a normal run"

        result = self.do_execution(
            data_in=[("content", data)],
            config={"create_venv": "false", "scripts": os.path.join(_TDIR, "extractors", "mapping", "feature_list")},
            no_multiprocessing=True,
        )

        self.assertJobResult(result[None], JobResult(state=State(State.Label.COMPLETED_EMPTY)))
        self.assertJobResult(
            result["FeatureList"],
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="874b79e5e72899321c28e872d892a957ff8141d6f21128b69dd7da25bc558fb7",
                        features={
                            "family": [FV("malware")],
                            "client": [
                                FV(Uri("tcp://1.2.3.4:5678"), label="tcp://9.10.11.12:13"),
                                FV(Uri("tcp://14.15.16.17:1819"), label="tcp://20.21.22.23:24"),
                            ],
                            "connection": [
                                FV(Uri("tcp://20.21.22.23:24"), label="upload"),
                                FV(Uri("tcp://9.10.11.12:13"), label="upload"),
                            ],
                            "connection_upload": [FV(Uri("tcp://20.21.22.23:24")), FV(Uri("tcp://9.10.11.12:13"))],
                        },
                    )
                ],
            ),
        )

    def test_bad_data(self):
        """Test that model finds returned data to be invalid."""

        data = b"a normal run"

        result = self.do_execution(
            data_in=[("content", data)],
            config={"create_venv": "false", "scripts": os.path.join(_TDIR, "extractors", "mapping", "bad_data")},
            no_multiprocessing=True,
        )["BadData"]
        self.assertEqual(result.state.label, State.Label.ERROR_EXCEPTION)

    def test_relationship_mapping(self):
        """Test mapping of the child binary relationship attribute."""

        data = b"a normal run"
        child_data_1 = rb"\x10\x20\x30\x40"
        child_data_2 = rb"\x90\xA0\xB0\xC0"

        result = self.do_execution(
            data_in=[("content", data)],
            config={
                "create_venv": "false",
                "scripts": os.path.join(_TDIR, "extractors", "mapping", "relationship_mapping"),
            },
            no_multiprocessing=True,
        )

        self.assertJobResult(result[None], JobResult(state=State(State.Label.COMPLETED_EMPTY)))
        self.assertJobResult(
            result["RelationshipMapping"],
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="874b79e5e72899321c28e872d892a957ff8141d6f21128b69dd7da25bc558fb7",
                        features={"family": [FV("malware")]},
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="874b79e5e72899321c28e872d892a957ff8141d6f21128b69dd7da25bc558fb7",
                        ),
                        entity_type="binary",
                        entity_id="e9c83ff8680a99f5d96cb724e9bfe32d4ca87068172874439b4fe671564a9770",
                        relationship={
                            "action": "deobfuscated",
                            "datatype": "payload",
                            "obfuscation_type": "base64 -> AES",
                        },
                        data=[
                            EventData(
                                hash="e9c83ff8680a99f5d96cb724e9bfe32d4ca87068172874439b4fe671564a9770",
                                label="content",
                            )
                        ],
                        features={},
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="874b79e5e72899321c28e872d892a957ff8141d6f21128b69dd7da25bc558fb7",
                        ),
                        entity_type="binary",
                        entity_id="29cf67d7d3ff86c378e3c56dce4fae227022b71cf4350b1049dff7356f77f674",
                        relationship={
                            "action": "extracted",
                            "datatype": "payload",
                            "obfuscation_type": "base64 -> AES",
                        },
                        data=[
                            EventData(
                                hash="29cf67d7d3ff86c378e3c56dce4fae227022b71cf4350b1049dff7356f77f674",
                                label="content",
                            )
                        ],
                        features={},
                    ),
                ],
                data={
                    "e9c83ff8680a99f5d96cb724e9bfe32d4ca87068172874439b4fe671564a9770": child_data_1,
                    "29cf67d7d3ff86c378e3c56dce4fae227022b71cf4350b1049dff7356f77f674": child_data_2,
                },
            ),
            inspect_data=True,
        )

    def test_bad_relationship_mapping(self):
        """Test incorrect type of the child binary relationship attribute."""

        data = b"a normal run"

        result = self.do_execution(
            data_in=[("content", data)],
            config={
                "create_venv": "false",
                "scripts": os.path.join(_TDIR, "extractors", "mapping", "bad_relationship_mapping"),
            },
            no_multiprocessing=True,
        )["BadRelationshipMapping"]
        self.assertEqual(result.state.label, State.Label.ERROR_EXCEPTION)

    def test_all(self):
        """Test all fields are mapped."""

        data = b"a normal run"
        result = self.do_execution(
            data_in=[("content", data)],
            config={"create_venv": "false", "scripts": os.path.join(_TDIR, "extractors", "mapping", "all")},
            no_multiprocessing=True,
        )

        self.assertJobResult(result[None], JobResult(state=State(State.Label.COMPLETED_EMPTY)))
        self.assertJobResult(
            result["All"],
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="874b79e5e72899321c28e872d892a957ff8141d6f21128b69dd7da25bc558fb7",
                        features={
                            "algorithm": [FV("alxor", label="binary")],
                            "algorithm_binary": [FV("alxor")],
                            "attack": [FV("T1204.002")],
                            "campaign_id": [FV("32")],
                            "capability_disabled": [FV("thing2")],
                            "capability_enabled": [FV("thing1")],
                            "category": [FV("adware")],
                            "client": [
                                FV(Uri("tcp://12.3.2.1:9584"), label="tcp://73.21.32.43:4"),
                                FV(Uri("tcp://16.8.4.2:1541"), label="tcp://tcpdomain.com:400"),
                                FV(Uri("tcp://127.7.4.1:21737")),
                                FV(Uri("udp://12.1.1.1:2131"), label="udp://73.21.32.43:42"),
                                FV(Uri("udp://12.1.1.1:2131"), label="udp://udpdomain.com:42"),
                                FV(Uri("udp://127.2.3.9:21784")),
                            ],
                            "coin": [FV("APE", label="ransomware")],
                            "coin_address": [FV("689fdh658790d6dr987yth84iyth7er8gtrfohyt9", label="APE_ransomware")],
                            "coin_ransomware": [FV("APE")],
                            "connection": [
                                FV(Uri("dns://123.21.21.21:9"), label="other"),
                                FV(Uri("ftp://apple:bad@somewhere:553/temporary.exe"), label="c2"),
                                FV(Uri("http:///thebad"), label="other"),
                                FV(Uri("http://differenturi.com:221"), label="other"),
                                FV(
                                    Uri("https://user:pass@blarg.com:221/malz?yeah=453&blah=yeah#a_part_of_the_page"),
                                    label="c2",
                                ),
                                FV(Uri("icmp://192.168.0.80"), label="c2"),
                                FV(Uri("icmp://malicious.com"), label="other"),
                                FV(Uri("smtp://user:pass@here.com:432"), label="upload"),
                                FV(Uri("socks5://capsicum:red@192.168.0.80:56"), label="tunnel"),
                                FV(Uri("ssh://user:pass@bad.malware:99"), label="download"),
                                FV(Uri("tcp://73.21.32.43:4"), label="c2"),
                                FV(Uri("tcp://tcpdomain.com:400"), label="upload"),
                                FV(Uri("udp://73.21.32.43:42"), label="decoy"),
                                FV(Uri("udp://udpdomain.com:42"), label="decoy"),
                            ],
                            "connection_c2": [
                                FV(Uri("ftp://apple:bad@somewhere:553/temporary.exe")),
                                FV(Uri("https://user:pass@blarg.com:221/malz?yeah=453&blah=yeah#a_part_of_the_page")),
                                FV(Uri("icmp://192.168.0.80")),
                                FV(Uri("tcp://73.21.32.43:4")),
                            ],
                            "connection_decoy": [
                                FV(Uri("udp://73.21.32.43:42")),
                                FV(Uri("udp://udpdomain.com:42")),
                            ],
                            "connection_download": [FV(Uri("ssh://user:pass@bad.malware:99"))],
                            "connection_other": [
                                FV(Uri("dns://123.21.21.21:9")),
                                FV(Uri("http:///thebad")),
                                FV(Uri("http://differenturi.com:221")),
                                FV(Uri("icmp://malicious.com")),
                            ],
                            "connection_tunnel": [FV(Uri("socks5://capsicum:red@192.168.0.80:56"))],
                            "connection_upload": [
                                FV(Uri("smtp://user:pass@here.com:432")),
                                FV(Uri("tcp://tcpdomain.com:400")),
                            ],
                            "constants": [
                                FV("34543", label="binary_alxor"),
                                FV("53453", label="binary_alxor"),
                                FV("8768", label="binary_alxor"),
                            ],
                            "decoded_strings": [FV("are"), FV("some"), FV("strings"), FV("there")],
                            "dns_hostname": [FV("www.evil.com", label="dns://123.21.21.21:9")],
                            "family": [FV("scuba")],
                            "header_fields": [
                                FV(
                                    "Application State",
                                    label="yeah_what_does_a_header_look_like - https://user:pass@blarg.com:221/malz?yeah=453&blah=yeah#a_part_of_the_page",
                                )
                            ],
                            "header_values": [
                                FV(
                                    "yeah_what_does_a_header_look_like",
                                    label="Application State - https://user:pass@blarg.com:221/malz?yeah=453&blah=yeah#a_part_of_the_page",
                                )
                            ],
                            "headers": [
                                FV(
                                    "Application State: yeah_what_does_a_header_look_like",
                                    label="https://user:pass@blarg.com:221/malz?yeah=453&blah=yeah#a_part_of_the_page",
                                )
                            ],
                            "icmp_code": [FV("0", label="icmp://malicious.com")],
                            "icmp_header": [FV("DEADBEEF", label="icmp://192.168.0.80")],
                            "icmp_type": [FV("14", label="icmp://malicious.com")],
                            "identifier": [FV("uxuduxuduxuudux")],
                            "inject_exe": [FV("Teams.exe")],
                            "iv": [FV("2432", label="binary_alxor")],
                            "key": [FV("5845u304654", label="binary_alxor")],
                            "mail": [
                                FV("me@you.com", label="smtp://user:pass@here.com:432"),
                                FV("you@me.com", label="smtp://user:pass@here.com:432"),
                                FV("your@computer.com", label="smtp://user:pass@here.com:432"),
                            ],
                            "mail_from": [FV("your@computer.com", label="smtp://user:pass@here.com:432")],
                            "mail_subject": [
                                FV("gum leaves - next superfood!???!", label="smtp://user:pass@here.com:432")
                            ],
                            "mail_to": [
                                FV("me@you.com", label="smtp://user:pass@here.com:432"),
                                FV("you@me.com", label="smtp://user:pass@here.com:432"),
                            ],
                            "max_size": [
                                FV(595, label="http:///thebad"),
                                FV(595, label="http://differenturi.com:221"),
                                FV(
                                    595,
                                    label="https://user:pass@blarg.com:221/malz?yeah=453&blah=yeah#a_part_of_the_page",
                                ),
                            ],
                            "method": [
                                FV("GET", label="http:///thebad"),
                                FV("GET", label="http://differenturi.com:221"),
                                FV(
                                    "GET",
                                    label="https://user:pass@blarg.com:221/malz?yeah=453&blah=yeah#a_part_of_the_page",
                                ),
                            ],
                            "mode": [FV("block", label="binary_alxor")],
                            "mutex": [FV("YEAH")],
                            "nonce": [FV("324324", label="binary_alxor")],
                            "password": [
                                FV("bad", label="ftp://apple:bad@somewhere:553/temporary.exe"),
                                FV("hunter2"),
                                FV(
                                    "pass",
                                    label="https://user:pass@blarg.com:221/malz?yeah=453&blah=yeah#a_part_of_the_page",
                                ),
                                FV("pass", label="smtp://user:pass@here.com:432"),
                                FV("pass", label="ssh://user:pass@bad.malware:99"),
                                FV("password", label="http:///thebad"),
                                FV("password", label="http://differenturi.com:221"),
                                FV("red", label="socks5://capsicum:red@192.168.0.80:56"),
                            ],
                            "path": [
                                FV(Filepath("C:/Windows/system32"), label="install"),
                                FV(Filepath("C:/user/USERNAME/xxxxx/xxxxx/"), label="logs"),
                                FV(Filepath("\\here\\is\\some\\place"), label="install"),
                            ],
                            "path_install": [
                                FV(Filepath("C:/Windows/system32")),
                                FV(Filepath("\\here\\is\\some\\place")),
                            ],
                            "path_logs": [FV(Filepath("C:/user/USERNAME/xxxxx/xxxxx/"))],
                            "pipe": [FV("xiod")],
                            "provider": [FV("homebrew", label="binary_alxor")],
                            "public_key": [FV("ret45yrththbf", label="binary_alxor")],
                            "ransom_amount": [FV(1.5, label="APE_ransomware")],
                            "record_type": [FV("TXT", label="dns://123.21.21.21:9")],
                            "registry": [
                                FV("HKLM_LOCAL_USER/some/location/to/key", label="store_data"),
                                FV("HKLM_LOCAL_USER/system/location", label="read"),
                            ],
                            "registry_read": [FV("HKLM_LOCAL_USER/system/location")],
                            "registry_store_data": [FV("HKLM_LOCAL_USER/some/location/to/key")],
                            "seed": [FV("2", label="binary_alxor")],
                            "service": [FV("DeviceMonitorSvc")],
                            "service_description": [FV("Device Monitor Service", label="DeviceMonitorSvc")],
                            "service_display": [FV("DeviceMonitorSvc", label="DeviceMonitorSvc")],
                            "service_dll": [FV("malware.dll", label="DeviceMonitorSvc")],
                            "sleep_delay": [FV(45000)],
                            "sleep_delay_jitter": [FV(2500)],
                            "user_agent": [
                                FV(
                                    "moonbrowser 15.86",
                                    label="https://user:pass@blarg.com:221/malz?yeah=453&blah=yeah#a_part_of_the_page",
                                ),
                                FV("sunbrowser 15.86", label="http:///thebad"),
                                FV("sunbrowser 15.86", label="http://differenturi.com:221"),
                            ],
                            "version": [FV("lotso_stuff")],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="874b79e5e72899321c28e872d892a957ff8141d6f21128b69dd7da25bc558fb7",
                        ),
                        entity_type="binary",
                        entity_id="e9c83ff8680a99f5d96cb724e9bfe32d4ca87068172874439b4fe671564a9770",
                        relationship={"action": "extracted", "datatype": "payload"},
                        data=[
                            EventData(
                                hash="e9c83ff8680a99f5d96cb724e9bfe32d4ca87068172874439b4fe671564a9770",
                                label="content",
                            )
                        ],
                        features={
                            "algorithm": [FV("AES", label="binary")],
                            "algorithm_binary": [FV("AES")],
                            "constants": [FV("34543", label="binary_AES"), FV("53453", label="binary_AES")],
                            "iv": [FV("5481", label="binary_AES")],
                            "key": [FV("16884a684", label="binary_AES")],
                            "mode": [FV("block", label="binary_AES")],
                            "nonce": [FV("12432", label="binary_AES")],
                            "provider": [FV("Microsoft", label="binary_AES")],
                            "public_key": [FV("afhnre9o48y", label="binary_AES")],
                            "seed": [FV("5", label="binary_AES")],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="874b79e5e72899321c28e872d892a957ff8141d6f21128b69dd7da25bc558fb7",
                        ),
                        entity_type="binary",
                        entity_id="053ec394f2cfed3507e682b59d7b2397f5eb49163acc34a934e9b3da6ea766e4",
                        relationship={"action": "extracted", "datatype": "payload"},
                        data=[
                            EventData(
                                hash="053ec394f2cfed3507e682b59d7b2397f5eb49163acc34a934e9b3da6ea766e4",
                                label="content",
                            )
                        ],
                        features={
                            "algorithm": [FV("AES", label="binary"), FV("XOR", label="config")],
                            "algorithm_binary": [FV("AES")],
                            "algorithm_config": [FV("XOR")],
                            "key": [FV("abcdefgh", label="binary_AES"), FV("0x84", label="config_XOR")],
                        },
                    ),
                ],
                data={
                    "e9c83ff8680a99f5d96cb724e9bfe32d4ca87068172874439b4fe671564a9770": b"\\x10\\x20\\x30\\x40",
                    "053ec394f2cfed3507e682b59d7b2397f5eb49163acc34a934e9b3da6ea766e4": b"\\x50\\x60\\x70\\x80",
                },
            ),
            inspect_data=True,
        )

    def test_complex_child(self):
        """Test all fields (including maco attributes) for a child binary are mapped."""

        data = b"a normal run with a child"
        result = self.do_execution(
            data_in=[("content", data)],
            config={"create_venv": "false", "scripts": os.path.join(_TDIR, "extractors", "mapping", "complex_child")},
            no_multiprocessing=True,
        )

        self.assertJobResult(result[None], JobResult(state=State(State.Label.COMPLETED_EMPTY)))
        self.assertJobResult(
            result["ComplexChild"],
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="1239ed4331b652fd9a227355f9ce1568274e1811fe18f9fb38cb404a98536fab",
                        features={
                            "attack": [FV("T1204.002")],
                            "category": [FV("adware")],
                            "family": [FV("scuba")],
                        },
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="1239ed4331b652fd9a227355f9ce1568274e1811fe18f9fb38cb404a98536fab",
                        ),
                        entity_type="binary",
                        entity_id="053ec394f2cfed3507e682b59d7b2397f5eb49163acc34a934e9b3da6ea766e4",
                        relationship={"action": "extracted", "datatype": "payload"},
                        data=[
                            EventData(
                                hash="053ec394f2cfed3507e682b59d7b2397f5eb49163acc34a934e9b3da6ea766e4",
                                label="content",
                            )
                        ],
                        features={
                            "algorithm": [FV("AES", label="binary"), FV("XOR", label="config")],
                            "algorithm_binary": [FV("AES")],
                            "algorithm_config": [FV("XOR")],
                            "campaign_id": [FV("32")],
                            "capability_disabled": [FV("thing2")],
                            "capability_enabled": [FV("thing1")],
                            "client": [
                                FV(Uri("tcp://12.3.2.1:9584"), label="tcp://73.21.32.43:4"),
                                FV(Uri("tcp://16.8.4.2:1541"), label="tcp://tcpdomain.com:400"),
                                FV(Uri("tcp://127.7.4.1:21737")),
                                FV(Uri("udp://12.1.1.1:2131"), label="udp://73.21.32.43:42"),
                                FV(Uri("udp://12.1.1.1:2131"), label="udp://udpdomain.com:42"),
                                FV(Uri("udp://127.2.3.9:21784")),
                            ],
                            "coin": [FV("APE", label="ransomware")],
                            "coin_address": [FV("689fdh658790d6dr987yth84iyth7er8gtrfohyt9", label="APE_ransomware")],
                            "coin_ransomware": [FV("APE")],
                            "connection": [
                                FV(Uri("dns://123.21.21.21:9"), label="other"),
                                FV(Uri("ftp://apple:bad@somewhere:553/temporary.exe"), label="c2"),
                                FV(Uri("http:///thebad"), label="other"),
                                FV(Uri("http://differenturi.com:221"), label="other"),
                                FV(
                                    Uri("https://user:pass@blarg.com:221/malz?yeah=453&blah=yeah#a_part_of_the_page"),
                                    label="c2",
                                ),
                                FV(Uri("icmp://192.168.0.80"), label="c2"),
                                FV(Uri("icmp://malicious.com"), label="other"),
                                FV(Uri("smtp://user:pass@here.com:432"), label="upload"),
                                FV(Uri("socks5://capsicum:red@192.168.0.80:56"), label="tunnel"),
                                FV(Uri("ssh://user:pass@bad.malware:99"), label="download"),
                                FV(Uri("tcp://73.21.32.43:4"), label="c2"),
                                FV(Uri("tcp://tcpdomain.com:400"), label="upload"),
                                FV(Uri("udp://73.21.32.43:42"), label="decoy"),
                                FV(Uri("udp://udpdomain.com:42"), label="decoy"),
                            ],
                            "connection_c2": [
                                FV(Uri("ftp://apple:bad@somewhere:553/temporary.exe")),
                                FV(Uri("https://user:pass@blarg.com:221/malz?yeah=453&blah=yeah#a_part_of_the_page")),
                                FV(Uri("icmp://192.168.0.80")),
                                FV(Uri("tcp://73.21.32.43:4")),
                            ],
                            "connection_decoy": [
                                FV(Uri("udp://73.21.32.43:42")),
                                FV(Uri("udp://udpdomain.com:42")),
                            ],
                            "connection_download": [FV(Uri("ssh://user:pass@bad.malware:99"))],
                            "connection_other": [
                                FV(Uri("dns://123.21.21.21:9")),
                                FV(Uri("http:///thebad")),
                                FV(Uri("http://differenturi.com:221")),
                                FV(Uri("icmp://malicious.com")),
                            ],
                            "connection_tunnel": [FV(Uri("socks5://capsicum:red@192.168.0.80:56"))],
                            "connection_upload": [
                                FV(Uri("smtp://user:pass@here.com:432")),
                                FV(Uri("tcp://tcpdomain.com:400")),
                            ],
                            "decoded_strings": [FV("are"), FV("some"), FV("strings"), FV("there")],
                            "dns_hostname": [FV("www.evil.com", label="dns://123.21.21.21:9")],
                            "header_fields": [
                                FV(
                                    "Application State",
                                    label="yeah_what_does_a_header_look_like - https://user:pass@blarg.com:221/malz?yeah=453&blah=yeah#a_part_of_the_page",
                                )
                            ],
                            "header_values": [
                                FV(
                                    "yeah_what_does_a_header_look_like",
                                    label="Application State - https://user:pass@blarg.com:221/malz?yeah=453&blah=yeah#a_part_of_the_page",
                                )
                            ],
                            "headers": [
                                FV(
                                    "Application State: yeah_what_does_a_header_look_like",
                                    label="https://user:pass@blarg.com:221/malz?yeah=453&blah=yeah#a_part_of_the_page",
                                )
                            ],
                            "icmp_code": [FV("0", label="icmp://malicious.com")],
                            "icmp_header": [FV("DEADBEEF", label="icmp://192.168.0.80")],
                            "icmp_type": [FV("14", label="icmp://malicious.com")],
                            "identifier": [FV("uxuduxuduxuudux")],
                            "inject_exe": [FV("Teams.exe")],
                            "key": [FV("abcdefgh", label="binary_AES"), FV("0x84", label="config_XOR")],
                            "mail": [
                                FV("me@you.com", label="smtp://user:pass@here.com:432"),
                                FV("you@me.com", label="smtp://user:pass@here.com:432"),
                                FV("your@computer.com", label="smtp://user:pass@here.com:432"),
                            ],
                            "mail_from": [FV("your@computer.com", label="smtp://user:pass@here.com:432")],
                            "mail_subject": [
                                FV("gum leaves - next superfood!???!", label="smtp://user:pass@here.com:432")
                            ],
                            "mail_to": [
                                FV("me@you.com", label="smtp://user:pass@here.com:432"),
                                FV("you@me.com", label="smtp://user:pass@here.com:432"),
                            ],
                            "max_size": [
                                FV(595, label="http:///thebad"),
                                FV(595, label="http://differenturi.com:221"),
                                FV(
                                    595,
                                    label="https://user:pass@blarg.com:221/malz?yeah=453&blah=yeah#a_part_of_the_page",
                                ),
                            ],
                            "method": [
                                FV("GET", label="http:///thebad"),
                                FV("GET", label="http://differenturi.com:221"),
                                FV(
                                    "GET",
                                    label="https://user:pass@blarg.com:221/malz?yeah=453&blah=yeah#a_part_of_the_page",
                                ),
                            ],
                            "mutex": [FV("YEAH")],
                            "password": [
                                FV("bad", label="ftp://apple:bad@somewhere:553/temporary.exe"),
                                FV("hunter2"),
                                FV(
                                    "pass",
                                    label="https://user:pass@blarg.com:221/malz?yeah=453&blah=yeah#a_part_of_the_page",
                                ),
                                FV("pass", label="smtp://user:pass@here.com:432"),
                                FV("pass", label="ssh://user:pass@bad.malware:99"),
                                FV("password", label="http:///thebad"),
                                FV("password", label="http://differenturi.com:221"),
                                FV("red", label="socks5://capsicum:red@192.168.0.80:56"),
                            ],
                            "path": [
                                FV(Filepath("C:/Windows/system32"), label="install"),
                                FV(Filepath("C:/user/USERNAME/xxxxx/xxxxx/"), label="logs"),
                                FV(Filepath("\\here\\is\\some\\place"), label="install"),
                            ],
                            "path_install": [
                                FV(Filepath("C:/Windows/system32")),
                                FV(Filepath("\\here\\is\\some\\place")),
                            ],
                            "path_logs": [FV(Filepath("C:/user/USERNAME/xxxxx/xxxxx/"))],
                            "pipe": [FV("xiod")],
                            "ransom_amount": [FV(1.5, label="APE_ransomware")],
                            "record_type": [FV("TXT", label="dns://123.21.21.21:9")],
                            "registry": [
                                FV("HKLM_LOCAL_USER/some/location/to/key", label="store_data"),
                                FV("HKLM_LOCAL_USER/system/location", label="read"),
                            ],
                            "registry_read": [FV("HKLM_LOCAL_USER/system/location")],
                            "registry_store_data": [FV("HKLM_LOCAL_USER/some/location/to/key")],
                            "service": [FV("DeviceMonitorSvc")],
                            "service_description": [FV("Device Monitor Service", label="DeviceMonitorSvc")],
                            "service_display": [FV("DeviceMonitorSvc", label="DeviceMonitorSvc")],
                            "service_dll": [FV("malware.dll", label="DeviceMonitorSvc")],
                            "sleep_delay": [FV(45000)],
                            "sleep_delay_jitter": [FV(2500)],
                            "user_agent": [
                                FV(
                                    "moonbrowser 15.86",
                                    label="https://user:pass@blarg.com:221/malz?yeah=453&blah=yeah#a_part_of_the_page",
                                ),
                                FV("sunbrowser 15.86", label="http:///thebad"),
                                FV("sunbrowser 15.86", label="http://differenturi.com:221"),
                            ],
                            "version": [FV("lotso_stuff")],
                        },
                    ),
                ],
                data={
                    "053ec394f2cfed3507e682b59d7b2397f5eb49163acc34a934e9b3da6ea766e4": b"\\x50\\x60\\x70\\x80",
                },
            ),
            inspect_data=True,
        )

    def test_uri_empty_protocol(self):
        """Test that uris with empty protocols are added correctly."""

        data = b"a normal run"

        result = self.do_execution(
            data_in=[("content", data)],
            config={
                "create_venv": "false",
                "scripts": os.path.join(_TDIR, "extractors", "mapping", "uri_empty_protocol"),
            },
            no_multiprocessing=True,
        )

        self.assertJobResult(result[None], JobResult(state=State(State.Label.COMPLETED_EMPTY)))
        self.assertJobResult(
            result["UriEmptyProtocol"],
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="874b79e5e72899321c28e872d892a957ff8141d6f21128b69dd7da25bc558fb7",
                        features={
                            "family": [FV("malware")],
                            "connection": [
                                FV(Uri("https://example.com:443"), label="c2"),
                                FV(Uri("bad.example.com:8080"), label="download"),
                            ],
                            "connection_c2": [FV(Uri("https://example.com:443"))],
                            "connection_download": [FV(Uri("bad.example.com:8080"))],
                        },
                    )
                ],
            ),
        )

    def test_runtime_other_features(self):
        """Test custom features added at runtime."""

        data = b"a normal run"

        result = self.do_execution(
            data_in=[("content", data)],
            config={
                "create_venv": "false",
                "scripts": os.path.join(_TDIR, "extractors", "mapping", "runtime_features"),
                "custom_features": {"cool_cats": "Does backflips|String"},
            },
            no_multiprocessing=True,
        )

        self.assertJobResultsDict(
            result,
            {
                "RuntimeFeatures": JobResult(
                    state=State(State.Label.COMPLETED),
                    events=[
                        Event(
                            entity_type="binary",
                            entity_id="874b79e5e72899321c28e872d892a957ff8141d6f21128b69dd7da25bc558fb7",
                            features={"cool_cats": [FV("apple")], "family": [FV("random")]},
                        )
                    ],
                ),
                None: JobResult(state=State(State.Label.COMPLETED_EMPTY)),
            },
        )

    def test_singleton_other_features(self):
        """Test new singleton other features.

        As new individual features are added, they should be added into this test case for testing."""

        data = b"a normal run"

        result = self.do_execution(
            data_in=[("content", data)],
            config={
                "create_venv": "false",
                "scripts": os.path.join(_TDIR, "extractors", "mapping", "singleton_other_features"),
            },
            no_multiprocessing=True,
        )

        # add the features in here to confirm they are mapped correctly to Azul features
        self.assertJobResult(
            result["SingletonOtherFeatures"],
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="874b79e5e72899321c28e872d892a957ff8141d6f21128b69dd7da25bc558fb7",
                        features={
                            "family": [FV("scripts")],
                            "file_extension": [FV("blargo")],
                            "file_format": [FV("paris")],
                            "file_format_legacy": [FV("xibalba")],
                            "filename": [FV("minecraft.hex")],
                            "magic": [FV("overgrown")],
                            "mime": [FV("xxd")],
                            "payload_parent_filename": [FV("payload_spawner.bin")],
                            "config_layout": [FV("s16dddp4")],
                            "payload_filename": [FV("my_enc_payload.dat")],
                            "payload_format": [FV("binary_data")],
                            "script_variable": [FV("chicken"), FV("password"), FV("payload")],
                        },
                    )
                ],
            ),
        )

    def test_other_features(self):
        """Test features added for generic features first added with the CobaltStrike extractor."""

        data = b"a normal run"
        result = self.do_execution(
            data_in=[("content", data)],
            config={"create_venv": "false", "scripts": os.path.join(_TDIR, "extractors", "mapping", "other_features")},
            no_multiprocessing=True,
        )
        self.assertJobResultsDict(
            result,
            {
                "OtherFeatures": JobResult(
                    state=State(State.Label.COMPLETED),
                    events=[
                        Event(
                            entity_type="binary",
                            entity_id="874b79e5e72899321c28e872d892a957ff8141d6f21128b69dd7da25bc558fb7",
                            features={
                                "family": [FV("family"), FV("random")],
                                "builder_hash": [FV("de21e4fc85c688c6e84b36adbb1b7ef1")],
                                "release_notes_hash": [FV("60305b8e35fc693f0f9f7118f24ac390")],
                                "bytes_inject_prepend_append_x86": [FV("prepend: 909090, append: 909090")],
                                "bytes_inject_prepend_append_x64": [FV("prepend: 9090, append: 909090")],
                                "c2_instructions": [FV("Print, Base64 URL-safe decode")],
                                "http_get_metadata": [
                                    FV(
                                        "ConstHeaders: [testheader: constheader], ConstParams: [testparam=para], Metadata: [base64url, print], SessionId: [base64url, header Cookie], Output: [print]"
                                    )
                                ],
                                "http_post_metadata": [
                                    FV(
                                        "ConstHeaders: [testheader: constheader], ConstParams: [testparam=para], Metadata: [base64url, print], SessionId: [base64url, header Cookie], Output: [print]"
                                    )
                                ],
                                "kill_date": [FV(datetime.datetime(2050, 12, 11, 0, 0))],
                                "smb_frame_data": [FV("000880212121")],
                                "ssh_banner": [FV("Host: httpHostHeaderidk\r\n")],
                                "tcp_frame_data": [
                                    FV(
                                        "00297463704672616d654865616465725f70726570656e6465645f746573745f6d657373616765"
                                    )
                                ],
                                "watermark": [FV("987654321 (0x3ade68b1)")],
                            },
                        )
                    ],
                ),
                None: JobResult(state=State(State.Label.COMPLETED_EMPTY)),
            },
        )

    def test_analysis_aborted(self):
        """Test a plugin which aborts during execution due to it not being able to run on this sample."""
        data = b"a normal run"

        result = self.do_execution(
            data_in=[("content", data)],
            config={"create_venv": "false", "scripts": os.path.join(_TDIR, "extractors", "mapping", "terminator")},
            no_multiprocessing=True,
        )

        self.assertJobResult(result[None], JobResult(state=State(State.Label.COMPLETED_EMPTY)))
        self.assertJobResult(
            result["Terminator"],
            JobResult(
                state=State(
                    State.Label.OPT_OUT,
                    failure_name="no_results",
                    message="Maco extractor ran but returned no results.",
                ),
            ),
        )
