"""Map config to Azul features."""

from collections import defaultdict
from typing import Optional
from urllib import parse

from azul_runner import FV
from pydantic import BaseModel


class Child(BaseModel):
    """Child information produced from maco binary instance."""

    data: bytes = None
    relationship: dict = {}
    features: dict = {}
    other: dict = {}


class MappedData(BaseModel):
    """Data mapped from maco model."""

    features: dict = defaultdict(list)
    children: list[Child] = []
    other: dict = {}


class ClearDict:
    """Wrapper class for a dict and list of accessed keys, which are deleted after."""

    d: dict
    to_delete: list

    def __init__(self, d: dict):
        """Create new ClearDict."""
        self.d = d

    def __enter__(self):
        """Called at start of 'with' scope."""
        self.to_delete = []
        return self

    def get(self, key: str, default):
        """Get dict value and mark key for deletion."""
        if key in self.d:
            if key not in self.to_delete:
                self.to_delete.append(key)
            return self.d[key]
        else:
            return default

    def __exit__(self, *args):
        """Called at end of 'with' scope."""
        for key in self.to_delete:
            del self.d[key]
        if len(self.d) != 0:
            raise Exception(f"Unmapped maco data found: {str(self.d)}")


def _add_multiple_features(features: dict, features_to_add: dict):
    for key_to_add, value_to_add in features_to_add.items():
        if key_to_add in features:
            if isinstance(features[key_to_add], list) and isinstance(value_to_add, list):
                features[key_to_add] += value_to_add
            else:
                raise Exception(
                    f"Feature {key_to_add} would overwrite value {features[key_to_add]} with {value_to_add}."
                )
        else:
            features[key_to_add] = value_to_add


def _build_uri(*, proto="", un="", pw="", host="", port="", path="", query="", fragment="") -> Optional[str]:
    """Return a structured URI.

    Examples:
    https://user:pass@host.com:8769/path/?apple=yes#pagestop
    host.com
    host.com:879
    user:pass@host.com
    user@host.com
    ftp://anon.com/somepath
    hoster.com/path
    """
    # build netloc
    netloc = ""
    if host:
        if un:
            netloc += un
            if pw:
                netloc += f":{pw}"
            netloc += "@"
        netloc += host
        if port:
            netloc += f":{port}"

    uri = parse.urlunparse((proto, netloc, path, "", query, fragment))
    # if proto was empty, urlunparse gives us a uri starting with "//"
    if uri and uri.startswith("//"):
        # remove the starting "//"
        uri = uri.replace("//", "", 1)
    return uri if uri else None


def _map_encryption_dict(encryption_config: dict) -> defaultdict:
    """Map dict of encryption config to features."""
    features: defaultdict = defaultdict(list)
    with ClearDict(encryption_config) as cd:
        usage = cd.get("usage", "other")
        if algorithm := cd.get("algorithm", None):
            features[f"algorithm_{usage}"].append(FV(algorithm))
            features["algorithm"].append(FV(algorithm, label=usage))

        usage_alg = f"{usage}"
        if algorithm:
            usage_alg += f"_{algorithm}"

        if pub_key := cd.get("public_key", None):
            features["public_key"].append(FV(pub_key, label=usage_alg))
        if feat_name := cd.get("key", None):
            features["key"].append(FV(feat_name, label=usage_alg))
        if provider := cd.get("provider", None):
            features["provider"].append(FV(provider, label=usage_alg))
        if mode := cd.get("mode", None):
            features["mode"].append(FV(mode, label=usage_alg))
        if iv := cd.get("iv", None):
            features["iv"].append(FV(iv, label=usage_alg))
        if seed := cd.get("seed", None):
            features["seed"].append(FV(seed, label=usage_alg))
        if nonce := cd.get("nonce", None):
            features["nonce"].append(FV(nonce, label=usage_alg))
        for constant in cd.get("constants", []):
            features["constants"].append(FV(constant, label=usage_alg))
    return features


def _map_http(
    uri: str, user_agent: str, method: str, headers: dict[str, str], max_size: int, password: str, usage: str
) -> defaultdict:
    """Map http connection config to features."""
    features: defaultdict = defaultdict(list)
    if uri:
        features[f"connection_{usage}"].append(uri)
        features["connection"].append(FV(uri, label=usage))
    if user_agent:
        features["user_agent"].append(FV(user_agent, label=uri))
    if method:
        features["method"].append(FV(method, label=uri))
    for field, value in headers.items():
        features["headers"].append(FV(f"{field}: {value}", label=uri))
        features["header_fields"].append(FV(field, label=f"{value} - {uri}"))
        features["header_values"].append(FV(value, label=f"{field} - {uri}"))
    if max_size:
        features["max_size"].append(FV(max_size, label=uri))
    if password:
        features["password"].append(FV(password, label=uri))
    return features


def _map_connection(
    protocol: str, server_host: str, server_port: int, client_ip: str, client_port: int, usage: str
) -> defaultdict:
    """Map tcp/udp connection config to features."""
    features: defaultdict = defaultdict(list)
    if server_host:
        server_uri = _build_uri(
            proto=protocol,
            host=server_host,
            port=server_port,
        )
        features[f"connection_{usage}"].append(server_uri)
        features["connection"].append(FV(server_uri, label=usage))

        client_uri = _build_uri(
            proto=protocol,
            host=client_ip,
            port=client_port,
        )
        features["client"].append(FV(client_uri, label=server_uri))
    else:
        client_uri = _build_uri(
            proto=protocol,
            host=client_ip,
            port=client_port,
        )
        features["client"].append(FV(client_uri))
    return features


def map_config(d: dict) -> MappedData:
    """Map extractor config to Azul features."""
    mapped = MappedData()

    with ClearDict(d) as cd1:
        # family is required
        if family := cd1.get("family", None):
            mapped.features["family"] = family
        else:
            raise Exception("malware family is required.")
        mapped.features["version"] = cd1.get("version", None)
        mapped.features["category"] = cd1.get("category", [])
        mapped.features["attack"] = cd1.get("attack", [])
        mapped.features["capability_enabled"] = cd1.get("capability_enabled", [])
        mapped.features["capability_disabled"] = cd1.get("capability_disabled", [])

        mapped.features["campaign_id"] = cd1.get("campaign_id", [])
        mapped.features["identifier"] = cd1.get("identifier", [])
        mapped.features["decoded_strings"] = cd1.get("decoded_strings", [])
        mapped.features["password"] = cd1.get("password", [])
        mapped.features["mutex"] = cd1.get("mutex", [])
        mapped.features["pipe"] = cd1.get("pipe", [])
        mapped.features["sleep_delay"] = cd1.get("sleep_delay", [])
        mapped.features["sleep_delay_jitter"] = cd1.get("sleep_delay_jitter", [])
        mapped.features["inject_exe"] = cd1.get("inject_exe", [])

        # protocol mapping
        # ftp
        for item in cd1.get("ftp", []):
            with ClearDict(item) as cd2:
                uri = _build_uri(
                    proto="ftp",
                    un=cd2.get("username", ""),
                    pw=cd2.get("password", ""),
                    host=cd2.get("hostname", ""),
                    port=cd2.get("port", ""),
                    path=cd2.get("path", ""),
                )
                mapped.features[f'connection_{cd2.get("usage", "other")}'].append(uri)
                mapped.features["connection"].append(FV(uri, label=cd2.get("usage", "other")))

                if password := cd2.get("password", None):
                    mapped.features["password"].append(FV(password, label=uri))

        # smtp
        for item in cd1.get("smtp", []):
            with ClearDict(item) as cd2:
                # server login
                uri = _build_uri(
                    proto="smtp",
                    un=cd2.get("username", ""),
                    pw=cd2.get("password", ""),
                    host=cd2.get("hostname", ""),
                    port=cd2.get("port", ""),
                )
                mapped.features[f'connection_{cd2.get("usage", "other")}'].append(uri)
                mapped.features["connection"].append(FV(uri, label=cd2.get("usage", "other")))

                for mail_to in cd2.get("mail_to", []):
                    fv = FV(mail_to, label=uri)
                    mapped.features["mail_to"].append(fv)
                    mapped.features["mail"].append(fv)
                if mail_from := cd2.get("mail_from", None):
                    fv = FV(mail_from, label=uri)
                    mapped.features["mail_from"].append(fv)
                    mapped.features["mail"].append(fv)
                if mail_sub := cd2.get("subject", None):
                    mapped.features["mail_subject"].append(FV(mail_sub, label=uri))

                if password := cd2.get("password", None):
                    mapped.features["password"].append(FV(password, label=uri))

        # http
        for item in cd1.get("http", []):
            with ClearDict(item) as cd2:
                # if there is an entered uri and a generated uri we keep both as features
                if uri := cd2.get("uri", None):
                    _add_multiple_features(
                        mapped.features,
                        _map_http(
                            uri,
                            cd2.get("user_agent", None),
                            cd2.get("method", None),
                            cd2.get("headers", {}),
                            cd2.get("max_size", None),
                            cd2.get("password", None),
                            cd2.get("usage", "other"),
                        ),
                    )

                # server login
                uri_gen = _build_uri(
                    proto=cd2.get("protocol", ""),
                    un=cd2.get("username", ""),
                    pw=cd2.get("password", ""),
                    host=cd2.get("hostname", ""),
                    port=cd2.get("port", ""),
                    path=cd2.get("path", ""),
                    query=cd2.get("query", ""),
                    fragment=cd2.get("fragment", ""),
                )
                if uri_gen and uri_gen != uri:
                    _add_multiple_features(
                        mapped.features,
                        _map_http(
                            uri_gen,
                            cd2.get("user_agent", None),
                            cd2.get("method", None),
                            cd2.get("headers", {}),
                            cd2.get("max_size", None),
                            cd2.get("password", None),
                            cd2.get("usage", "other"),
                        ),
                    )

        # ssh
        for item in cd1.get("ssh", []):
            with ClearDict(item) as cd2:
                # ssh doesn't really follow the uri format, but the fields are better
                # to search this way
                uri = _build_uri(
                    proto="ssh",
                    un=cd2.get("username", ""),
                    pw=cd2.get("password", ""),
                    host=cd2.get("hostname", ""),
                    port=cd2.get("port", ""),
                )
                mapped.features[f'connection_{cd2.get("usage", "other")}'].append(uri)
                mapped.features["connection"].append(FV(uri, label=cd2.get("usage", "other")))

                if password := cd2.get("password", None):
                    mapped.features["password"].append(FV(password, label=uri))

        # proxy
        for item in cd1.get("proxy", []):
            with ClearDict(item) as cd2:
                uri = _build_uri(
                    proto=cd2.get("protocol", "proxy"),
                    un=cd2.get("username", ""),
                    pw=cd2.get("password", ""),
                    host=cd2.get("hostname", ""),
                    port=cd2.get("port", ""),
                )
                mapped.features[f'connection_{cd2.get("usage", "other")}'].append(uri)
                mapped.features["connection"].append(FV(uri, label=cd2.get("usage", "other")))

                if password := cd2.get("password", None):
                    mapped.features["password"].append(FV(password, label=uri))

        # icmp
        for item in cd1.get("icmp", []):
            with ClearDict(item) as cd2:
                uri = _build_uri(
                    proto="icmp",
                    host=cd2.get("hostname", ""),
                )
                mapped.features[f'connection_{cd2.get("usage", "other")}'].append(uri)
                mapped.features["connection"].append(FV(uri, label=cd2.get("usage", "other")))

                if cd2.get("type", -1) >= 0:
                    mapped.features["icmp_type"].append(FV(cd2.get("type", -1), label=uri))
                if cd2.get("code", -1) >= 0:
                    mapped.features["icmp_code"].append(FV(cd2.get("code", -1), label=uri))
                if icmp_header := cd2.get("header", None):
                    mapped.features["icmp_header"].append(FV(icmp_header, label=uri))

        # dns
        for item in cd1.get("dns", []):
            with ClearDict(item) as cd2:
                uri = _build_uri(
                    proto="dns",
                    host=cd2.get("ip", ""),
                    port=cd2.get("port", ""),
                )
                mapped.features[f'connection_{cd2.get("usage", "other")}'].append(uri)
                mapped.features["connection"].append(FV(uri, label=cd2.get("usage", "other")))

                if hostname := cd2.get("hostname", None):
                    mapped.features["dns_hostname"].append(FV(hostname, label=uri))
                if record_type := cd2.get("record_type", None):
                    mapped.features["record_type"].append(FV(record_type, label=uri))

        # tcp
        for item in cd1.get("tcp", []):
            with ClearDict(item) as cd2:
                if server_ip := cd2.get("server_ip", ""):
                    _add_multiple_features(
                        mapped.features,
                        _map_connection(
                            "tcp",
                            server_ip,
                            cd2.get("server_port", ""),
                            cd2.get("client_ip", ""),
                            cd2.get("client_port", ""),
                            cd2.get("usage", "other"),
                        ),
                    )
                if server_domain := cd2.get("server_domain", ""):
                    _add_multiple_features(
                        mapped.features,
                        _map_connection(
                            "tcp",
                            server_domain,
                            cd2.get("server_port", ""),
                            cd2.get("client_ip", ""),
                            cd2.get("client_port", ""),
                            cd2.get("usage", "other"),
                        ),
                    )
                # Handle server-less Connection features
                if not (server_domain or server_ip):
                    if client_ip := cd2.get("client_ip", ""):
                        _add_multiple_features(
                            mapped.features,
                            _map_connection(
                                "tcp",
                                "",
                                "",
                                client_ip,
                                cd2.get("client_port", ""),
                                cd2.get("usage", "other"),
                            ),
                        )

        # udp
        for item in cd1.get("udp", []):
            with ClearDict(item) as cd2:
                if server_ip := cd2.get("server_ip", ""):
                    _add_multiple_features(
                        mapped.features,
                        _map_connection(
                            "udp",
                            server_ip,
                            cd2.get("server_port", ""),
                            cd2.get("client_ip", ""),
                            cd2.get("client_port", ""),
                            cd2.get("usage", "other"),
                        ),
                    )
                if server_domain := cd2.get("server_domain", ""):
                    _add_multiple_features(
                        mapped.features,
                        _map_connection(
                            "udp",
                            server_domain,
                            cd2.get("server_port", ""),
                            cd2.get("client_ip", ""),
                            cd2.get("client_port", ""),
                            cd2.get("usage", "other"),
                        ),
                    )
                # Handle server-less Connection features
                if not (server_domain or server_ip):
                    if client_ip := cd2.get("client_ip", ""):
                        _add_multiple_features(
                            mapped.features,
                            _map_connection(
                                "udp",
                                "",
                                "",
                                client_ip,
                                cd2.get("client_port", ""),
                                cd2.get("usage", "other"),
                            ),
                        )

        # encryption
        for item in cd1.get("encryption", []):
            _add_multiple_features(mapped.features, _map_encryption_dict(item))

        # service
        for item in cd1.get("service", []):
            with ClearDict(item) as cd2:
                if service := cd2.get("name", None):
                    mapped.features["service"].append(service)
                if service_dll := cd2.get("dll", None):
                    mapped.features["service_dll"].append(FV(service_dll, label=service))
                if service_display := cd2.get("display_name", None):
                    mapped.features["service_display"].append(FV(service_display, label=service))
                if service_desc := cd2.get("description", None):
                    mapped.features["service_description"].append(FV(service_desc, label=service))

        # cryptocurrency
        for item in cd1.get("cryptocurrency", []):
            with ClearDict(item) as cd2:
                usage = cd2.get("usage", "other")
                if coin := cd2.get("coin", None):
                    mapped.features[f"coin_{usage}"].append(coin)
                    mapped.features["coin"].append(FV(coin, label=usage))

                if coin is not None:
                    coin = f"{coin}_"
                else:
                    coin = ""
                coin_usage = f"{coin}{usage}"

                if coin_addr := cd2.get("address", None):
                    mapped.features["coin_address"].append(FV(coin_addr, label=coin_usage))
                if ransom_amount := cd2.get("ransom_amount", None):
                    mapped.features["ransom_amount"].append(FV(ransom_amount, label=coin_usage))

        # path
        for item in cd1.get("paths", []):
            with ClearDict(item) as cd2:
                if usage := cd2.get("usage", None):
                    mapped.features[f"path_{usage}"].append(cd2.get("path", None))
                mapped.features["path"].append(FV(cd2.get("path", None), label=usage))

        # registry
        for item in cd1.get("registry", []):
            with ClearDict(item) as cd2:
                if usage := cd2.get("usage", None):
                    mapped.features[f"registry_{usage}"].append(cd2.get("key", None))
                mapped.features["registry"].append(FV(cd2.get("key", None), label=usage))

        # other
        mapped.other = cd1.get("other", {})
        if language := mapped.other.get("language"):
            mapped.features["language"].append(language)

        # binary
        for item in cd1.get("binaries", []):
            with ClearDict(item) as cd2:
                child = Child()
                child.data = cd2.get("data", None)
                if child.data is None:
                    raise Exception("Cannot submit child binary without data.")
                child.relationship = {"action": "extracted"}
                if datatype := cd2.get("datatype", None):
                    child.relationship["datatype"] = datatype
                child.features = {}
                # Maco supports either a single encryption object, or a list of encryption objects on the child
                # binaries
                child_encryption = cd2.get("encryption", {})
                if isinstance(child_encryption, list):
                    for item in child_encryption:
                        _add_multiple_features(child.features, _map_encryption_dict(item))
                else:
                    child.features.update(_map_encryption_dict(child_encryption))
                child_other = cd2.get("other", {})
                # Maco doesn't have a specific relationship attribute for child binaries, so store the
                # relationship dictionary under the other attribute. If relationship is not of the expected
                # type, an exception will be raised.
                if "relationship" in child_other.keys():
                    try:
                        child.relationship.update(child_other.get("relationship"))
                        del child_other["relationship"]
                    except ValueError:
                        raise Exception("child relationship attribute must be a dictionary")
                child.other = child_other
                mapped.children.append(child)

    # remove Nones and empty lists, sort non-empty lists
    for feat_name, feat in list(mapped.features.items()):
        if feat is None or (isinstance(feat, list) and len(feat) == 0):
            del mapped.features[feat_name]
            continue
        if isinstance(feat, list):
            mapped.features[feat_name] = sorted({x for x in feat}, key=lambda f: f.value if isinstance(f, FV) else f)

    return mapped
