from typing import BinaryIO, List, Optional

from maco import extractor, model, yara

data_big = {
    "family": "scuba",
    "category": ["adware"],
    "attack": ["T1204.002"],
    "binaries": [
        {
            "datatype": "payload",
            "data": rb"\x50\x60\x70\x80",
            "other": {
                "version": "azul_v1",
                "features": {
                    "version": "lotso_stuff",
                    "capability_enabled": ["thing1"],
                    "capability_disabled": ["thing2"],
                    "campaign_id": ["32"],
                    "identifier": ["uxuduxuduxuudux"],
                    "decoded_strings": ["there", "are", "some", "strings"],
                    "password": ["hunter2"],
                    "mutex": ["YEAH"],
                    "pipe": ["xiod"],
                    "sleep_delay": 45000,
                    "sleep_delay_jitter": 2500,
                    "inject_exe": ["Teams.exe"],
                    "ftp": [
                        {
                            "username": "apple",
                            "password": "bad",
                            "hostname": "somewhere",
                            "port": 553,
                            "path": "/temporary.exe",
                            "usage": "c2",
                        }
                    ],
                    "smtp": [
                        {
                            "username": "user",
                            "password": "pass",
                            "hostname": "here.com",
                            "port": 432,
                            "mail_to": ["me@you.com", "you@me.com"],
                            "mail_from": "your@computer.com",
                            "subject": "gum leaves - next superfood!???!",
                            "usage": "upload",
                        }
                    ],
                    "http": [
                        {
                            "uri": "https://user:pass@blarg.com:221/malz?yeah=453&blah=yeah#a_part_of_the_page",
                            "protocol": "https",
                            "username": "user",
                            "password": "pass",
                            "hostname": "blarg.com",
                            "port": 221,
                            "path": "/malz",
                            "query": "yeah=453&blah=yeah",
                            "fragment": "a_part_of_the_page",
                            "user_agent": "moonbrowser 15.86",
                            "method": "GET",
                            "headers": {"Application State": "yeah_what_does_a_header_look_like"},
                            "max_size": 595,
                            "usage": "c2",
                        },
                        {
                            "uri": "http://differenturi.com:221",
                            "protocol": "http",
                            "username": "username",
                            "password": "password",
                            "path": "/thebad",
                            "user_agent": "sunbrowser 15.86",
                            "method": "GET",
                            "max_size": 595,
                        },
                    ],
                    "ssh": [
                        {
                            "username": "user",
                            "password": "pass",
                            "hostname": "bad.malware",
                            "port": 99,
                            "usage": "download",
                        }
                    ],
                    "proxy": [
                        {
                            "protocol": "socks5",
                            "username": "capsicum",
                            "password": "red",
                            "hostname": "192.168.0.80",
                            "port": 56,
                            "usage": "tunnel",
                        }
                    ],
                    "icmp": [
                        {"hostname": "192.168.0.80", "header": "DEADBEEF", "usage": "c2"},
                        {"type": 14, "code": 0, "hostname": "malicious.com", "usage": "other"},
                    ],
                    "dns": [
                        {
                            "ip": "123.21.21.21",
                            "port": 9,
                            "hostname": "www.evil.com",
                            "record_type": "TXT",
                            "usage": "other",
                        }
                    ],
                    "tcp": [
                        {
                            "client_ip": "12.3.2.1",
                            "client_port": 9584,
                            "server_ip": "73.21.32.43",
                            "server_port": 4,
                            "usage": "c2",
                        },
                        {
                            "client_ip": "16.8.4.2",
                            "client_port": 1541,
                            "server_domain": "tcpdomain.com",
                            "server_port": 400,
                            "usage": "upload",
                        },
                        {"client_ip": "127.7.4.1", "client_port": 21737},
                    ],
                    "udp": [
                        {
                            "client_ip": "12.1.1.1",
                            "client_port": 2131,
                            "server_ip": "73.21.32.43",
                            "server_domain": "udpdomain.com",
                            "server_port": 42,
                            "usage": "decoy",
                        },
                        {
                            "client_ip": "127.2.3.9",
                            "client_port": 21784,
                        },
                    ],
                    "service": [
                        {
                            "dll": "malware.dll",
                            "name": "DeviceMonitorSvc",
                            "display_name": "DeviceMonitorSvc",
                            "description": "Device Monitor Service",
                        }
                    ],
                    "cryptocurrency": [
                        {
                            "coin": "APE",
                            "address": "689fdh658790d6dr987yth84iyth7er8gtrfohyt9",
                            "ransom_amount": 1.50,
                            "usage": "ransomware",
                        }
                    ],
                    "paths": [
                        {"path": "C:/Windows/system32", "usage": "install"},
                        {"path": "C:/user/USERNAME/xxxxx/xxxxx/", "usage": "logs"},
                        {"path": "\\here\\is\\some\\place", "usage": "install"},
                    ],
                    "registry": [
                        {
                            "key": "HKLM_LOCAL_USER/some/location/to/key",
                            "usage": "store_data",
                        },
                        {"key": "HKLM_LOCAL_USER/system/location", "usage": "read"},
                    ],
                },
            },
            "encryption": [
                {
                    "algorithm": "AES",
                    "key": "abcdefgh",
                    "usage": "binary",
                },
                {
                    "algorithm": "XOR",
                    "key": "0x84",
                    "usage": "config",
                },
            ],
        },
    ],
}


class ComplexChild(extractor.Extractor):
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

    def run(self, stream: BinaryIO, matches: List[yara.Match]) -> Optional[model.ExtractorModel]:
        ret = model.ExtractorModel.model_validate(data_big)
        return ret
