from typing import BinaryIO, List, Optional

from maco import extractor, model, yara


class FeatureList(extractor.Extractor):
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
        return model.ExtractorModel.model_validate(
            {
                "family": "malware",
                "tcp": [
                    {
                        "client_ip": "1.2.3.4",
                        "client_port": 5678,
                        "server_ip": "9.10.11.12",
                        "server_port": 13,
                        "usage": "upload",
                    },
                    {
                        "client_ip": "14.15.16.17",
                        "client_port": 1819,
                        "server_ip": "20.21.22.23",
                        "server_port": 24,
                        "usage": "upload",
                    },
                ],
            }
        )
