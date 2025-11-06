from typing import BinaryIO, List, Optional

from maco import extractor, model, yara


class UriEmptyProtocol(extractor.Extractor):
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
    # intending to test domains:
    # - https://example.com:443
    # - bad.example.com:8080

    def run(self, stream: BinaryIO, matches: List[yara.Match]) -> Optional[model.ExtractorModel]:
        return model.ExtractorModel.model_validate(
            {
                "family": "malware",
                "http": [
                    {
                        "protocol": "https",
                        "hostname": "example.com",
                        "port": 443,
                        "usage": "c2",
                    },
                    {
                        "hostname": "bad.example.com",
                        "port": 8080,
                        "usage": "download",
                    },
                ],
            }
        )
