from typing import BinaryIO, List, Optional

from maco import extractor, model, yara


class BadRelationshipMapping(extractor.Extractor):
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
        ret = model.ExtractorModel.model_validate(
            {
                "family": "malware",
                "binaries": [
                    {
                        "datatype": "payload",
                        "data": rb"\x50\x60\x70\x80",
                        "other": {
                            "relationship": "invalid relationship type",
                        },
                    },
                ],
            }
        )
        return ret
