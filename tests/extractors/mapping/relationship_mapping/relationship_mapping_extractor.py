from typing import BinaryIO, List, Optional

from maco import extractor, model, yara


class RelationshipMapping(extractor.Extractor):
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
                        "data": rb"\x10\x20\x30\x40",
                        "other": {
                            "relationship": {"action": "deobfuscated", "obfuscation_type": "base64 -> AES"},
                        },
                    },
                    {
                        "datatype": "payload",
                        "data": rb"\x90\xA0\xB0\xC0",
                        "other": {
                            "relationship": {"obfuscation_type": "base64 -> AES"},
                        },
                    },
                ],
            }
        )
        return ret
