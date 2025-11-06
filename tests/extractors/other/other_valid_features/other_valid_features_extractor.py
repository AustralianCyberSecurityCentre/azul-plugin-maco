from typing import BinaryIO, List, Optional

from maco import extractor, model, yara


class OtherValidFeatures(extractor.Extractor):
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
        return model.ExtractorModel(
            family="random",
            other={
                "version": "azul_v1",
                "features": {
                    "config_offset": [394],
                    "config_section_name": ".abc",
                    "config_size": 13,
                    "config_type": {"value": "standard", "label": "mongoose", "offset": 394, "size": 13},
                    "config_file_extensions": [".txt", ".docx", ".swf"],
                },
                "report": "some text\n" * 10,
            },
        )
