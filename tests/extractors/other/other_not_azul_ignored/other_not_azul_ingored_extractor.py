from typing import BinaryIO, List, Optional

from maco import extractor, model, yara


class OtherNotAzul(extractor.Extractor):
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
        return model.ExtractorModel(family="random", other={"junk": 55})
