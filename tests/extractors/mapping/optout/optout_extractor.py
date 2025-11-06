from typing import BinaryIO, List, Optional

from maco import extractor, model, yara


class Optout(extractor.Extractor):
    author = "me"
    family = "evil"
    last_modified = "2020-02-02"
    yara_rule = """
    rule TmpScript
    {
        condition:
            false
    }
    """

    def run(self, stream: BinaryIO, matches: List[yara.Match]) -> Optional[model.ExtractorModel]:
        return
