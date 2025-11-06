from typing import BinaryIO, List, Optional

from maco import extractor, model, yara


class BadData(extractor.Extractor):
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
        ret = model.ExtractorModel(family="random")
        # This will raise a UserWarning. This is fine.
        ret.sleep_delay = "husky"
        return ret
