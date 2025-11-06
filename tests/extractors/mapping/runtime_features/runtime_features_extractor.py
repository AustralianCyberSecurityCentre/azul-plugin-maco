from typing import BinaryIO, List, Optional

from maco import extractor, model, yara

# Test data for framework features
data_framework = {
    "features": {
        # A feature that doesn't exist in the base Maco extractor plugin
        "cool_cats": "apple",
    },
    "version": "azul_v1",
}


class RuntimeFeatures(extractor.Extractor):
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
        return model.ExtractorModel(family="random", other=data_framework)
