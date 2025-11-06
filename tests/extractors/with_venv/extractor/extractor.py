from maco import extractor, model


class MacoVenv(extractor.Extractor):
    author = "me"
    family = "evil"
    last_modified = "2020-02-02"
    yara_rule = """
    rule MacoVenv
    {
        condition:
            true
    }
    """

    def run(self, stream, matches):
        return model.ExtractorModel(family="evil")
