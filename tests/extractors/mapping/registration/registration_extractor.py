from maco import extractor


# Boilerplate
class Base(extractor.Extractor):
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


class Clear(Base):
    sharing = "TLP:CLEAR"


class Description(Base):
    """My lazy description with no fullstop"""


class UnspecifiedSharing(Base):
    """This is my description."""

    sharing = None


class UnknownMapping(Base):
    """This is my description."""

    sharing = "FISHFINGERS TLP:CLEAR"


class PartialMatch(Base):
    """This is my description."""

    sharing = "OFFICIAL TLP:AMBER"
