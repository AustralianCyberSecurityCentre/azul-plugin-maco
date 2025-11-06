from typing import BinaryIO, List, Optional

from maco import extractor, model, yara


class SingletonOtherFeatures(extractor.Extractor):
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
        other = {
            "version": "azul_v1",
            "features": {
                "script_variable": ["payload", "password", "chicken"],
                "payload_format": ["binary_data"],
                "payload_filename": ["my_enc_payload.dat"],
                "payload_parent_filename": ["payload_spawner.bin"],
                "config_layout": ["s16dddp4"],
                "filename": ["minecraft.hex"],
                # these should generally be set by dispatcher and not overwritten by your extractor
                # check it works anyway
                "file_extension": ["blargo"],
                "file_format": ["paris"],
                "file_format_legacy": ["xibalba"],
                "magic": ["overgrown"],
                "mime": ["xxd"],
            },
        }
        return model.ExtractorModel(family="scripts", other=other)
