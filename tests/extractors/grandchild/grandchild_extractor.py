from typing import BinaryIO, List, Optional

from maco import extractor, model, yara


class ChildBinary(extractor.Extractor):
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
            binaries=[
                model.ExtractorModel.Binary(
                    data=b"1234",
                ),
                model.ExtractorModel.Binary(
                    data=b"5678",
                    datatype=model.ExtractorModel.Binary.TypeEnum.config,
                    other={
                        "version": "azul_v1",
                        "child_of": "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4",
                    },
                    encryption=model.ExtractorModel.Binary.Encryption(
                        algorithm="AES",
                        public_key="afhnre9o48y",
                        key="16884a684",
                        mode="block",
                        iv="5481",
                        seed="5",
                        nonce="12432",
                        usage=model.ExtractorModel.Binary.Encryption.UsageEnum.binary,
                    ),
                ),
            ],
        )
