from typing import BinaryIO, List, Optional

from maco import extractor, model, yara

# Test data for framework features
data_framework = {
    "features": {
        "family": "family",
        "c2_instructions": "Print, Base64 URL-safe decode",
        "http_get_metadata": "ConstHeaders: [testheader: constheader], ConstParams: [testparam=para], "
        "Metadata: [base64url, print], SessionId: [base64url, header Cookie], "
        "Output: [print]",
        "http_post_metadata": "ConstHeaders: [testheader: constheader], ConstParams: [testparam=para], "
        "Metadata: [base64url, print], SessionId: [base64url, header Cookie], "
        "Output: [print]",
        "ssh_banner": "Host: httpHostHeaderidk\r\n",
        "watermark": "987654321 (0x3ade68b1)",
        "kill_date": "2050-12-11 00:00:00",
        "bytes_inject_prepend_append_x86": "prepend: 909090, append: 909090",
        "bytes_inject_prepend_append_x64": "prepend: 9090, append: 909090",
        "builder_hash": "de21e4fc85c688c6e84b36adbb1b7ef1",
        "release_notes_hash": "60305b8e35fc693f0f9f7118f24ac390",
        "smb_frame_data": "000880212121",
        "tcp_frame_data": "00297463704672616d654865616465725f70726570656e6465645f746573745f6d657373616765",
    },
    "version": "azul_v1",
}


class OtherFeatures(extractor.Extractor):
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
