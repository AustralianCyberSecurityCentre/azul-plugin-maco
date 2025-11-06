"""Test cases for plugin output."""

import os

from azul_runner import (
    Event,
    EventData,
    EventParent,
    FeatureValue,
    Filepath,
    JobResult,
    State,
    Uri,
    test_template,
)

from azul_plugin_maco.main import AzulPluginMaco

FV = FeatureValue
FVU = lambda x: FeatureValue(Uri(x))
FVP = lambda x: FeatureValue(Filepath(x))


_PLUGIN_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "extractors", "grandchild")


class TestExecute(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginMaco

    def setUp(self):
        super().setUp()
        os.environ["plugin_scripts"] = _PLUGIN_DIR

    def test_binary_grandchild(self):
        """Test child and grandchild binaries."""

        data = b"a normal run"

        result = self.do_execution(
            data_in=[("content", data)],
            config={"create_venv": "false", "scripts": _PLUGIN_DIR},
            no_multiprocessing=True,
        )
        self.assertJobResult(result[None], JobResult(state=State(State.Label.COMPLETED_EMPTY)))
        self.assertJobResult(
            result["ChildBinary"],
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="874b79e5e72899321c28e872d892a957ff8141d6f21128b69dd7da25bc558fb7",
                        features={"family": [FV("random")]},
                    ),
                    Event(
                        parent=EventParent(
                            entity_type="binary",
                            entity_id="874b79e5e72899321c28e872d892a957ff8141d6f21128b69dd7da25bc558fb7",
                        ),
                        entity_type="binary",
                        entity_id="03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4",
                        relationship={"action": "extracted"},
                        data=[
                            EventData(
                                hash="03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4",
                                label="content",
                            )
                        ],
                    ),
                    Event(
                        parent=EventParent(
                            parent=EventParent(
                                entity_type="binary",
                                entity_id="874b79e5e72899321c28e872d892a957ff8141d6f21128b69dd7da25bc558fb7",
                            ),
                            entity_type="binary",
                            entity_id="03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4",
                            relationship={"action": "extracted"},
                        ),
                        entity_type="binary",
                        entity_id="f8638b979b2f4f793ddb6dbd197e0ee25a7a6ea32b0ae22f5e3c5d119d839e75",
                        relationship={"action": "extracted", "datatype": "config"},
                        data=[
                            EventData(
                                hash="f8638b979b2f4f793ddb6dbd197e0ee25a7a6ea32b0ae22f5e3c5d119d839e75",
                                label="content",
                            )
                        ],
                        features={
                            "algorithm": [FV("AES", label="binary")],
                            "algorithm_binary": [FV("AES")],
                            "iv": [FV("5481", label="binary_AES")],
                            "key": [FV("16884a684", label="binary_AES")],
                            "mode": [FV("block", label="binary_AES")],
                            "nonce": [FV("12432", label="binary_AES")],
                            "public_key": [FV("afhnre9o48y", label="binary_AES")],
                            "seed": [FV("5", label="binary_AES")],
                        },
                    ),
                ],
                data={
                    "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4": b"1234",
                    "f8638b979b2f4f793ddb6dbd197e0ee25a7a6ea32b0ae22f5e3c5d119d839e75": b"5678",
                },
            ),
            inspect_data=True,
        )
