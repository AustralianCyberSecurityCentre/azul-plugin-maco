"""Test cases for the 'other' optional Maco field."""

import os

from azul_runner import Event, EventData, EventParent
from azul_runner import FeatureValue as FV
from azul_runner import JobResult, State, test_template

from azul_plugin_maco.main import AzulPluginMaco

_TDIR = os.path.dirname(os.path.realpath(__file__))


class TestExecute(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginMaco

    def setUp(self):
        super().setUp()
        os.environ["plugin_scripts"] = os.path.join(_TDIR, "extractors", "basic")

    def test_other_not_azul(self):
        """Test that 'other' without azul version gets ignored."""

        data = b"a normal run"

        result = self.do_execution(
            data_in=[("content", data)],
            config={
                "create_venv": "false",
                "scripts": os.path.join(_TDIR, "extractors", "other", "other_not_azul_ignored"),
            },
            no_multiprocessing=True,
        )
        self.assertJobResult(result[None], JobResult(state=State(State.Label.COMPLETED_EMPTY)))
        self.assertJobResult(
            result["OtherNotAzul"],
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="874b79e5e72899321c28e872d892a957ff8141d6f21128b69dd7da25bc558fb7",
                        features={"family": [FV("random")]},
                    )
                ],
            ),
        )

    def test_other_not_azul_error(self):
        """Test that 'other' with an azul version and unmapped data returns an error."""
        data = b"a normal run"

        result = self.do_execution(
            data_in=[("content", data)],
            config={
                "create_venv": "false",
                "scripts": os.path.join(_TDIR, "extractors", "other", "other_not_azul_error"),
            },
            no_multiprocessing=True,
        )
        self.assertEqual(result["OtherNotAzulError"].state.failure_name, "ExtractorOtherMappingException")

    def test_other(self):
        """Test 'other' with azul version and valid features and report."""
        data = b"a normal run"

        result = self.do_execution(
            data_in=[("content", data)],
            config={
                "create_venv": "false",
                "scripts": os.path.join(_TDIR, "extractors", "other", "other_valid_features"),
            },
            no_multiprocessing=True,
        )
        self.assertJobResult(result[None], JobResult(state=State(State.Label.COMPLETED_EMPTY)))
        self.assertJobResult(
            result["OtherValidFeatures"],
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="874b79e5e72899321c28e872d892a957ff8141d6f21128b69dd7da25bc558fb7",
                        features={
                            "config_offset": [FV(394)],
                            "config_section_name": [FV(".abc")],
                            "config_size": [FV(13)],
                            "config_type": [FV("standard", label="mongoose", offset=394, size=13)],
                            "config_file_extensions": [FV(".txt"), FV(".docx"), FV(".swf")],
                            "family": [FV("random")],
                        },
                        data=[
                            EventData(
                                hash="f71222bb898359be8df31042439ee36eba63546f333af661ae23db10fbb69df2",
                                label="text",
                            )
                        ],
                    )
                ],
                data={
                    "f71222bb898359be8df31042439ee36eba63546f333af661ae23db10fbb69df2": b"some text\nsome text\nsome text\nsome text\nsome text\nsome text\nsome text\nsome text\nsome text\nsome text\n"
                },
            ),
            inspect_data=True,
        )

    def test_binary_other_not_azul(self):
        """Test that binary 'other' without azul version gets ignored."""

        data = b"a normal run"

        result = self.do_execution(
            data_in=[("content", data)],
            config={
                "create_venv": "false",
                "scripts": os.path.join(_TDIR, "extractors", "other", "other_binary_not_azul"),
            },
            no_multiprocessing=True,
        )
        self.assertJobResult(result[None], JobResult(state=State(State.Label.COMPLETED_EMPTY)))
        self.assertJobResult(
            result["OtherBinaryNotAzul"],
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
                ],
                data={"03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4": b"1234"},
            ),
            inspect_data=True,
        )

    def test_binary_other_not_azul_error(self):
        """Test that binary 'other' with an azul version and unmapped data returns an error."""

        data = b"a normal run"

        result = self.do_execution(
            data_in=[("content", data)],
            config={
                "create_venv": "false",
                "scripts": os.path.join(_TDIR, "extractors", "other", "other_binary_unmapped"),
            },
            no_multiprocessing=True,
        )
        self.assertEqual(result["OtherBinaryUnmapped"].state.failure_name, "ExtractorOtherMappingException")
