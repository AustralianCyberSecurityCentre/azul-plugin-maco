"""Test cases for plugin output."""

import os

from azul_runner import Event, FeatureValue, JobResult, State, test_template

from azul_plugin_maco.main import AzulPluginMaco

_PLUGIN_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "extractors", "with_venv")


class TestExecute(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginMaco

    def setUp(self):
        super().setUp()
        os.environ["plugin_scripts"] = _PLUGIN_DIR

    def test_maco_venv_enabled(self):
        """Test extractors are loaded and used correctly when maco is set to use a venv."""

        data = b"a normal run"
        result = self.do_execution(
            data_in=[("content", data)],
            config={"create_venv": "true", "scripts": _PLUGIN_DIR},
            no_multiprocessing=True,
        )

        self.assertJobResult(result[None], JobResult(state=State(State.Label.COMPLETED_EMPTY)))
        self.assertJobResult(
            result["MacoVenv"],
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="874b79e5e72899321c28e872d892a957ff8141d6f21128b69dd7da25bc558fb7",
                        features={"family": [FeatureValue("evil")]},
                    ),
                ],
            ),
            inspect_data=True,
        )
