from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

import yaml

from provemark.config import DEFAULT_CONFIG_TEMPLATE, Config, load_config
from provemark.cli import main
from provemark.fixers import CI_TEMPLATE

ROOT = Path(__file__).resolve().parent.parent
ACTION_FILE = ROOT / "action" / "action.yml"


class ActionManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(ACTION_FILE.is_file(), f"缺少 {ACTION_FILE}")
        self.data = yaml.safe_load(ACTION_FILE.read_text(encoding="utf-8"))

    def test_is_composite_action(self) -> None:
        self.assertEqual(self.data["runs"]["using"], "composite")
        self.assertIn("name", self.data)
        self.assertIn("description", self.data)

    def test_gate_defaults_match_policy(self) -> None:
        inputs = self.data["inputs"]
        self.assertEqual(inputs["fail-on"]["default"], "high")
        self.assertEqual(inputs["min-confidence"]["default"], "0.5")

    def test_installs_from_its_own_ref(self) -> None:
        steps = self.data["runs"]["steps"]
        install = next(step for step in steps if step.get("name") == "Install Provemark")
        self.assertIn("github.action_repository", str(install["env"]))
        self.assertIn("github.action_ref", str(install["env"]))
        self.assertIn("git+https://github.com/", install["run"])

    def test_scan_uses_inputs_and_outputs_sarif(self) -> None:
        steps = self.data["runs"]["steps"]
        scan = next(step for step in steps if step.get("id") == "scan")
        self.assertIn("--fail-on", scan["run"])
        self.assertIn("--min-confidence", scan["run"])
        self.assertIn("--format sarif", scan["run"])
        self.assertIn("sarif-path", self.data["outputs"])

    def test_upload_is_optional(self) -> None:
        steps = self.data["runs"]["steps"]
        upload = next(step for step in steps if step.get("name") == "Upload SARIF")
        self.assertIn("upload-sarif", upload["if"])
        self.assertEqual(upload["uses"], "github/codeql-action/upload-sarif@v4")
        self.assertTrue(upload.get("continue-on-error"))

    def test_setup_python_present(self) -> None:
        steps = self.data["runs"]["steps"]
        self.assertTrue(any(str(step.get("uses", "")).startswith("actions/setup-python@") for step in steps))


class PolicyDefaultsTests(unittest.TestCase):
    def test_config_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Config(root=Path(tmp))
        self.assertEqual(config.fail_on, "high")
        self.assertEqual(config.min_confidence, 0.5)

    def test_template_documents_gate_defaults(self) -> None:
        self.assertIn('fail_on = "high"', DEFAULT_CONFIG_TEMPLATE)
        self.assertIn("min_confidence = 0.5", DEFAULT_CONFIG_TEMPLATE)

    def test_generated_workflow_passes_both_flags(self) -> None:
        self.assertIn("--fail-on high", CI_TEMPLATE)
        self.assertIn("--min-confidence 0.5", CI_TEMPLATE)

    def test_init_writes_readable_policy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["init", str(root), "--apply", "--no-ci"]), 0)
            config = load_config(root)
        self.assertEqual(config.fail_on, "high")
        self.assertEqual(config.min_confidence, 0.5)


if __name__ == "__main__":
    unittest.main()
