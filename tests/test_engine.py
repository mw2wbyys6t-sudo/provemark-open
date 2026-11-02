from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from provemark.config import load_config
from provemark.engine import _calibration_notes, gate_failed, run_scan
from provemark.models import Finding
from provemark.report import ai_fix_prompt, render
from provemark.report import sarif
from provemark import cache as cache_module


def write(root: Path, rel: str, content: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


class EngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        write(
            self.root,
            "package.json",
            json.dumps({"dependencies": {"lodahs": "^4.17.0"}}),
        )
        write(self.root, ".gitignore", "node_modules/\n")
        write(
            self.root,
            "src/app.py",
            "\n".join(
                [
                    "import os",
                    "import requests",
                    "from requests import Session",
                    "",
                    "API_KEY = 'sk-proj-Q7mZ2pLx9TvR4sKd8WnB3yHf6'",
                    "",
                    "def load(path):",
                    "    try:",
                    "        return open(path).read()",
                    "    except Exception:",
                    "        pass",
                    "",
                ]
            ),
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def scan(self, **kwargs):
        config = load_config(self.root)
        return run_scan(self.root, config, offline=True, **kwargs)

    def test_finds_expected_categories(self) -> None:
        result = self.scan()
        rules = {finding.rule_id for finding in result.findings}
        self.assertIn("HYG-001", rules)
        self.assertIn("HYG-005", rules)
        self.assertIn("SEC-001", rules)
        self.assertIn("AI-004", rules)
        self.assertIn("AI-012", rules)
        self.assertIn("SCP-004", rules)

    def test_secret_evidence_is_masked(self) -> None:
        result = self.scan()
        secret = next(f for f in result.findings if f.rule_id == "SEC-001")
        self.assertIn("****", secret.evidence)
        self.assertNotIn("Q7mZ2pLx9TvR4sKd8WnB3yHf6", secret.evidence)

    def test_score_and_grade_present(self) -> None:
        result = self.scan()
        self.assertIsNotNone(result.score)
        self.assertLess(result.score.total, 100)
        self.assertIn(result.score.grade, ("A", "B", "C", "D", "F"))

    def test_gate_on_high(self) -> None:
        result = self.scan()
        self.assertTrue(gate_failed(result, "high"))
        self.assertTrue(gate_failed(result, "critical"))
        self.assertFalse(gate_failed(result, "none"))

    def test_offline_marks_unverified(self) -> None:
        result = self.scan()
        self.assertTrue(any("离线" in note or "未做漏洞查询" in note for note in result.stats.notes))

    def test_baseline_suppresses_and_expires(self) -> None:
        write(
            self.root,
            ".provemark.toml",
            '[[ignore]]\nrule = "SCP-001"\nreason = "锁文件稍后补"\nexpires = "2099-01-01"\n',
        )
        result = self.scan()
        self.assertFalse(any(f.rule_id == "SCP-001" for f in result.findings))
        self.assertTrue(any(f.rule_id == "SCP-001" for f in result.suppressed))

        write(
            self.root,
            ".provemark.toml",
            '[[ignore]]\nrule = "SCP-001"\nreason = "过期"\nexpires = "2020-01-01"\n',
        )
        result = self.scan()
        self.assertTrue(any(f.rule_id == "SCP-001" for f in result.findings))
        self.assertTrue(any(f.rule_id == "IGN-001" for f in result.findings))

    def test_critical_cannot_be_suppressed(self) -> None:
        write(
            self.root,
            ".provemark.toml",
            '[[ignore]]\nrule = "SEC-001"\nreason = "想蒙混过关"\nexpires = "2099-01-01"\n',
        )
        result = self.scan()
        self.assertTrue(any(f.rule_id == "IGN-002" for f in result.findings))

    def test_only_and_skip(self) -> None:
        only_secrets = self.scan(only=["secrets"])
        self.assertTrue(all(f.category == "secrets" for f in only_secrets.findings))
        skipped = self.scan(skip=["secrets", "ai"])
        self.assertFalse(any(f.category in ("secrets", "ai") for f in skipped.findings))

    def test_all_report_formats_render(self) -> None:
        result = self.scan()
        for fmt in ("table", "json", "markdown", "html", "sarif"):
            content = render(result, fmt, verbose=True)
            self.assertTrue(content.strip())
            if fmt == "json":
                json.loads(content)
            if fmt == "sarif":
                document = json.loads(content)
                self.assertEqual(document["version"], "2.1.0")
                self.assertEqual(document["runs"][0]["tool"]["driver"]["name"], "Provemark")
            if fmt == "html":
                self.assertIn("<!doctype html>", content)
                self.assertIn(result.root, content)

    def test_ai_prompt_lists_constraints(self) -> None:
        result = self.scan()
        prompt = ai_fix_prompt(result, test_command="pytest -q")
        self.assertIn("执行约束", prompt)
        self.assertIn("pytest -q", prompt)
        self.assertIn("SEC-001", prompt)

    def test_sarif_has_rules_and_locations(self) -> None:
        result = self.scan()
        document = json.loads(sarif.render(result))
        run = document["runs"][0]
        self.assertTrue(run["tool"]["driver"]["rules"])
        located = [item for item in run["results"] if item.get("locations")]
        self.assertTrue(located)
        self.assertIn("partialFingerprints", located[0])

    def test_empty_repo_is_clean_enough(self) -> None:
        with tempfile.TemporaryDirectory() as other:
            root = Path(other)
            write(root, "LICENSE", "MIT License\n\nPermission is hereby granted, free of charge")
            write(root, "README.md", "# demo")
            write(root, "SECURITY.md", "# security")
            write(root, ".gitignore", ".env\n.env.*\nnode_modules/\n__pycache__/\n")
            write(root, ".github/workflows/ci.yml", "name: ci\n")
            write(root, "tests/test_ok.py", "def test_ok():\n    assert True\n")
            result = run_scan(root, load_config(root), offline=True)
            self.assertGreaterEqual(result.score.total, 80)
            self.assertFalse(gate_failed(result, "high"))

    def test_config_severity_override(self) -> None:
        write(
            self.root,
            ".provemark.toml",
            '[severity]\n"AI-004" = "low"\n',
        )
        result = self.scan()
        overridden = [f for f in result.findings if f.rule_id == "AI-004"]
        self.assertTrue(overridden)
        self.assertTrue(all(f.severity == "low" for f in overridden))


class CacheRetentionTests(unittest.TestCase):
    def test_prunes_oldest_entries_on_save(self) -> None:
        old_max, old_keep = cache_module.MAX_ENTRIES, cache_module.KEEP_ENTRIES
        cache_module.MAX_ENTRIES, cache_module.KEEP_ENTRIES = 5, 3
        try:
            with tempfile.TemporaryDirectory() as tmp:
                directory = Path(tmp)
                cache = cache_module.Cache(directory)
                for index in range(6):
                    cache.set(f"k{index}", index)
                cache.save()
                reloaded = cache_module.Cache(directory)
                reloaded._load()
                self.assertEqual(len(reloaded._data), 3)
                self.assertNotIn("k0", reloaded._data)
                self.assertIn("k5", reloaded._data)
        finally:
            cache_module.MAX_ENTRIES, cache_module.KEEP_ENTRIES = old_max, old_keep

    def test_small_cache_is_untouched(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cache = cache_module.Cache(Path(tmp))
            cache.set("only", "value")
            cache.save()
            self.assertEqual(len(cache._data), 1)


class CalibrationNoteTests(unittest.TestCase):
    def _finding(self, category: str) -> Finding:
        return Finding(
            rule_id="AI-004" if category == "ai" else "SEC-001",
            category=category,
            severity="medium",
            title="t",
            message="m",
        )

    def test_small_result_gets_no_note(self) -> None:
        self.assertEqual(_calibration_notes([self._finding("ai") for _ in range(10)]), [])

    def test_ai_dominated_result_explains_the_score(self) -> None:
        notes = _calibration_notes([self._finding("ai") for _ in range(80)] + [self._finding("secrets")])
        self.assertTrue(any("AI 代码质量类为主" in note for note in notes))

    def test_large_mixed_result_suggests_narrowing(self) -> None:
        findings = [self._finding("security") for _ in range(250)]
        notes = _calibration_notes(findings)
        self.assertTrue(any("--only security,dependency" in note for note in notes))


if __name__ == "__main__":
    unittest.main()