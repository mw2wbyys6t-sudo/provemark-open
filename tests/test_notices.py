from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from provemark import notices
from provemark.config import load_config
from provemark.scanners import repo as repo_scanner


def write(root: Path, rel: str, content: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content if content.endswith("\n") else content + "\n", encoding="utf-8")


def context_for(root: Path):
    return notices.build_context(root, load_config(root))


class NoticesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        write(self.root, "requirements.txt", "requests==2.31.0\nurllib3==2.0.7")
        write(
            self.root,
            ".github/workflows/ci.yml",
            "jobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def collect(self, resolved: dict[str, str]):
        with mock.patch.object(notices.license_scanner, "resolve_licenses", return_value=resolved):
            return notices.collect(context_for(self.root))

    def test_render_lists_runtime_dependencies_only(self) -> None:
        entries, unknown = self.collect({"PyPI:requests@2.31.0": "Apache-2.0"})
        names = [item.name for item in entries]
        self.assertIn("requests", names)
        self.assertNotIn("actions/checkout", names)
        self.assertEqual(unknown, 1)
        text = notices.render(entries, unknown)
        self.assertIn("# Third-Party Notices", text)
        self.assertIn("Apache-2.0", text)
        self.assertIn(notices.MARKER, text)

    def test_unknown_license_is_called_out(self) -> None:
        entries, unknown = self.collect({})
        self.assertEqual(unknown, len(entries))
        text = notices.render(entries, unknown)
        self.assertIn("## 许可证未知", text)
        self.assertIn("人工补齐", text)

    def test_write_creates_marked_file(self) -> None:
        entries, unknown = self.collect({"PyPI:requests@2.31.0": "Apache-2.0"})
        target = self.root / notices.DEFAULT_NAME
        written, redirected = notices.write(entries, unknown, target)
        self.assertEqual(written, target)
        self.assertFalse(redirected)
        self.assertIn(notices.MARKER, target.read_text(encoding="utf-8"))

    def test_write_never_overwrites_handwritten_file(self) -> None:
        target = self.root / notices.DEFAULT_NAME
        write(self.root, notices.DEFAULT_NAME, "# 我手写的归因文件")
        entries, unknown = self.collect({})
        written, redirected = notices.write(entries, unknown, target)
        self.assertTrue(redirected)
        self.assertEqual(written.name, "THIRD_PARTY_NOTICES.provemark.md")
        self.assertIn("我手写的", target.read_text(encoding="utf-8"))

    def test_force_overwrites(self) -> None:
        target = self.root / notices.DEFAULT_NAME
        write(self.root, notices.DEFAULT_NAME, "# 我手写的归因文件")
        entries, unknown = self.collect({})
        written, redirected = notices.write(entries, unknown, target, force=True)
        self.assertEqual(written, target)
        self.assertFalse(redirected)
        self.assertIn(notices.MARKER, target.read_text(encoding="utf-8"))


class NoticesCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        write(self.root, "requirements.txt", "requests==2.31.0\nurllib3==2.0.7")
        write(self.root, "README.md", "# demo")
        write(self.root, "LICENSE", "MIT License\n\nPermission is hereby granted, free of charge")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def scan(self):
        return repo_scanner.scan(context_for(self.root))

    def test_missing_notices_is_flagged(self) -> None:
        findings = [item for item in self.scan() if item.rule_id == "HYG-014"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "low")

    def test_partial_notices_reports_missing_packages(self) -> None:
        write(self.root, "THIRD_PARTY_NOTICES.md", "| requests | 2.31.0 | Apache-2.0 | PyPI |")
        findings = [item for item in self.scan() if item.rule_id == "HYG-015"]
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].detail["count"], 1)
        self.assertIn("urllib3", findings[0].detail["missing"][0])

    def test_complete_notices_is_quiet(self) -> None:
        write(
            self.root,
            "THIRD_PARTY_NOTICES.md",
            "| requests | 2.31.0 | Apache-2.0 | PyPI |\n| urllib3 | 2.0.7 | MIT | PyPI |",
        )
        rules = {item.rule_id for item in self.scan()}
        self.assertNotIn("HYG-014", rules)
        self.assertNotIn("HYG-015", rules)


if __name__ == "__main__":
    unittest.main()
