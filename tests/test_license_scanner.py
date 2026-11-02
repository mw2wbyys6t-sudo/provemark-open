from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from provemark.cache import Cache
from provemark.config import load_config
from provemark.scanners import deps, files as files_scanner
from provemark.scanners import license as license_scanner
from provemark.scanners.base import Context

MIT_TEXT = "MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy"
GPL2_TEXT = "GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991"
GPL3_TEXT = "GNU GENERAL PUBLIC LICENSE\nVersion 3, 29 June 2007"


def write(root: Path, rel: str, content: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content if content.endswith("\n") else content + "\n", encoding="utf-8")


def build_context(root: Path) -> Context:
    config = load_config(root)
    collected, _ = files_scanner.collect_files(root, config)
    return Context(
        root=root,
        config=config,
        files=collected,
        deps=deps.collect(root, config),
        cache=Cache(enabled=False),
    )


class LicenseMatrixScannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        write(self.root, "requirements.txt", "requests==2.31.0\nurllib3==2.0.7")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def run_scan(self, resolved: dict[str, str]) -> list:
        ctx = build_context(self.root)
        with mock.patch.object(
            license_scanner,
            "_package_license",
            side_effect=lambda _ctx, package: resolved.get(package.name, ""),
        ):
            return license_scanner.scan(ctx)

    def test_apache_dependency_conflicts_with_gpl2_project(self) -> None:
        write(self.root, "LICENSE", GPL2_TEXT)
        findings = self.run_scan({"requests": "Apache-2.0", "urllib3": "MIT"})
        conflicts = [item for item in findings if item.rule_id == "LIC-009"]
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0].severity, "high")
        self.assertEqual(conflicts[0].detail["project_license"], "GPL-2.0-only")
        self.assertEqual(conflicts[0].detail["dependency_license"], "Apache-2.0")

    def test_compatible_combination_is_quiet(self) -> None:
        write(self.root, "LICENSE", MIT_TEXT)
        findings = self.run_scan({"requests": "MIT", "urllib3": "MIT"})
        self.assertFalse([item for item in findings if item.rule_id == "LIC-009"])

    def test_gpl3_project_with_gpl3_dependency_is_downgraded(self) -> None:
        write(self.root, "LICENSE", GPL3_TEXT)
        findings = self.run_scan({"requests": "GPL-3.0-only", "urllib3": "MIT"})
        rules = {item.rule_id: item for item in findings if item.rule_id == "LIC-004"}
        self.assertTrue(rules)
        self.assertEqual(rules["LIC-004"].severity, "info")
        self.assertIn("兼容", rules["LIC-004"].message)

    def test_missing_project_license_skips_matrix(self) -> None:
        findings = self.run_scan({"requests": "Apache-2.0", "urllib3": "MIT"})
        self.assertFalse([item for item in findings if item.rule_id in ("LIC-009", "LIC-010")])

    def test_unknown_combination_is_reported_once(self) -> None:
        write(self.root, "LICENSE", MIT_TEXT)
        write(self.root, ".provemark.toml", '[license]\nallow = ["Custom-Proprietary"]')
        findings = self.run_scan(
            {"requests": "Custom-Proprietary", "urllib3": "Custom-Proprietary"}
        )
        unknown = [item for item in findings if item.rule_id == "LIC-010"]
        self.assertEqual(len(unknown), 1)
        self.assertEqual(unknown[0].severity, "info")
        self.assertEqual(len(unknown[0].detail["pairs"]), 1)
        self.assertEqual(len(unknown[0].detail["pairs"][0]["packages"]), 2)


if __name__ == "__main__":
    unittest.main()
