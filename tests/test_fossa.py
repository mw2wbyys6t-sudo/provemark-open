from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from provemark.cache import Cache
from provemark.config import load_config
from provemark.scanners import deps, files as files_scanner, fossa, supply
from provemark.scanners.base import Context


def write(root: Path, rel: str, content: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def build_context(root: Path, *, sbom: Path | None = None, resolved: dict[str, str] | None = None) -> Context:
    config = load_config(root)
    collected, _ = files_scanner.collect_files(root, config)
    return Context(
        root=root,
        config=config,
        files=collected,
        deps=deps.collect(root, config),
        cache=Cache(enabled=False),
        sbom=sbom,
        license_resolved=resolved or {},
    )


def node_repo(root: Path) -> None:
    write(
        root,
        "package.json",
        json.dumps({"dependencies": {"lodash": "^4.17.0", "axios": "^1.6.0"}}),
    )
    write(
        root,
        "package-lock.json",
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "demo"},
                    "node_modules/lodash": {"version": "4.17.21"},
                    "node_modules/axios": {"version": "1.6.8"},
                },
            }
        ),
    )


class FossaConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_old_config_version(self) -> None:
        write(self.root, ".fossa.yml", "version: 2\ncli:\n  project: demo\n")
        rules = {finding.rule_id for finding in fossa.scan(build_context(self.root))}
        self.assertIn("FOS-005", rules)

    def test_multi_package_repo_without_scope(self) -> None:
        write(self.root, "app/package.json", json.dumps({"dependencies": {"react": "^18.2.0"}}))
        write(
            self.root,
            "service/pom.xml",
            "<project><dependencies><dependency>"
            "<groupId>com.example</groupId><artifactId>core</artifactId>"
            "<version>1.0.0</version></dependency></dependencies></project>",
        )
        write(self.root, "tool/go.mod", "module example.com/tool\n\nrequire golang.org/x/sync v0.7.0\n")
        write(self.root, ".fossa.yml", "version: 3\npaths:\n  only:\n    - app/\n")

        findings = {item.rule_id for item in fossa.scan(build_context(self.root))}
        self.assertNotIn("FOS-001", findings)

        write(self.root, ".fossa.yml", "version: 3\ncli:\n  project: demo\n")
        findings = {item.rule_id for item in fossa.scan(build_context(self.root))}
        self.assertIn("FOS-001", findings)

    def test_vendor_directory_must_be_excluded(self) -> None:
        write(self.root, "package.json", json.dumps({"name": "demo"}))
        write(self.root, "vendor/lib/thing.go", "package thing\n")
        write(self.root, "src/main.go", "package main\n")

        write(self.root, ".fossa.yml", "version: 3\ncli:\n  project: demo\n")
        findings = fossa.scan(build_context(self.root))
        vendor = [item for item in findings if item.rule_id == "FOS-002"]
        self.assertTrue(vendor)
        self.assertIn("vendor", vendor[0].evidence)

        write(
            self.root,
            ".fossa.yml",
            "version: 3\npaths:\n  exclude:\n    - vendor/\n",
        )
        findings = {item.rule_id for item in fossa.scan(build_context(self.root))}
        self.assertNotIn("FOS-002", findings)

        # paths.only 已经把 vendor/ 排除在分析范围之外，不应再报
        write(self.root, ".fossa.yml", "version: 3\npaths:\n  only:\n    - src/\n")
        findings = {item.rule_id for item in fossa.scan(build_context(self.root))}
        self.assertNotIn("FOS-002", findings)


class FossaDepsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_deps_file_problems(self) -> None:
        write(self.root, "package.json", json.dumps({"name": "demo"}))
        write(
            self.root,
            "fossa-deps.yml",
            """
referenced-dependencies:
  - type: pypi
    name: Django
  - type: unknownpm
    name: mystery
    version: "1.0.0"
custom-dependencies:
  - name: internal-sdk
    version: "2.0.0"
vendored-dependencies:
  - name: vendored-lib
    path: vendor/missing/lib.zip
""",
        )
        findings = fossa.scan(build_context(self.root))
        by_rule = [item for item in findings if item.rule_id == "FOS-003"]
        titles = " ".join(item.title for item in by_rule)
        self.assertIn("类型", titles)
        self.assertIn("版本", titles)
        self.assertIn("license", titles)
        self.assertIn("路径不存在", titles)

    def test_valid_deps_file_is_silent(self) -> None:
        write(self.root, "package.json", json.dumps({"name": "demo"}))
        write(self.root, "vendor/lib.zip", "PK")
        write(
            self.root,
            "fossa-deps.yml",
            """
referenced-dependencies:
  - type: pypi
    name: Django
    version: "2.1.7"
custom-dependencies:
  - name: internal-sdk
    version: "2.0.0"
    license: MIT
vendored-dependencies:
  - name: vendored-lib
    path: vendor/lib.zip
""",
        )
        findings = [item for item in fossa.scan(build_context(self.root)) if item.rule_id == "FOS-003"]
        self.assertFalse(findings)


class FossaGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_analyze_without_test_is_flagged(self) -> None:
        write(self.root, "package.json", json.dumps({"name": "demo"}))
        write(
            self.root,
            ".github/workflows/ci.yml",
            "jobs:\n  compliance:\n    steps:\n"
            "      - run: fossa analyze --project demo\n",
        )
        findings = [item for item in fossa.scan(build_context(self.root)) if item.rule_id == "FOS-004"]
        self.assertTrue(findings)
        self.assertEqual(findings[0].path, ".github/workflows/ci.yml")

        write(
            self.root,
            ".github/workflows/ci.yml",
            "jobs:\n  compliance:\n    steps:\n"
            "      - run: fossa analyze --project demo\n"
            "      - run: fossa test\n",
        )
        findings = [item for item in fossa.scan(build_context(self.root)) if item.rule_id == "FOS-004"]
        self.assertFalse(findings)


class FossaSbomTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        node_repo(self.root)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _cyclonedx(self) -> Path:
        payload = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "components": [
                {"name": "lodash", "version": "4.17.21", "licenses": [{"license": {"id": "GPL-3.0-only"}}]},
                {"name": "axios", "version": "1.6.8", "licenses": [{"license": {"id": "MIT"}}]},
                {"name": "vendored-thing", "version": "0.1.0", "licenses": [{"license": {"id": "Apache-2.0"}}]},
            ],
        }
        path = self.root / "sbom.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def test_conflict_fill_and_gap(self) -> None:
        sbom = self._cyclonedx()
        ctx = build_context(
            self.root,
            sbom=sbom,
            resolved={"npm:lodash@4.17.21": "MIT", "npm:axios@1.6.8": ""},
        )
        findings = fossa.scan(ctx)
        rules = {item.rule_id for item in findings}
        self.assertIn("FOS-006", rules)
        self.assertIn("FOS-007", rules)
        self.assertIn("FOS-008", rules)

        conflict = next(item for item in findings if item.rule_id == "FOS-006")
        self.assertIn("lodash", conflict.detail["conflicts"][0]["package"])
        fill = next(item for item in findings if item.rule_id == "FOS-007")
        self.assertIn("axios", " ".join(fill.detail["packages"]))
        gap = next(item for item in findings if item.rule_id == "FOS-008")
        self.assertIn("vendored-thing", " ".join(gap.detail["components"]))

    def test_spdx_sbom_is_supported(self) -> None:
        payload = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {
                    "name": "lodash",
                    "versionInfo": "4.17.21",
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "GPL-3.0-only",
                }
            ],
        }
        path = self.root / "report.spdx.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        ctx = build_context(self.root, sbom=path, resolved={"npm:lodash@4.17.21": "MIT"})
        findings = {item.rule_id for item in fossa.scan(ctx)}
        self.assertIn("FOS-006", findings)

    def test_offline_skips_license_comparison(self) -> None:
        sbom = self._cyclonedx()
        config = load_config(self.root)
        collected, _ = files_scanner.collect_files(self.root, config)
        ctx = Context(
            root=self.root,
            config=config,
            files=collected,
            deps=deps.collect(self.root, config),
            cache=Cache(enabled=False),
            offline=True,
            sbom=sbom,
            license_resolved={"npm:lodash@4.17.21": "MIT"},
        )
        rules = {item.rule_id for item in fossa.scan(ctx)}
        self.assertNotIn("FOS-006", rules)
        self.assertNotIn("FOS-007", rules)
        self.assertIn("FOS-008", rules)

    def test_broken_sbom_is_reported(self) -> None:
        path = self.root / "sbom.json"
        path.write_text("{not json", encoding="utf-8")
        rules = {item.rule_id for item in fossa.scan(build_context(self.root, sbom=path))}
        self.assertIn("FOS-006", rules)


class WorkflowRiskTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_pwn_request_and_write_all(self) -> None:
        write(self.root, "package.json", json.dumps({"name": "demo"}))
        write(
            self.root,
            ".github/workflows/pr.yml",
            """
name: pr
on: pull_request_target
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
""",
        )
        ctx = build_context(self.root)
        results = supply.scan(ctx)
        rules = {item.rule_id for item in results}
        self.assertIn("SCP-012", rules)
        self.assertIn("SCP-013", rules)

        pwn = next(item for item in results if item.rule_id == "SCP-012")
        self.assertIn("pull_request.head.sha", pwn.evidence)
        self.assertEqual(pwn.severity, "high")

    def test_safe_workflow_is_silent(self) -> None:
        write(self.root, "package.json", json.dumps({"name": "demo"}))
        write(
            self.root,
            ".github/workflows/ci.yml",
            """
name: ci
on: pull_request
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""",
        )
        rules = {item.rule_id for item in supply.scan(build_context(self.root))}
        self.assertNotIn("SCP-012", rules)
        self.assertNotIn("SCP-013", rules)


if __name__ == "__main__":
    unittest.main()
