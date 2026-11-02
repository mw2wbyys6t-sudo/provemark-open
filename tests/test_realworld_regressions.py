"""真实项目测试暴露出的精度/崩溃回归。

背景：用 flask 3.1.3（PyPI sdist）、express 5.3.0（npm）、gin v1.12.0（Go module）、
serde 1.0.229（crates.io）跑了一轮外部验收，发现这些问题：

- Go/JS 的幻觉依赖记录少了 `confidence` 字段，整条 AI 扫描器直接 KeyError；
- Go 的 import 是「包路径」，go.mod 声明的是「模块路径」，逐字比较把每个第三方子包都判成未声明；
- 文档字符串里的示例 import、`if TYPE_CHECKING:` 里的类型导入被当成真实依赖；
- Rust 常见的 LICENSE-MIT / LICENSE-APACHE 不被识别为许可证文件；
- dev-only 工具的浮动版本、库没有锁文件，被当成中等风险；
- `_test.go` 里的测试数据没有被当作测试文件。
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from provemark.cache import Cache
from provemark.config import load_config
from provemark.engine import run_scan
from provemark.net import NetworkError
from provemark.scanners import ai_code, deps, files as files_scanner, repo, supply
from provemark.scanners.base import Context


def write(root: Path, rel: str, content: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content if content.endswith("\n") else content + "\n", encoding="utf-8")


def context_for(root: Path) -> Context:
    config = load_config(root)
    collected, _ = files_scanner.collect_files(root, config)
    return Context(
        root=root,
        config=config,
        files=collected,
        deps=deps.collect(root, config),
        cache=Cache(enabled=False),
    )


def rules_of(findings, *rule_ids: str) -> dict[str, object]:
    wanted = set(rule_ids)
    return {item.rule_id: item for item in findings if item.rule_id in wanted}


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()


class GoImportTests(Base):
    def test_module_prefix_covers_subpackages(self) -> None:
        """go.mod 写 `golang.org/x/net`，代码 import `golang.org/x/net/http2` 是合法的。"""
        write(
            self.root,
            "go.mod",
            "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgolang.org/x/net v0.51.0\n)\n",
        )
        write(
            self.root,
            "main.go",
            'package main\n\nimport (\n\t"fmt"\n\n\t"golang.org/x/net/http2"\n\t"golang.org/x/net/http2/h2c"\n)\n\nfunc main() { fmt.Println(http2.ClientPreface); _ = h2c.NewHandler }\n',
        )
        found = rules_of(ai_code.scan(context_for(self.root)), "AI-012")
        self.assertEqual(found, {}, "模块下的子包不应被判为未声明")

    def test_undeclared_go_import_reports_without_crashing(self) -> None:
        """回归：Go 记录曾缺少 confidence，导致整条 AI 扫描器 KeyError。"""
        write(self.root, "go.mod", "module example.com/app\n\ngo 1.22\n")
        write(
            self.root,
            "main.go",
            'package main\n\nimport (\n\t"github.com/definitely-not-declared/pkg"\n)\n\nfunc main() { pkg.Run() }\n',
        )
        findings = ai_code.scan(context_for(self.root))
        found = rules_of(findings, "AI-012").get("AI-012")
        self.assertIsNotNone(found, "未声明的 Go 依赖应当被报出")
        self.assertGreaterEqual(found.confidence, 0.5)  # type: ignore[union-attr]
        self.assertEqual(found.severity, "high")  # type: ignore[union-attr]

    def test_undeclared_js_import_reports_without_crashing(self) -> None:
        write(self.root, "package.json", '{"name": "app", "dependencies": {"express": "^4.0.0"}}')
        write(self.root, "index.js", "import leftPad from 'left-pad';\nexport default leftPad;\n")
        findings = ai_code.scan(context_for(self.root))
        found = rules_of(findings, "AI-012").get("AI-012")
        self.assertIsNotNone(found, "未声明的 npm 依赖应当被报出")
        self.assertGreaterEqual(found.confidence, 0.5)  # type: ignore[union-attr]


class PythonImportHeuristicTests(Base):
    def test_docstring_examples_are_not_imports(self) -> None:
        write(
            self.root,
            "pyproject.toml",
            '[project]\nname = "demo"\nversion = "1.0"\ndependencies = ["requests>=2"]\n',
        )
        write(
            self.root,
            "src/demo.py",
            '"""Demo module.\n\n'
            "The import name of your application matters; extensions import it.\n\n"
            "    from yourapplication import create_app\n"
            '"""\n\nimport requests\n',
        )
        found = rules_of(ai_code.scan(context_for(self.root)), "AI-012")
        self.assertEqual(found, {}, "文档字符串里的示例导入不是真实依赖")

    def test_type_checking_imports_are_ignored(self) -> None:
        write(
            self.root,
            "pyproject.toml",
            '[project]\nname = "demo"\nversion = "1.0"\ndependencies = ["requests>=2"]\n',
        )
        write(
            self.root,
            "src/demo.py",
            "import typing as t\n\nif t.TYPE_CHECKING:\n    import typing_extensions as te\n\nimport requests\n",
        )
        found = rules_of(ai_code.scan(context_for(self.root)), "AI-012")
        self.assertEqual(found, {}, "TYPE_CHECKING 块里的类型导入不应报幻觉依赖")


class SupplySeverityTests(Base):
    def test_dev_group_float_version_is_advisory(self) -> None:
        write(self.root, "README.md", "# demo")
        write(self.root, "LICENSE", "MIT License\n")
        write(
            self.root,
            "pyproject.toml",
            '[project]\nname = "demo"\nversion = "1.0"\n\n[dependency-groups]\ndev = ["ruff"]\n',
        )
        found = rules_of(supply.scan(context_for(self.root)), "SCP-002")
        self.assertTrue(found, "dev 依赖的浮动版本仍应列出")
        self.assertEqual(found["SCP-002"].severity, "info")  # type: ignore[union-attr]

    def test_library_without_lockfile_is_low(self) -> None:
        write(self.root, "README.md", "# demo")
        write(self.root, "LICENSE", "MIT License\n")
        write(self.root, "pyproject.toml", '[project]\nname = "demo"\nversion = "1.0"\ndependencies = ["requests>=2"]\n')
        found = rules_of(supply.scan(context_for(self.root)), "SCP-001")
        self.assertEqual(found["SCP-001"].severity, "low")  # type: ignore[union-attr]

    def test_application_without_lockfile_is_medium(self) -> None:
        write(self.root, "README.md", "# demo")
        write(self.root, "LICENSE", "MIT License\n")
        write(
            self.root,
            ".provemark.toml",
            '[project]\nkind = "app"\n',
        )
        write(self.root, "pyproject.toml", '[project]\nname = "demo"\nversion = "1.0"\ndependencies = ["requests>=2"]\n')
        found = rules_of(supply.scan(context_for(self.root)), "SCP-001")
        self.assertEqual(found["SCP-001"].severity, "medium")  # type: ignore[union-attr]


class LicenceFileTests(Base):
    def test_license_aliases_are_recognised(self) -> None:
        write(self.root, "README.md", "# demo")
        write(self.root, "LICENSE-MIT", "MIT License\n\nPermission is hereby granted")
        write(self.root, "LICENSE-APACHE", "Apache License\nVersion 2.0")
        found = rules_of(repo.scan(context_for(self.root)), "HYG-001")
        self.assertEqual(found, {}, "Rust 常见的 LICENSE-MIT / LICENSE-APACHE 应算作许可证文件")

    def test_missing_license_still_flagged(self) -> None:
        write(self.root, "README.md", "# demo")
        found = rules_of(repo.scan(context_for(self.root)), "HYG-001")
        self.assertIn("HYG-001", found)


class TestFileDetectionTests(Base):
    def test_per_file_test_markers(self) -> None:
        for rel, expected in (
            ("context_test.go", True),
            ("test_app.py", True),
            ("app.test.ts", True),
            ("app.spec.js", True),
            ("widget_test.rs", True),
            ("src/app.py", False),
            ("src/testing_utils.go", False),
        ):
            write(self.root, rel, "x")
            info = files_scanner.FileInfo(
                path=self.root / rel,
                rel=rel,
                size=1,
                suffix=Path(rel).suffix,
            )
            self.assertEqual(info.is_test, expected, rel)

    def test_testdata_is_treated_as_fixture(self) -> None:
        write(self.root, "testdata/protoexample/x.go", "package x")
        info = files_scanner.FileInfo(
            path=self.root / "testdata/protoexample/x.go",
            rel="testdata/protoexample/x.go",
            size=1,
            suffix=".go",
        )
        self.assertTrue(info.is_test)


class ReleaseArtifactTests(Base):
    def test_packaged_artifact_hygiene_is_advisory(self) -> None:
        """sdist/crate 里没有 .gitignore / SECURITY.md / CI，别把它们报成中危。"""
        write(self.root, "PKG-INFO", "Metadata-Version: 2.1\nName: demo\n")
        write(self.root, "README.md", "# demo")
        write(self.root, "LICENSE", "MIT License\n")
        findings = repo.scan(context_for(self.root))
        for rule in ("HYG-003", "HYG-004", "HYG-010", "HYG-014"):
            for item in findings:
                if item.rule_id == rule:
                    self.assertEqual(item.severity, "info", f"{rule} 在发布包里应为提示")

    def test_source_tree_keeps_repo_level_severity(self) -> None:
        write(self.root, "README.md", "# demo")
        write(self.root, "LICENSE", "MIT License\n")
        findings = repo.scan(context_for(self.root))
        severities = {item.rule_id: item.severity for item in findings if item.rule_id == "HYG-003"}
        self.assertEqual(severities.get("HYG-003"), "medium")


class OnlineReliabilityTests(Base):
    def test_network_failure_marks_score_unreliable(self) -> None:
        """联网失败时必须标注「数据不完整」——否则 89/B 会被读成“仓库很健康”。"""
        write(self.root, "README.md", "# demo")
        write(self.root, "LICENSE", "MIT License\n")
        write(self.root, "requirements.txt", "requests==2.31.0\nflask==3.0.0\nurllib3==2.0.7\n")
        cache_dir = self.root / ".cache"
        with mock.patch.dict(os.environ, {"PROVEMARK_CACHE_DIR": str(cache_dir)}):
            with (
                mock.patch("provemark.scanners.vuln.http_json", side_effect=NetworkError("boom")),
                mock.patch("provemark.scanners.license.http_json", side_effect=NetworkError("boom")),
                mock.patch("provemark.scanners.license.http_text", side_effect=NetworkError("boom")),
            ):
                result = run_scan(self.root, load_config(self.root), offline=False)
        self.assertFalse(result.score.reliable, "联网失败时分数必须标为仅供参考")
        self.assertTrue(
            any("联网查询失败" in note for note in result.stats.notes),
            f"缺少联网失败说明：{result.stats.notes}",
        )
        self.assertFalse(result.stats.network_used)

    def test_offline_scan_stays_honest(self) -> None:
        write(self.root, "README.md", "# demo")
        write(self.root, "LICENSE", "MIT License\n")
        write(self.root, "requirements.txt", "requests==2.31.0\n")
        cache_dir = self.root / ".cache"
        with mock.patch.dict(os.environ, {"PROVEMARK_CACHE_DIR": str(cache_dir)}):
            result = run_scan(self.root, load_config(self.root), offline=True)
        self.assertFalse(result.stats.network_used)
        self.assertTrue(any("离线模式" in note for note in result.stats.notes), result.stats.notes)


if __name__ == "__main__":
    unittest.main()
