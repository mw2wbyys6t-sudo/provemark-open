from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from provemark import ai_usage, vendored
from provemark.config import load_config
from provemark.scanners import ai_code, supply

MIT_TEXT = "MIT License\n\nPermission is hereby granted, free of charge, to any person"
COMPLETE_AI_USAGE = """# AI 使用声明

## 使用的工具
- Claude Code

## 使用范围
- src/ 下的样板代码

## 人工复核
- 由两人逐行复核并跑测试

## 生成内容留存
- 未留存
"""


def write(root: Path, rel: str, content: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content if content.endswith("\n") else content + "\n", encoding="utf-8")


def context_for(root: Path):
    from provemark.cache import Cache
    from provemark.scanners import deps, files as files_scanner
    from provemark.scanners.base import Context

    config = load_config(root)
    collected, _ = files_scanner.collect_files(root, config)
    return Context(
        root=root,
        config=config,
        files=collected,
        deps=deps.collect(root, config),
        cache=Cache(enabled=False),
    )


class AiUsageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_detects_assistant_artifacts(self) -> None:
        write(self.root, "CLAUDE.md", "# rules")
        write(self.root, ".github/copilot-instructions.md", "# instructions")
        found = ai_usage.detect_artifacts(self.root)
        self.assertIn("CLAUDE.md", found)
        self.assertIn(".github/copilot-instructions.md", found)

    def test_render_has_required_sections(self) -> None:
        text = ai_usage.render(["CLAUDE.md"])
        for section in ai_usage.REQUIRED_SECTIONS:
            self.assertIn(f"## {section}", text)
        self.assertIn("`CLAUDE.md`", text)
        self.assertEqual(ai_usage.missing_sections(text), [])
        self.assertGreater(ai_usage.unfilled_placeholders(text), 0)

    def test_missing_sections_are_reported(self) -> None:
        self.assertEqual(len(ai_usage.missing_sections("# 随便写点")), 3)

    def test_write_creates_marked_file(self) -> None:
        target = self.root / ai_usage.DEFAULT_NAME
        written, redirected = ai_usage.write(target, ["CLAUDE.md"])
        self.assertEqual(written, target)
        self.assertFalse(redirected)
        self.assertIn(ai_usage.MARKER, target.read_text(encoding="utf-8"))


class VendoredTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        write(self.root, "vendor/foo/LICENSE", MIT_TEXT)
        write(self.root, "vendor/foo/index.js", "module.exports = {}")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_detects_directory_and_license(self) -> None:
        entries, _ = vendored.detect(self.root)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].path, "vendor/foo")
        self.assertEqual(entries[0].license, "MIT")

    def test_package_manager_dirs_are_ignored(self) -> None:
        write(self.root, "node_modules/bar/LICENSE", MIT_TEXT)
        entries, _ = vendored.detect(self.root)
        self.assertEqual([item.path for item in entries], ["vendor/foo"])

    def test_render_marks_upstream_as_todo(self) -> None:
        entries, truncated = vendored.detect(self.root)
        text = vendored.render(entries, truncated)
        self.assertIn("| vendor/foo | MIT | 待补齐 | 待补齐 |", text)
        self.assertEqual(vendored.pending_count(text), 2)

    def test_missing_entries_detects_gap(self) -> None:
        entries, _ = vendored.detect(self.root)
        self.assertEqual(len(vendored.missing_entries("| vendor/bar |", entries)), 1)

    def test_write_does_not_overwrite_handwritten(self) -> None:
        target = self.root / vendored.DEFAULT_NAME
        write(self.root, vendored.DEFAULT_NAME, "# 手写来源记录")
        entries, truncated = vendored.detect(self.root)
        written, redirected = vendored.write(target, entries, truncated)
        self.assertTrue(redirected)
        self.assertEqual(written.name, "VENDORED.provemark.md")
        self.assertIn("手写", target.read_text(encoding="utf-8"))


class DeclarationCheckTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        write(self.root, "README.md", "# demo")
        write(self.root, "LICENSE", MIT_TEXT)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def rules(self) -> dict[str, object]:
        ctx = context_for(self.root)
        findings = ai_code.scan(ctx) + supply.scan(ctx)
        return {
            item.rule_id: item
            for item in findings
            if item.rule_id in ("AI-013", "AI-014", "SCP-014", "SCP-015")
        }

    def test_missing_ai_declaration_is_flagged(self) -> None:
        write(self.root, "CLAUDE.md", "# rules")
        self.assertIn("AI-013", self.rules())

    def test_incomplete_ai_declaration_is_flagged(self) -> None:
        write(self.root, "CLAUDE.md", "# rules")
        write(self.root, "AI_USAGE.md", ai_usage.render(["CLAUDE.md"]))
        found = self.rules()
        self.assertNotIn("AI-013", found)
        self.assertIn("AI-014", found)
        self.assertGreater(found["AI-014"].detail["unfilled"], 0)

    def test_complete_ai_declaration_is_quiet(self) -> None:
        write(self.root, "CLAUDE.md", "# rules")
        write(self.root, "AI_USAGE.md", COMPLETE_AI_USAGE)
        self.assertEqual(self.rules(), {})

    def test_missing_vendored_record_is_flagged(self) -> None:
        write(self.root, "vendor/foo/LICENSE", MIT_TEXT)
        write(self.root, "vendor/foo/main.go", "package foo")
        found = self.rules()
        self.assertIn("SCP-014", found)
        self.assertEqual(found["SCP-014"].severity, "medium")

    def test_partial_vendored_record_reports_gap(self) -> None:
        write(self.root, "vendor/foo/LICENSE", MIT_TEXT)
        write(self.root, "vendor/foo/main.go", "package foo")
        write(self.root, "VENDORED.md", "| vendor/bar | MIT | https://x | abc123 | 未修改 |")
        found = self.rules()
        self.assertIn("SCP-015", found)
        self.assertEqual(found["SCP-015"].detail["count"], 1)

    def test_complete_vendored_record_is_quiet(self) -> None:
        write(self.root, "vendor/foo/LICENSE", MIT_TEXT)
        write(self.root, "vendor/foo/main.go", "package foo")
        write(self.root, "VENDORED.md", "| vendor/foo | MIT | https://x | abc123 | 未修改 |")
        self.assertNotIn("SCP-015", self.rules())

    def test_excluded_vendored_directory_is_not_flagged(self) -> None:
        """用户显式排除的目录不参与 vendored 归因（排除即不归本仓库管）。"""
        write(self.root, ".provemark.toml", '[scan]\nexclude = ["third_party/**"]\n')
        write(self.root, "third_party/foo/LICENSE", MIT_TEXT)
        write(self.root, "third_party/foo/main.go", "package foo")
        self.assertNotIn("SCP-014", self.rules())

    def test_default_excludes_do_not_hide_vendored_rules(self) -> None:
        """内置默认就排除 vendor/**（不扫内容），但归因规则正是为它而设。"""
        write(self.root, "vendor/foo/LICENSE", MIT_TEXT)
        write(self.root, "vendor/foo/main.go", "package foo")
        self.assertIn("SCP-014", self.rules())

    def test_vendored_detect_honours_user_exclusion_directly(self) -> None:
        from provemark.config import Config

        write(self.root, "third_party/foo/LICENSE", MIT_TEXT)
        write(self.root, "third_party/foo/main.go", "package foo")
        config = Config(root=self.root)
        config.exclude = ["third_party/**"]
        entries, _ = vendored.detect(self.root, config)
        self.assertEqual(entries, [])
        self.assertTrue(vendored.detect(self.root)[0], "不传 config 时应保持旧行为")


if __name__ == "__main__":
    unittest.main()
