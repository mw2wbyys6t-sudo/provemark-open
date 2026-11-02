"""DSH 插件包（plugin/provemark-dsh）的一致性守卫。

插件把扫描器源码复制了一份（`python/provemark/`）随包分发，这层复制是最容易
悄悄漂移的地方：改了仓库源码忘了同步，装到宿主里的就是旧规则。这里用测试把
「包清单 / loader 补丁 / 技能文档 / 随包源码」四件事钉住。
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugin" / "provemark-dsh"
SKILL = PLUGIN / "skills" / "provemark"


def _read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _python_files(root: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for path in root.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        files[path.relative_to(root).as_posix()] = path.read_bytes()
    return files


class PluginLayoutTests(unittest.TestCase):
    def test_plugin_package_exists(self) -> None:
        self.assertTrue(PLUGIN.is_dir(), "plugin/provemark-dsh 不存在")

    def test_manifest_declares_bundle(self) -> None:
        manifest = _read_json(PLUGIN / "package.json")
        self.assertEqual(manifest["name"], "provemark-dsh")
        self.assertEqual(manifest["type"], "module")
        patch = manifest["dsh"]["bundle"]["patch"]
        self.assertTrue((PLUGIN / patch).is_file(), f"dsh.bundle.patch 指向的文件不存在：{patch}")
        for entry in ("lib", "bin", "skills", "python"):
            self.assertIn(entry, manifest["files"], f"files[] 少了 {entry}")
        self.assertTrue((PLUGIN / manifest["main"]).is_file(), "main 入口不存在")

    def test_manifest_version_matches_plugin_entry(self) -> None:
        """插件包版本与入口 VERSION 一致；扫描器版本由 sync-vendor --check 守。"""
        manifest = _read_json(PLUGIN / "package.json")
        entry = (PLUGIN / "lib" / "index.js").read_text(encoding="utf-8")
        self.assertIn(f"export const VERSION = '{manifest['version']}'", entry)
        # 随包扫描器保持自己的版本号（0.4.0），与插件版本解耦
        vendored = (PLUGIN / "python" / "provemark" / "__init__.py").read_text(encoding="utf-8")
        from provemark import __version__

        self.assertIn(f'__version__ = "{__version__}"', vendored)

    def test_bundle_patch_mounts_guardrail_and_skill(self) -> None:
        text = (PLUGIN / "cordis.patch.yml").read_text(encoding="utf-8")
        self.assertRegex(text, r"(?m)^- insert:")
        # row 1: the always-on guardrail plugin
        self.assertIn("id: provemark-guard", text)
        self.assertIn("name: 'provemark-dsh'", text)
        self.assertIn("autoScan:", text)
        # row 2: the skill provider
        self.assertIn("id: provemark-skill-filesystem", text)
        self.assertIn("@deepseek-ai/dsh-skill-filesystem", text)
        self.assertIn("providerName: provemark-plugin", text)
        # 技能根必须从 baseUrl 解析包身份得到，不能写死本机路径
        self.assertIn("createRequire(baseUrl).resolve('provemark-dsh/package.json')", text)
        self.assertIn("bundledSkillDir:", text)
        self.assertNotRegex(text, r"[A-Za-z]:\\", "补丁里出现了写死的 Windows 路径")

    def test_entry_point_is_a_host_plugin(self) -> None:
        entry = (PLUGIN / "lib" / "index.js").read_text(encoding="utf-8")
        self.assertIn("export function apply(", entry)
        self.assertIn("export const name", entry)
        # 宿主插件只允许一种导出形态：apply()（不要混 default）
        self.assertNotIn("export default", entry)
        # 宿主包只能在运行时动态 import，静态 import 失败会让整个 profile 起不来
        self.assertNotRegex(entry, r"from ['\"]@deepseek-ai/", "lib/index.js 不应静态 import 宿主包")
        for module in ("config.js", "format.js", "python.js", "scan.js"):
            self.assertTrue((PLUGIN / "lib" / module).is_file(), f"lib/{module} 缺失")

    def test_entry_and_launcher_exist(self) -> None:
        self.assertTrue((PLUGIN / "lib" / "index.js").is_file())
        launcher = (PLUGIN / "bin" / "provemark.mjs").read_text(encoding="utf-8")
        self.assertIn("../lib/python.js", launcher, "启动器应复用 lib/python.js 的解释器探测")
        interpreter = (PLUGIN / "lib" / "python.js").read_text(encoding="utf-8")
        self.assertIn("PROVEMARK_PYTHON", interpreter, "缺少解释器覆盖入口")
        self.assertIn("'-P'", interpreter, "未使用 -P，扫描的仓库可能遮蔽随包模块")
        self.assertIn("PYTHONPATH", interpreter)

    def test_scripts_shipped(self) -> None:
        for name in ("install.mjs", "uninstall.mjs", "sync-vendor.mjs", "validate.mjs", "selftest.mjs"):
            self.assertTrue((PLUGIN / "scripts" / name).is_file(), f"scripts/{name} 缺失")

    @unittest.skipUnless(shutil.which("node"), "node 不在 PATH，跳过插件端到端自检")
    def test_selftest_passes(self) -> None:
        result = subprocess.run(
            ["node", "scripts/selftest.mjs", "--repo", str(ROOT)],
            cwd=PLUGIN,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=240,
        )
        self.assertEqual(result.returncode, 0, (result.stdout or "") + (result.stderr or ""))
        self.assertIn("[selftest] pass", result.stdout)


class SkillDocumentTests(unittest.TestCase):
    def test_frontmatter(self) -> None:
        text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        front = re.match(r"^---\r?\n([\s\S]*?)\r?\n---\r?\n", text)
        self.assertIsNotNone(front, "SKILL.md 缺少 YAML frontmatter")
        block = front.group(1)  # type: ignore[union-attr]
        self.assertRegex(block, r"(?m)^name:\s*provemark\s*$")
        description = re.search(r"(?m)^description:\s*(.+)$", block)
        self.assertIsNotNone(description, "SKILL.md 缺少 description")
        value = description.group(1).strip("\"'")  # type: ignore[union-attr]
        self.assertGreaterEqual(len(value), 120, "description 太短，技能路由会匹配不到")
        self.assertIn("扫描", value)
        self.assertRegex(value, r"audit|vulnerabilit|license", msg="description 缺少英文触发词")

    def test_referenced_files_exist(self) -> None:
        text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        referenced = set(re.findall(r"references/([\w.-]+\.md)", text))
        self.assertGreaterEqual(len(referenced), 4, "SKILL.md 应索引各参考文件")
        for name in sorted(referenced):
            self.assertTrue((SKILL / "references" / name).is_file(), f"references/{name} 不存在")

    def test_commands_mentioned_exist_in_cli(self) -> None:
        from provemark.cli import build_parser

        parser = build_parser()
        subparsers = [action for action in parser._actions if action.dest == "command"]  # noqa: SLF001
        choices = set(subparsers[0].choices or {}) if subparsers else set()
        text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
        mentioned = set(re.findall(r"provemark\.mjs\"?\s+([a-z][a-z-]*)", text))
        unknown = {name for name in mentioned if name not in choices and name not in {"--pm-info", "--version"}}
        self.assertFalse(unknown, f"SKILL.md 提到了不存在的子命令：{sorted(unknown)}")


class VendoredScannerTests(unittest.TestCase):
    def test_vendored_copy_matches_source(self) -> None:
        source = _python_files(ROOT / "provemark")
        vendored = _python_files(PLUGIN / "python" / "provemark")
        self.assertTrue(vendored, "随包源码为空")
        missing = sorted(set(source) - set(vendored))
        extra = sorted(set(vendored) - set(source))
        self.assertFalse(missing, f"随包源码缺文件（先跑 scripts/sync-vendor.mjs）：{missing}")
        self.assertFalse(extra, f"随包源码多出文件：{extra}")
        differing = sorted(name for name in source if source[name] != vendored[name])
        self.assertFalse(differing, f"随包源码与仓库不一致（先跑 scripts/sync-vendor.mjs）：{differing}")

    def test_vendored_metadata(self) -> None:
        from provemark import __version__

        meta = _read_json(PLUGIN / "python" / "provemark" / "VENDORED.json")
        self.assertEqual(meta["version"], __version__)
        self.assertNotIn(":", meta["source"].split("/")[0], "VENDORED.json 不应记录本机绝对路径")


if __name__ == "__main__":
    unittest.main()
