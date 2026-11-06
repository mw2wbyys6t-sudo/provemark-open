from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from provemark.cli import main
from provemark.config import ConfigError, load_config


def write(root: Path, rel: str, content: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def run(args: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(args)
        except SystemExit as exc:  # argparse 报错
            code = int(exc.code or 0)
    return code, out.getvalue(), err.getvalue()


class ScanErrorPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        write(self.root, "package.json", json.dumps({"name": "demo"}))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_missing_repo_path(self) -> None:
        code, _, err = run(["scan", str(self.root / "nope"), "--offline"])
        self.assertEqual(code, 2)
        self.assertIn("路径不存在", err)

    def test_unknown_scanner_name(self) -> None:
        code, _, err = run(["scan", str(self.root), "--offline", "--only", "nope"])
        self.assertEqual(code, 2)
        self.assertIn("未知扫描器", err)

    def test_sbom_file_missing(self) -> None:
        code, _, err = run(
            ["scan", str(self.root), "--offline", "--sbom", str(self.root / "nope.json")]
        )
        self.assertEqual(code, 2)
        self.assertIn("SBOM 文件不存在", err)

    def test_output_directory_missing(self) -> None:
        code, _, err = run(
            ["scan", str(self.root), "--offline", "-o", str(self.root / "no" / "report.html")]
        )
        self.assertEqual(code, 2)
        self.assertIn("写入失败", err)

    def test_output_table_directory_missing(self) -> None:
        code, _, err = run(
            ["scan", str(self.root), "--offline", "-o", str(self.root / "no" / "report")]
        )
        self.assertEqual(code, 2)
        self.assertIn("写入失败", err)

    def test_staged_outside_git(self) -> None:
        code, _, err = run(["scan", str(self.root), "--offline", "--staged"])
        self.assertEqual(code, 2)
        self.assertIn("暂存区", err)


class ConfigValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _load(self, body: str):
        write(self.root, ".provemark.toml", body)
        return load_config(self.root)

    def test_rejects_quoted_number(self) -> None:
        with self.assertRaises(ConfigError) as ctx:
            self._load('[scan]\nmax_files = "abc"\n')
        self.assertIn("整数", str(ctx.exception))

    def test_rejects_string_timeout(self) -> None:
        with self.assertRaises(ConfigError) as ctx:
            self._load('[network]\ntimeout = "20"\n')
        self.assertIn("数字", str(ctx.exception))

    def test_rejects_typo_gate_value(self) -> None:
        with self.assertRaises(ConfigError) as ctx:
            self._load('[gate]\nfail_on = "hgih"\n')
        self.assertIn("fail_on", str(ctx.exception))

    def test_rejects_typo_severity_floor(self) -> None:
        with self.assertRaises(ConfigError):
            self._load('[scan]\nseverity_floor = "loww"\n')

    def test_rejects_typo_license_unknown(self) -> None:
        with self.assertRaises(ConfigError) as ctx:
            self._load('[license]\nunknown = "midium"\n')
        self.assertIn("license.unknown", str(ctx.exception))

    def test_rejects_unknown_project_kind(self) -> None:
        with self.assertRaises(ConfigError):
            self._load('[project]\nkind = "service"\n')

    def test_rejects_bad_severity_override_key(self) -> None:
        with self.assertRaises(ConfigError):
            self._load('[severity]\n"bad-key" = "low"\n')

    def test_rejects_bad_severity_override_value(self) -> None:
        with self.assertRaises(ConfigError):
            self._load('[severity]\n"AI-004" = "urgent"\n')

    def test_accepts_valid_values(self) -> None:
        config = self._load(
            '[project]\nkind = "app"\n[scan]\nmax_files = 500\nseverity_floor = "low"\n'
            '[gate]\nfail_on = "critical"\n[network]\ntimeout = 5\n'
            '[severity]\n"AI-004" = "high"\n'
        )
        self.assertEqual(config.project_kind, "app")
        self.assertEqual(config.max_files, 500)
        self.assertEqual(config.severity_floor, "low")
        self.assertEqual(config.fail_on, "critical")
        self.assertEqual(config.timeout, 5.0)
        self.assertEqual(config.severity_overrides, {"AI-004": "high"})

    def test_cli_reports_config_error_without_traceback(self) -> None:
        write(self.root, ".provemark.toml", '[scan]\nmax_files = "abc"\n')
        code, _, err = run(["scan", str(self.root), "--offline"])
        self.assertEqual(code, 2)
        self.assertIn("配置错误", err)
        self.assertNotIn("Traceback", err)


class MinConfidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        write(self.root, "package.json", json.dumps({"name": "demo"}))
        write(
            self.root,
            "src/sign.py",
            "signing_key = 'Zx9Q2mK7pL4vB8nR3tY6wA1sD5gH0jF2cV7bN'\n",
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_default_threshold_blocks(self) -> None:
        code, _, _ = run(
            ["scan", str(self.root), "--offline", "--only", "secrets", "--fail-on", "high", "--quiet"]
        )
        self.assertEqual(code, 1)

    def test_flag_raises_threshold(self) -> None:
        code, _, _ = run(
            [
                "scan",
                str(self.root),
                "--offline",
                "--only",
                "secrets",
                "--fail-on",
                "high",
                "--min-confidence",
                "0.8",
                "--quiet",
            ]
        )
        self.assertEqual(code, 0)

    def test_flag_rejects_out_of_range(self) -> None:
        code, _, err = run(["scan", str(self.root), "--offline", "--min-confidence", "2"])
        self.assertEqual(code, 2)
        self.assertIn("0 到 1", err)


class TrackedExcludeTests(unittest.TestCase):
    def test_excluded_tracked_file_skips_hygiene_checks(self) -> None:
        if shutil.which("git") is None:
            self.skipTest("需要 git")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, ".env", "DEMO=1\n")
            write(root, ".gitignore", ".env\n")
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "add", "-f", ".env"], cwd=root, check=True)

            _, out, _ = run(["scan", str(root), "--offline", "--verbose", "--no-color"])
            self.assertIn("HYG-006", out)

            write(root, ".provemark.toml", '[scan]\nexclude = [".env"]\n')
            _, out, _ = run(["scan", str(root), "--offline", "--verbose", "--no-color"])
            self.assertNotIn("HYG-006", out)


class FixerTests(unittest.TestCase):
    def test_apache_license_text_is_bundled(self) -> None:
        from provemark.fixers import license_text

        text = license_text("Apache-2.0", "Demo", 2026, offline=True)
        self.assertIn("Apache License", text)
        self.assertGreater(len(text), 10000)

    def test_fix_applies_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "README.md", "# demo")
            code, _, _ = run(["fix", str(root), "--apply"])
            self.assertEqual(code, 0)
            self.assertTrue((root / "LICENSE").is_file())

    def test_fix_uses_license_from_license_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, "LICENSE", "GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991")
            write(root, "README.md", "# demo")
            code, _, _ = run(["fix", str(root), "--apply"])
            self.assertEqual(code, 0)
            text = (root / ".provemark.toml").read_text(encoding="utf-8")
            self.assertIn('license = "GPL-2.0-only"', text)


class LegacyCompatTests(unittest.TestCase):
    def test_reads_legacy_config_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, ".reposentinel.toml", '[gate]\nfail_on = "critical"\n')
            self.assertEqual(load_config(root).fail_on, "critical")

    def test_new_config_wins_over_legacy(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, ".reposentinel.toml", '[gate]\nfail_on = "critical"\n')
            write(root, ".provemark.toml", '[gate]\nfail_on = "low"\n')
            self.assertEqual(load_config(root).fail_on, "low")

    def test_legacy_config_triggers_notice(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write(root, ".reposentinel.toml", '[gate]\nfail_on = "critical"\n')
            write(root, "README.md", "# demo")
            _, _, err = run(["scan", str(root), "--offline"])
            self.assertIn(".provemark.toml", err)

    def test_legacy_cache_env_still_works(self) -> None:
        from provemark.cache import default_cache_dir

        env = {key: value for key, value in os.environ.items() if "CACHE" not in key}
        env["REPOSENTINEL_CACHE_DIR"] = "/tmp/legacy-cache"
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(str(default_cache_dir()), str(Path("/tmp/legacy-cache")))

    def test_new_cache_env_wins(self) -> None:
        from provemark.cache import default_cache_dir

        env = {key: value for key, value in os.environ.items() if "CACHE" not in key}
        env["PROVEMARK_CACHE_DIR"] = "/tmp/new-cache"
        env["REPOSENTINEL_CACHE_DIR"] = "/tmp/legacy-cache"
        with mock.patch.dict(os.environ, env, clear=True):
            self.assertEqual(str(default_cache_dir()), str(Path("/tmp/new-cache")))


class CommandTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_init_preview_then_apply(self) -> None:
        code, out, _ = run(["init", str(self.root)])
        self.assertEqual(code, 0)
        self.assertIn("这是预览", out)
        self.assertFalse((self.root / "LICENSE").exists())

        code, _, _ = run(["init", str(self.root), "--apply"])
        self.assertEqual(code, 0)
        for name in ("LICENSE", ".gitignore", "SECURITY.md", ".provemark.toml"):
            self.assertTrue((self.root / name).exists(), name)

    def test_fix_preview_then_apply(self) -> None:
        code, out, _ = run(["fix", str(self.root)])
        self.assertEqual(code, 0)
        self.assertIn("预览", out)
        self.assertFalse((self.root / "LICENSE").exists())

        code, _, _ = run(["fix", str(self.root), "--apply"])
        self.assertEqual(code, 0)
        self.assertTrue((self.root / "LICENSE").exists())

    def test_fix_rejects_unknown_only_scope(self) -> None:
        """拼错的 --only 必须报错，不能静默什么都不做。"""
        code, _, err = run(["fix", str(self.root), "--only", "readme"])
        self.assertEqual(code, 2)
        self.assertIn("未知修复项", err)
        self.assertIn("license", err)

    def test_fix_accepts_documented_only_scopes(self) -> None:
        for scope in ("license", "gitignore", "security", "config", "ci"):
            code, _, err = run(["fix", str(self.root), "--only", scope])
            self.assertEqual(code, 0, f"{scope}: {err}")

    def test_ignore_appends_rule(self) -> None:
        code, _, _ = run(
            [
                "ignore",
                "--root",
                str(self.root),
                "--rule",
                "AI-004",
                "--reason",
                "历史遗留",
                "--expires",
                "2099-01-01",
            ]
        )
        self.assertEqual(code, 0)
        text = (self.root / ".provemark.toml").read_text(encoding="utf-8")
        self.assertIn('rule = "AI-004"', text)
        self.assertIn("历史遗留", text)

    def test_ignore_requires_criterion(self) -> None:
        code, _, err = run(
            ["ignore", "--root", str(self.root), "--reason", "x", "--expires", "2099-01-01"]
        )
        self.assertEqual(code, 2)
        self.assertIn("至少提供", err)

    def test_ignore_rejects_past_expiry(self) -> None:
        code, _, err = run(
            [
                "ignore",
                "--root",
                str(self.root),
                "--rule",
                "AI-004",
                "--reason",
                "x",
                "--expires",
                "2020-01-01",
            ]
        )
        self.assertEqual(code, 2)
        self.assertIn("必须晚于今天", err)

    def test_ignore_rejects_bad_date(self) -> None:
        code, _, err = run(
            [
                "ignore",
                "--root",
                str(self.root),
                "--rule",
                "AI-004",
                "--reason",
                "x",
                "--expires",
                "2099/01/01",
            ]
        )
        self.assertEqual(code, 2)
        self.assertIn("YYYY-MM-DD", err)

    def test_explain_known_and_unknown(self) -> None:
        code, out, _ = run(["explain", "AI-004"])
        self.assertEqual(code, 0)
        self.assertIn("AI-004", out)

        code, _, err = run(["explain", "ZZZ-999"])
        self.assertEqual(code, 2)
        self.assertIn("没有找到规则", err)

    def test_rules_lists_entries(self) -> None:
        code, out, _ = run(["rules"])
        self.assertEqual(code, 0)
        self.assertIn("AI-001", out)
        self.assertIn("FOS-006", out)

    def test_hook_install_and_uninstall(self) -> None:
        (self.root / ".git").mkdir()
        code, out, _ = run(["hook", "install", str(self.root)])
        self.assertEqual(code, 0)
        hook = self.root / ".git" / "hooks" / "pre-commit"
        self.assertTrue(hook.exists())
        self.assertIn("已安装", out)

        code, out, _ = run(["hook", "uninstall", str(self.root)])
        self.assertEqual(code, 0)
        self.assertFalse(hook.exists())

    def test_hook_requires_git(self) -> None:
        code, out, _ = run(["hook", "install", str(self.root)])
        self.assertEqual(code, 2)
        self.assertIn("不是 Git 仓库", out)


class UnsafeRootTests(unittest.TestCase):
    """文件系统根与用户主目录必须快速拒绝，而不是花几分钟去遍历。"""

    def test_filesystem_root_is_refused(self) -> None:
        root = Path.cwd().anchor or "/"
        code, _, err = run(["scan", root, "--offline"])
        self.assertEqual(code, 2)
        self.assertIn("文件系统根", err)

    def test_home_directory_is_refused(self) -> None:
        code, _, err = run(["scan", str(Path.home()), "--offline"])
        self.assertEqual(code, 2)
        self.assertIn("用户主目录", err)

    def test_init_and_fix_also_refuse_root(self) -> None:
        root = Path.cwd().anchor or "/"
        for command in ("init", "fix"):
            code, _, err = run([command, root])
            self.assertEqual(code, 2, command)
            self.assertIn("拒绝", err, command)


if __name__ == "__main__":
    unittest.main()
