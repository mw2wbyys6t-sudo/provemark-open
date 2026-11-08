"""凭据文件的严重度分级。

真实仓库里的私钥绝大多数是测试夹具（例如 requests 仓库里过期的测试证书）。
把它们按「真实泄漏」计成致命，会让一个测试目录把整个仓库打成 F 分，
久而久之用户就不看这个分数了。规则：测试目录里的凭据文件降一级、置信度下调，
但仍然报出来让人判断——不能因为是测试目录就不报。
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


def write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def scan(root: Path) -> str:
    result = subprocess.run(
        [sys.executable, "-m", "provemark", "scan", str(root), "--offline", "--only", "repo", "--verbose"],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={**os.environ, "PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1"},
        timeout=180,
    )
    return result.stdout


class CredentialSeverityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        write(self.root, "README.md", "# demo\n")
        write(self.root, "LICENSE", "MIT License\n")
        subprocess.run(
            ["git", "init", "-q", "."],
            cwd=self.root,
            capture_output=True,
            check=False,
        )
        subprocess.run(
            ["git", "config", "user.email", "t@example.com"],
            cwd=self.root,
            capture_output=True,
            check=False,
        )
        subprocess.run(
            ["git", "config", "user.name", "t"],
            cwd=self.root,
            capture_output=True,
            check=False,
        )

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _commit_all(self) -> None:
        subprocess.run(["git", "add", "-A"], cwd=self.root, capture_output=True, check=False)

    def test_private_key_outside_tests_stays_critical(self) -> None:
        write(self.root, "deploy/id_rsa", "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n")
        self._commit_all()
        out = scan(self.root)
        self.assertIn("HYG-007", out)
        self.assertIn("致命", out)

    def test_private_key_in_tests_is_downgraded_but_still_reported(self) -> None:
        write(self.root, "tests/certs/expired/server.key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n")
        self._commit_all()
        out = scan(self.root)
        self.assertIn("HYG-007", out, "测试目录里的私钥仍然必须报出来")
        self.assertNotIn("致命", out, "测试目录里的私钥不应按最高级别计分")
        self.assertIn("需人工确认", out)

    def test_fixture_directory_is_treated_as_test(self) -> None:
        write(self.root, "app/fixtures/private_key.pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n")
        self._commit_all()
        out = scan(self.root)
        self.assertIn("HYG-007", out)
        self.assertNotIn("致命", out)


if __name__ == "__main__":
    unittest.main()
