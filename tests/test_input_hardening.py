"""Input-hardening regressions: a scanned repository must not steer host I/O.

Two escapes are covered here:

* ``requirements.txt`` include directives (``-r ../outside.txt``) resolving out of
  the repository, which would turn a scan into an arbitrary file reader;
* the safe fixer writing through a symlink (``.gitignore -> ~/.bashrc``), which
  would edit a host file outside the project.
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from provemark.config import load_config
from provemark.fixers import Action, apply_action
from provemark.scanners import deps


def write(root: Path, rel: str, content: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def make_symlink(source: Path, link: Path) -> bool:
    try:
        os.symlink(source, link)
        return True
    except (OSError, NotImplementedError, AttributeError):
        return False


class RequirementsIncludeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.root = self.base / "repo"
        self.root.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_include_outside_the_repository_is_ignored(self) -> None:
        write(self.base, "outside.txt", "secret-dep==1.0.0\n")
        write(self.root, "requirements.txt", "-r ../outside.txt\nrequests==2.32.3\n")
        result = deps.collect(self.root, load_config(self.root))
        names = {package.name for package in result.packages}
        self.assertIn("requests", names)
        self.assertNotIn("secret-dep", names)

    def test_absolute_include_outside_the_repository_is_ignored(self) -> None:
        outside = write(self.base, "abs-outside.txt", "abs-dep==2.0.0\n")
        write(self.root, "requirements.txt", f"-r {outside}\nrequests==2.32.3\n")
        result = deps.collect(self.root, load_config(self.root))
        names = {package.name for package in result.packages}
        self.assertNotIn("abs-dep", names)

    def test_include_inside_the_repository_still_works(self) -> None:
        write(self.root, "requirements.txt", "-r requirements-dev.txt")
        write(self.root, "requirements-dev.txt", "pytest==8.2.0")
        result = deps.collect(self.root, load_config(self.root))
        self.assertEqual([package.name for package in result.packages], ["pytest"])


class FixerSymlinkTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.root = self.base / "repo"
        self.root.mkdir()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_refuses_a_symlinked_target(self) -> None:
        victim = write(self.base, "victim.txt", "keep me\n")
        if not make_symlink(victim, self.root / ".gitignore"):
            self.skipTest("symlinks are not permitted on this platform")
        action = Action(kind="append", path=".gitignore", description="追加忽略项", lines=["node_modules/"])
        message = apply_action(self.root, action)
        self.assertIn("符号链接", message)
        self.assertEqual(victim.read_text(encoding="utf-8"), "keep me\n")

    def test_refuses_a_symlinked_parent_directory(self) -> None:
        victim_dir = self.base / "victim-dir"
        victim_dir.mkdir()
        if not make_symlink(victim_dir, self.root / ".github"):
            self.skipTest("symlinks are not permitted on this platform")
        action = Action(
            kind="create",
            path=".github/workflows/provemark.yml",
            description="创建工作流",
            content="name: ci\n",
        )
        message = apply_action(self.root, action)
        self.assertIn("符号链接", message)
        self.assertFalse((victim_dir / "workflows" / "provemark.yml").exists())

    def test_still_creates_files_in_a_normal_repository(self) -> None:
        action = Action(kind="create", path="SECURITY.md", description="创建安全政策", content="# Security\n")
        message = apply_action(self.root, action)
        self.assertIn("已创建", message)
        self.assertTrue((self.root / "SECURITY.md").is_file())


if __name__ == "__main__":
    unittest.main()
