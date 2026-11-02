"""文件收集的默认忽略目录。

CI 的 `pip install .` 会生成 build/lib/**，如果被当成源码扫描，就会在干净的
仓库里凭空冒出一条 AI-005 high（实测于 GitHub Actions）。VCS 目录、虚拟环境、
node_modules 同理：它们不是仓库作者要交付的代码。
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from provemark.config import load_config
from provemark.scanners.files import collect_files


def write(root: Path, rel: str, content: str = "x = 1\n") -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


class DefaultExcludeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        write(self.root, "pyproject.toml", '[project]\nname = "demo"\nversion = "0.1"\n')
        write(self.root, "src/app.py")
        write(self.root, "build/lib/provemark/app.py", "def run(x):\n    return eval(x)\n")
        write(self.root, "dist/app.py")
        write(self.root, "demo.egg-info/SOURCES.txt")
        write(self.root, ".git/config")
        write(self.root, "node_modules/pkg/index.js")
        write(self.root, ".venv/lib/python3.12/site-packages/x.py")
        write(self.root, ".pytest_cache/v/cache/lastfailed")

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_build_and_vcs_dirs_are_skipped(self) -> None:
        files, _ = collect_files(self.root, load_config(self.root))
        rels = {info.rel for info in files}
        self.assertIn("src/app.py", rels)
        for skipped in ("build/lib/provemark/app.py", "dist/app.py", "demo.egg-info/SOURCES.txt", ".git/config", "node_modules/pkg/index.js", ".venv/lib/python3.12/site-packages/x.py", ".pytest_cache/v/cache/lastfailed"):
            self.assertNotIn(skipped, rels)

    def test_project_excludes_still_apply(self) -> None:
        write(self.root, ".provemark.toml", '[scan]\nexclude = ["src/app.py"]\n')
        files, _ = collect_files(self.root, load_config(self.root))
        self.assertNotIn("src/app.py", {info.rel for info in files})


if __name__ == "__main__":
    unittest.main()
