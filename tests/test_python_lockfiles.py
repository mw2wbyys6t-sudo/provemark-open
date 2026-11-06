"""Python 锁文件解析回归。

背景：`ecosystems.py` 把 uv.lock / poetry.lock / Pipfile.lock / pdm.lock 列为 PyPI 锁文件，
但解析器里没有对应实现，于是扫描真实项目（如 fastapi 的 876KB uv.lock）时，
213 个被锁定的版本全部丢失，报告成「79 个依赖版本无法确定」+ SCP-001，漏洞与许可证检查全部落空。
"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from provemark.config import load_config
from provemark.scanners import deps


def write(root: Path, rel: str, content: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


class Base(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def collect(self) -> deps.DepsResult:
        return deps.collect(self.root, load_config(self.root))

    def versions(self, result: deps.DepsResult) -> dict[str, str]:
        return {p.name: p.version for p in result.packages if p.ecosystem == "PyPI"}


class UvLockTests(Base):
    def test_parses_pinned_versions(self) -> None:
        write(
            self.root,
            "uv.lock",
            """
version = 1
revision = 5
requires-python = ">=3.10"

[[package]]
name = "fastapi"
version = "0.115.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "starlette" },
]

[[package]]
name = "starlette"
version = "0.41.3"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "typing-extensions"
version = "4.12.2"
source = { registry = "https://pypi.org/simple" }
""",
        )
        result = self.collect()
        versions = self.versions(result)
        self.assertEqual(versions["fastapi"], "0.115.0")
        self.assertEqual(versions["starlette"], "0.41.3")
        self.assertEqual(versions["typing-extensions"], "4.12.2")
        self.assertEqual([path.name for path in result.lockfiles], ["uv.lock"])

    def test_skips_project_itself_and_marks_git_sources(self) -> None:
        write(
            self.root,
            "uv.lock",
            """
[[package]]
name = "demo-app"
source = { editable = "." }

[[package]]
name = "vendored"
version = "0.3.1"
source = { git = "https://github.com/example/vendored" }

[[package]]
name = "local"
version = "1.0.0"
source = { path = "../local" }
""",
        )
        result = self.collect()
        names = {p.name for p in result.packages}
        self.assertNotIn("demo-app", names)
        vendored = next(p for p in result.packages if p.name == "vendored")
        self.assertEqual(vendored.locator, "url:git")
        local = next(p for p in result.packages if p.name == "local")
        self.assertEqual(local.locator, "file:.")

    def test_fills_version_for_manifest_dependency(self) -> None:
        write(
            self.root,
            "pyproject.toml",
            """
[project]
name = "demo"
dependencies = ["starlette>=0.40,<0.42"]
""",
        )
        write(
            self.root,
            "uv.lock",
            """
[[package]]
name = "starlette"
version = "0.41.3"
source = { registry = "https://pypi.org/simple" }
""",
        )
        result = self.collect()
        starlette = next(p for p in result.packages if p.name == "starlette")
        self.assertEqual(starlette.version, "0.41.3")
        self.assertTrue(starlette.direct)
        self.assertIn("uv.lock", starlette.manifest)

    def test_keeps_non_plain_versions(self) -> None:
        write(
            self.root,
            "uv.lock",
            """
[[package]]
name = "opentelemetry-sdk"
version = "1.26.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "outcome"
version = "1.3.0.post0"
source = { registry = "https://pypi.org/simple" }
""",
        )
        versions = self.versions(self.collect())
        self.assertEqual(versions["outcome"], "1.3.0.post0")


class PoetryLockTests(Base):
    def test_parses_pinned_versions(self) -> None:
        write(
            self.root,
            "poetry.lock",
            """
[[package]]
name = "requests"
version = "2.32.3"
description = "HTTP for Humans"
optional = false
python-versions = ">=3.8"
files = []

[[package]]
name = "pytest"
version = "8.3.3"
description = "pytest"
optional = false
python-versions = ">=3.8"
files = []
""",
        )
        result = self.collect()
        versions = self.versions(result)
        self.assertEqual(versions["requests"], "2.32.3")
        self.assertEqual(versions["pytest"], "8.3.3")
        self.assertEqual([path.name for path in result.lockfiles], ["poetry.lock"])

    def test_dev_category_marked_as_dev(self) -> None:
        write(
            self.root,
            "poetry.lock",
            """
[[package]]
name = "requests"
version = "2.32.3"
category = "main"
optional = false

[[package]]
name = "pytest"
version = "8.3.3"
category = "dev"
optional = false
""",
        )
        result = self.collect()
        scopes = {p.name: p.scope for p in result.packages}
        self.assertEqual(scopes["requests"], "runtime")
        self.assertEqual(scopes["pytest"], "dev")


class PdmLockTests(Base):
    def test_parses_pinned_versions_and_groups(self) -> None:
        write(
            self.root,
            "pdm.lock",
            """
[[package]]
name = "httpx"
version = "0.27.2"
requires-python = ">=3.8"
groups = ["default"]
files = []

[[package]]
name = "ruff"
version = "0.6.9"
requires-python = ">=3.8"
groups = ["dev"]
files = []
""",
        )
        result = self.collect()
        versions = self.versions(result)
        self.assertEqual(versions["httpx"], "0.27.2")
        self.assertEqual(versions["ruff"], "0.6.9")
        scopes = {p.name: p.scope for p in result.packages}
        self.assertEqual(scopes["httpx"], "runtime")
        self.assertEqual(scopes["ruff"], "dev")
        self.assertEqual([path.name for path in result.lockfiles], ["pdm.lock"])


class PipfileLockTests(Base):
    def test_parses_pinned_versions_and_sections(self) -> None:
        write(
            self.root,
            "Pipfile.lock",
            json.dumps(
                {
                    "_meta": {"hash": {"sha256": "abc"}},
                    "default": {
                        "requests": {
                            "hashes": ["sha256:0000000000000000000000000000000000000000000000000000000000000000"],
                            "index": "pypi",
                            "version": "==2.32.3",
                        },
                        "flask": {
                            "hashes": ["sha256:yyy"],
                            "index": "pypi",
                            "version": "==3.0.3",
                        },
                    },
                    "develop": {
                        "pytest": {
                            "hashes": ["sha256:zzz"],
                            "index": "pypi",
                            "version": "==8.3.3",
                        }
                    },
                }
            ),
        )
        result = self.collect()
        versions = self.versions(result)
        self.assertEqual(versions["requests"], "2.32.3")
        self.assertEqual(versions["flask"], "3.0.3")
        self.assertEqual(versions["pytest"], "8.3.3")
        scopes = {p.name: p.scope for p in result.packages}
        self.assertEqual(scopes["requests"], "runtime")
        self.assertEqual(scopes["pytest"], "dev")
        self.assertEqual([path.name for path in result.lockfiles], ["Pipfile.lock"])

    def test_unpinned_entry_has_no_version(self) -> None:
        write(
            self.root,
            "Pipfile.lock",
            json.dumps({"default": {"tomli": {"version": "*"}}}),
        )
        versions = self.versions(self.collect())
        self.assertNotIn("tomli", versions)


class BrokenLockTests(Base):
    def test_invalid_toml_is_skipped(self) -> None:
        write(self.root, "uv.lock", "[[package\nname = broken")
        result = self.collect()
        self.assertEqual(result.packages, [])
        self.assertEqual([path.name for path in result.lockfiles], ["uv.lock"])

    def test_invalid_json_is_skipped(self) -> None:
        write(self.root, "Pipfile.lock", "{not json")
        result = self.collect()
        self.assertEqual(result.packages, [])
        self.assertEqual([path.name for path in result.lockfiles], ["Pipfile.lock"])


if __name__ == "__main__":
    unittest.main()
