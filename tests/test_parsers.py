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


class RequirementsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_parses_pins_ranges_and_comments(self) -> None:
        write(
            self.root,
            "requirements.txt",
            "\n".join(
                [
                    "# 注释",
                    "requests==2.32.3",
                    "flask>=3.0,<4  # 行尾注释",
                    "pillow",
                    "uvicorn[standard]==0.30.1",
                    "pkg @ https://example.com/pkg.whl",
                ]
            ),
        )
        result = deps.collect(self.root, load_config(self.root))
        versions = {p.name: p.version for p in result.packages}
        self.assertEqual(versions["requests"], "2.32.3")
        self.assertEqual(versions["flask"], "")
        self.assertEqual(versions["uvicorn"], "0.30.1")
        self.assertIn("pillow", result.declared["PyPI"])
        self.assertEqual(len(result.packages), 5)

    def test_follows_included_requirements_files(self) -> None:
        write(self.root, "requirements.txt", "-r requirements-dev.txt")
        write(self.root, "requirements-dev.txt", "pytest==8.2.0")
        result = deps.collect(self.root, load_config(self.root))
        self.assertEqual([p.name for p in result.packages], ["pytest"])

    def test_detects_custom_index(self) -> None:
        write(
            self.root,
            "requirements.txt",
            "--extra-index-url http://mirror.internal/simple\nrequests==2.32.3",
        )
        result = deps.collect(self.root, load_config(self.root))
        self.assertTrue(result.indexes)
        self.assertEqual(result.indexes[0]["url"], "http://mirror.internal/simple")

    def test_dev_scope_detected(self) -> None:
        write(self.root, "requirements-dev.txt", "black==24.4.2")
        result = deps.collect(self.root, load_config(self.root))
        self.assertEqual(result.packages[0].scope, "dev")


class PyprojectTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_pep621_and_optional_groups(self) -> None:
        write(
            self.root,
            "pyproject.toml",
            """
[project]
name = "demo"
dependencies = ["httpx==0.27.0", "rich>=13"]

[project.optional-dependencies]
dev = ["pytest==8.2.0"]

[dependency-groups]
lint = ["ruff==0.5.0"]
""",
        )
        result = deps.collect(self.root, load_config(self.root))
        scopes = {p.name: p.scope for p in result.packages}
        self.assertEqual(scopes["httpx"], "runtime")
        self.assertEqual(scopes["pytest"], "dev")
        self.assertEqual(scopes["ruff"], "dev")

    def test_poetry_dependencies(self) -> None:
        write(
            self.root,
            "pyproject.toml",
            """
[tool.poetry.dependencies]
python = "^3.12"
fastapi = "^0.111.0"

[tool.poetry.group.dev.dependencies]
black = "^24.4.0"
""",
        )
        result = deps.collect(self.root, load_config(self.root))
        names = {p.name for p in result.packages}
        self.assertIn("fastapi", names)
        self.assertNotIn("python", names)
        self.assertEqual(
            next(p.scope for p in result.packages if p.name == "black"),
            "dev",
        )


class NodeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_package_json_and_lock_resolution(self) -> None:
        write(
            self.root,
            "package.json",
            json.dumps({"dependencies": {"lodash": "^4.17.0"}, "devDependencies": {"vitest": "^1.0.0"}}),
        )
        write(
            self.root,
            "package-lock.json",
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": {"name": "demo"},
                        "node_modules/lodash": {"version": "4.17.21"},
                        "node_modules/vitest": {"version": "1.6.0", "dev": True},
                    },
                }
            ),
        )
        result = deps.collect(self.root, load_config(self.root))
        versions = {p.name: p.version for p in result.packages}
        self.assertEqual(versions["lodash"], "4.17.21")
        lodash = next(p for p in result.packages if p.name == "lodash")
        vitest = next(p for p in result.packages if p.name == "vitest")
        self.assertTrue(lodash.direct)
        self.assertEqual(vitest.scope, "dev")

    def test_yarn_lock(self) -> None:
        write(self.root, "package.json", json.dumps({"dependencies": {"react": "^18.0.0"}}))
        write(
            self.root,
            "yarn.lock",
            'react@^18.0.0:\n  version "18.3.1"\n  resolved "https://registry.yarnpkg.com/react"\n',
        )
        result = deps.collect(self.root, load_config(self.root))
        self.assertEqual(
            next(p.version for p in result.packages if p.name == "react"),
            "18.3.1",
        )


class GoAndCargoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_go_mod_block_and_indirect(self) -> None:
        write(
            self.root,
            "go.mod",
            """
module example.com/demo

go 1.22

require (
\tgithub.com/gin-gonic/gin v1.10.0
\tgithub.com/stretchr/testify v1.9.0 // indirect
)

require golang.org/x/sync v0.7.0
""",
        )
        result = deps.collect(self.root, load_config(self.root))
        versions = {p.name: p.version for p in result.packages}
        self.assertEqual(versions["github.com/gin-gonic/gin"], "1.10.0")
        self.assertEqual(versions["golang.org/x/sync"], "0.7.0")
        testify = next(p for p in result.packages if p.name.endswith("testify"))
        self.assertFalse(testify.direct)

    def test_cargo_toml_and_lock(self) -> None:
        write(
            self.root,
            "Cargo.toml",
            """
[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = "1"
tokio = { version = "1.38" }
""",
        )
        write(
            self.root,
            "Cargo.lock",
            """
[[package]]
name = "serde"
version = "1.0.203"

[[package]]
name = "tokio"
version = "1.38.0"
""",
        )
        result = deps.collect(self.root, load_config(self.root))
        versions = {p.name: p.version for p in result.packages}
        self.assertEqual(versions["serde"], "1.0.203")
        self.assertTrue(next(p for p in result.packages if p.name == "serde").direct)


if __name__ == "__main__":
    unittest.main()
