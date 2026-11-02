from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from provemark import fossa_deps, yaml_lite
from provemark.cli import main
from provemark.config import load_config


def write(root: Path, rel: str, content: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def node_repo(root: Path, version: str = "4.17.21") -> None:
    write(root, "package.json", json.dumps({"dependencies": {"lodash": "^4.17.0"}}))
    write(
        root,
        "package-lock.json",
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {"": {"name": "demo"}, "node_modules/lodash": {"version": version}},
            }
        ),
    )


def make_plan(root: Path, *, mode: str = "missing", declared=None):
    return fossa_deps.plan(
        root, load_config(root), mode=mode, declared=declared or fossa_deps.load_declared(root)
    )


class MissingModeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_vendored_only(self) -> None:
        node_repo(self.root)
        write(self.root, "vendor/lib/thing.go", "package thing\n")
        planned = make_plan(self.root)
        self.assertTrue(planned.vendored)
        self.assertFalse(planned.referenced)
        self.assertIn(("lib", "vendor/lib"), planned.vendored)

        written, redirected = fossa_deps.write(planned, self.root / "fossa-deps.yml")
        self.assertFalse(redirected)
        text = written.read_text(encoding="utf-8")
        self.assertIn(fossa_deps.MARKER, text)
        self.assertNotIn("警告", text)
        data = yaml_lite.load(text)
        self.assertNotIn("referenced-dependencies", data)
        self.assertEqual(data["vendored-dependencies"][0]["path"], "vendor/lib")

    def test_empty_plan_does_not_write(self) -> None:
        node_repo(self.root)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = main(["fossa-deps", str(self.root)])
        self.assertEqual(code, 0)
        self.assertIn("不需要生成", buffer.getvalue())
        self.assertFalse((self.root / "fossa-deps.yml").exists())


class AllModeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_exports_supported_ecosystems(self) -> None:
        node_repo(self.root)
        write(
            self.root,
            "pom.xml",
            "<project><dependencies><dependency>"
            "<groupId>org.springframework</groupId><artifactId>spring-core</artifactId>"
            "<version>6.1.5</version></dependency></dependencies></project>",
        )
        write(
            self.root,
            "requirements.txt",
            "requests==2.32.3\ninternal @ git+https://example.com/internal.git\n",
        )
        planned = make_plan(self.root, mode="all")
        refs = {(item[0], item[1]): item[2] for item in planned.referenced}
        self.assertEqual(refs[("npm", "lodash")], "4.17.21")
        self.assertEqual(refs[("maven", "org.springframework:spring-core")], "6.1.5")
        self.assertEqual(refs[("pypi", "requests")], "2.32.3")
        self.assertGreaterEqual(planned.skipped.get("本地 / Git 路径依赖（无版本可声明）", 0), 1)

        written, _ = fossa_deps.write(planned, self.root / "fossa-deps.yml")
        text = written.read_text(encoding="utf-8")
        self.assertIn("警告", text)
        self.assertIn("重叠", text)
        self.assertIn("provemark fossa-deps", text)
        data = yaml_lite.load(text)
        entries = data["referenced-dependencies"]
        self.assertTrue(all(item["type"] for item in entries))
        lodash = next(item for item in entries if item["name"] == "lodash")
        self.assertEqual(lodash["version"], "4.17.21")

    def test_float_like_version_stays_string(self) -> None:
        node_repo(self.root, version="1.0")
        planned = make_plan(self.root, mode="all")
        written, _ = fossa_deps.write(planned, self.root / "fossa-deps.yml")
        data = yaml_lite.load(written.read_text(encoding="utf-8"))
        version = data["referenced-dependencies"][0]["version"]
        self.assertEqual(version, "1.0")
        self.assertIsInstance(version, str)

    def test_unsupported_ecosystem_is_counted(self) -> None:
        write(
            self.root,
            "environment.yml",
            "dependencies:\n  - python=3.11.9\n",
        )
        planned = make_plan(self.root, mode="all")
        self.assertFalse(planned.referenced)
        self.assertTrue(any("Conda" in reason for reason in planned.skipped))

    def test_limit_truncates(self) -> None:
        write(
            self.root,
            "requirements.txt",
            "\n".join(f"pkg{i}==1.0.{i}" for i in range(5)),
        )
        planned = make_plan(self.root, mode="all")
        truncated = fossa_deps.plan(
            self.root, load_config(self.root), mode="all", limit=2
        )
        self.assertEqual(len(planned.referenced), 5)
        self.assertEqual(len(truncated.referenced), 2)
        self.assertTrue(truncated.truncated)


class ExistingFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_handwritten_file_is_not_overwritten(self) -> None:
        node_repo(self.root)
        write(self.root, "vendor/lib/thing.go", "package thing\n")
        handwritten = self.root / "fossa-deps.yml"
        write(self.root, "fossa-deps.yml", "referenced-dependencies:\n  - type: pypi\n    name: custom\n")

        planned = make_plan(self.root)
        written, redirected = fossa_deps.write(planned, handwritten)
        self.assertTrue(redirected)
        self.assertEqual(written.name, "fossa-deps.provemark.yml")
        self.assertIn("custom", handwritten.read_text(encoding="utf-8"))

    def test_generated_file_is_overwritten(self) -> None:
        node_repo(self.root)
        write(self.root, "vendor/lib/thing.go", "package thing\n")
        write(self.root, "fossa-deps.yml", f"{fossa_deps.MARKER} 0.0.0\n")
        planned = make_plan(self.root)
        written, redirected = fossa_deps.write(planned, self.root / "fossa-deps.yml")
        self.assertFalse(redirected)
        self.assertEqual(written.name, "fossa-deps.yml")
        self.assertIn("vendored-dependencies", written.read_text(encoding="utf-8"))

    def test_regenerating_keeps_own_vendored_entries(self) -> None:
        node_repo(self.root)
        write(self.root, "vendor/lib/thing.go", "package thing\n")
        first = make_plan(self.root)
        fossa_deps.write(first, self.root / "fossa-deps.yml")

        # 第二次用 all 模式重生成：自己的旧文件不能被当成"手写声明"
        second = make_plan(self.root, mode="all")
        self.assertTrue(second.vendored)
        fossa_deps.write(second, self.root / "fossa-deps.yml")
        data = yaml_lite.load((self.root / "fossa-deps.yml").read_text(encoding="utf-8"))
        self.assertIn("referenced-dependencies", data)
        self.assertIn("vendored-dependencies", data)

    def test_force_overwrites_handwritten(self) -> None:
        node_repo(self.root)
        write(self.root, "vendor/lib/thing.go", "package thing\n")
        write(self.root, "fossa-deps.yml", "referenced-dependencies: []\n")
        planned = make_plan(self.root)
        written, redirected = fossa_deps.write(planned, self.root / "fossa-deps.yml", force=True)
        self.assertFalse(redirected)
        self.assertIn("vendored-dependencies", written.read_text(encoding="utf-8"))

    def test_declared_entries_are_skipped(self) -> None:
        node_repo(self.root)
        write(
            self.root,
            "fossa-deps.yml",
            'referenced-dependencies:\n  - type: npm\n    name: lodash\n    version: "4.17.21"\n',
        )
        declared = fossa_deps.load_declared(self.root)
        planned = make_plan(self.root, mode="all", declared=declared)
        names = {item[1] for item in planned.referenced}
        self.assertNotIn("lodash", names)
        self.assertGreaterEqual(planned.skipped.get("已有手写声明（跳过）", 0), 1)

    def test_json_deps_file_is_understood(self) -> None:
        write(
            self.root,
            "fossa-deps.json",
            json.dumps(
                {
                    "referenced-dependencies": [{"type": "pypi", "name": "Django", "version": "2.1.7"}],
                    "vendored-dependencies": [{"name": "x", "path": "vendor/x"}],
                }
            ),
        )
        refs, vendored = fossa_deps.load_declared(self.root)
        self.assertIn(("pypi", "django"), refs)
        self.assertIn("vendor/x", vendored)


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_print_mode_writes_nothing(self) -> None:
        node_repo(self.root)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = main(["fossa-deps", str(self.root), "--mode", "all", "--print"])
        self.assertEqual(code, 0)
        output = buffer.getvalue()
        self.assertIn("referenced-dependencies:", output)
        self.assertIn("lodash", output)
        self.assertFalse((self.root / "fossa-deps.yml").exists())

    def test_redirect_message_mentions_flag(self) -> None:
        node_repo(self.root)
        write(self.root, "vendor/lib/thing.go", "package thing\n")
        write(self.root, "fossa-deps.yml", "referenced-dependencies: []\n")
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = main(["fossa-deps", str(self.root)])
        self.assertEqual(code, 0)
        self.assertIn("--fossa-deps-file", buffer.getvalue())
        self.assertTrue((self.root / "fossa-deps.provemark.yml").is_file())


if __name__ == "__main__":
    unittest.main()
