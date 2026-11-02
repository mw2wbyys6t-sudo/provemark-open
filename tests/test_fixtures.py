from __future__ import annotations

import json
import os
import unittest
from pathlib import Path

from provemark import ecosystems
from provemark.config import load_config
from provemark.scanners import deps

FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "ecosystems"
EXPECTED_NAME = "expected.json"


def fixture_names() -> list[str]:
    selected = os.environ.get("FIXTURE", "").strip()
    if selected:
        return [selected]
    if not FIXTURE_ROOT.is_dir():
        return []
    return sorted(path.name for path in FIXTURE_ROOT.iterdir() if path.is_dir())


def load_expected(name: str) -> dict:
    path = FIXTURE_ROOT / name / EXPECTED_NAME
    return json.loads(path.read_text(encoding="utf-8"))


class FixtureParsingTests(unittest.TestCase):
    def test_fixtures_are_discoverable(self) -> None:
        self.assertTrue(fixture_names(), f"没有找到任何生态 fixture：{FIXTURE_ROOT}")

    def test_expected_packages_are_parsed(self) -> None:
        for name in fixture_names():
            with self.subTest(fixture=name):
                root = FIXTURE_ROOT / name
                self.assertTrue(root.is_dir(), f"fixture 不存在：{name}")
                self.assertTrue((root / EXPECTED_NAME).is_file(), f"{name} 缺少 {EXPECTED_NAME}")
                expected = load_expected(name)
                result = deps.collect(root, load_config(root))
                self.assertTrue(result.packages, f"{name} 没有解析出任何依赖")

                index = {(package.ecosystem, package.name.lower()): package for package in result.packages}
                for item in expected.get("packages", []):
                    key = (item["ecosystem"], item["name"].lower())
                    self.assertIn(key, index, f"{name} 缺少依赖 {key}，实际解析到 {sorted(index)}")
                    package = index[key]
                    self.assertEqual(
                        package.version,
                        item.get("version", ""),
                        f"{name} 的 {item['name']} 版本不一致",
                    )
                    if "scope" in item:
                        self.assertEqual(
                            package.scope,
                            item["scope"],
                            f"{name} 的 {item['name']} 作用域不一致",
                        )
                    if item.get("indirect"):
                        self.assertTrue(
                            package.indirect, f"{name} 的 {item['name']} 应标记为间接依赖"
                        )

    @unittest.skipIf(os.environ.get("FIXTURE"), "单生态矩阵模式跳过全量覆盖检查")
    def test_every_registered_ecosystem_has_fixture(self) -> None:
        covered: set[str] = set()
        for name in fixture_names():
            for item in load_expected(name).get("packages", []):
                covered.add(item["ecosystem"])
        missing = sorted(set(ecosystems.ECOSYSTEMS) - covered)
        self.assertFalse(missing, f"以下生态还没有 fixture 覆盖：{missing}")


if __name__ == "__main__":
    unittest.main()
