from __future__ import annotations

import base64
import tempfile
import unittest
from pathlib import Path

from provemark.cache import Cache
from provemark.config import load_config
from provemark.scanners import deps, files as files_scanner, secrets
from provemark.scanners.base import Context

SECRET = "sk-proj-Q7mZ2pLx9TvR4sKd8WnB3yHf6"


def write(root: Path, rel: str, content: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content if content.endswith("\n") else content + "\n", encoding="utf-8")


def build_context(root: Path) -> Context:
    config = load_config(root)
    collected, _ = files_scanner.collect_files(root, config)
    return Context(
        root=root,
        config=config,
        files=collected,
        deps=deps.collect(root, config),
        cache=Cache(enabled=False),
    )


def scan(root: Path) -> list:
    return secrets.scan(build_context(root))


class DedupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_same_secret_in_two_files_merges_into_one(self) -> None:
        write(self.root, "a.py", f"OPENAI_API_KEY = '{SECRET}'")
        write(self.root, "b.py", f"openai_key = '{SECRET}'")
        found = [item for item in scan(self.root) if item.rule_id == "SEC-001"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].detail["count"], 2)
        self.assertEqual(len(found[0].detail["occurrences"]), 2)
        self.assertIn("重复", found[0].message)
        self.assertEqual(found[0].severity, "critical")

    def test_same_secret_twice_in_one_file_merges(self) -> None:
        write(self.root, "cfg.py", f"A = '{SECRET}'\nB = '{SECRET}'")
        found = [item for item in scan(self.root) if item.rule_id == "SEC-001"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].detail["count"], 2)

    def test_different_secrets_are_kept_separately(self) -> None:
        other = "sk-proj-Z8nA3qWb6yTc1vRf5mKd2sLj9hGx4pN"
        write(self.root, "a.py", f"A = '{SECRET}'\nB = '{other}'")
        found = [item for item in scan(self.root) if item.rule_id == "SEC-001"]
        self.assertEqual(len(found), 2)

    def test_merge_does_not_leak_temp_attribute(self) -> None:
        write(self.root, "a.py", f"A = '{SECRET}'")
        found = scan(self.root)
        self.assertTrue(found)
        self.assertFalse(any(hasattr(item, "_dedup") for item in found))


class Base64Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_base64_encoded_secret_is_detected(self) -> None:
        encoded = base64.b64encode(SECRET.encode()).decode()
        write(self.root, "loader.py", f'KEY = "{encoded}"')
        found = [item for item in scan(self.root) if item.rule_id == "SEC-001"]
        self.assertEqual(len(found), 1)
        self.assertIn("base64", found[0].title)
        self.assertIn("****", found[0].evidence)
        self.assertNotIn(SECRET, found[0].evidence)
        self.assertEqual(found[0].detail["encoding"], "base64")
        self.assertLess(found[0].confidence, 1.0)

    def test_plain_and_encoded_same_secret_merge(self) -> None:
        encoded = base64.b64encode(SECRET.encode()).decode()
        write(self.root, "a.py", f"KEY = '{SECRET}'")
        write(self.root, "b.py", f'KEY = "{encoded}"')
        found = [item for item in scan(self.root) if item.rule_id == "SEC-001"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].detail["count"], 2)

    def test_benign_base64_is_ignored(self) -> None:
        payload = base64.b64encode(b"hello world, this is plain documentation text").decode()
        write(self.root, "README.py", f'BANNER = "{payload}"')
        self.assertFalse([item for item in scan(self.root) if item.category == "secrets"])

    def test_binary_base64_is_ignored(self) -> None:
        png = base64.b64encode(b"\x89PNG\r\n\x1a\n" + bytes(range(64))).decode()
        write(self.root, "asset.py", f'IMAGE = "data:image/png;base64,{png}"')
        self.assertFalse([item for item in scan(self.root) if item.rule_id == "SEC-001"])

    def test_short_base64_is_not_decoded(self) -> None:
        encoded = base64.b64encode(b"sk-proj-short").decode()
        write(self.root, "tiny.py", f'KEY = "{encoded}"')
        self.assertFalse([item for item in scan(self.root) if item.rule_id == "SEC-001"])


if __name__ == "__main__":
    unittest.main()
