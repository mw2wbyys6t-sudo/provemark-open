from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from provemark.cache import Cache
from provemark.config import load_config
from provemark.engine import run_scan
from provemark.scanners import deps, files as files_scanner, pii
from provemark.scanners.base import Context

ALL = ["sg-pdpa", "th-pdpa", "id-pdp", "my-pdpa", "ph-dpa"]


def write(root: Path, rel: str, content: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content if content.endswith("\n") else content + "\n", encoding="utf-8")


def set_jurisdictions(root: Path, items: list[str]) -> None:
    write(
        root,
        ".pdp-compliance.json",
        json.dumps({"personalDataProtection": {"jurisdictions": items}}, ensure_ascii=False),
    )


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
    return pii.scan(build_context(root))


def th_id(prefix: str) -> str:
    total = sum(int(prefix[index]) * (13 - index) for index in range(12))
    return prefix + str((11 - total % 11) % 10)


class PiiTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()


class EmailTests(PiiTestCase):
    def test_real_email_is_reported_and_masked(self) -> None:
        write(self.root, "src/user.py", 'CONTACT = "alice.tan@gmail.com"')
        found = [item for item in scan(self.root) if item.rule_id == "PII-001"]
        self.assertEqual(len(found), 1)
        self.assertNotIn("alice.tan", found[0].evidence)
        self.assertIn("***@gmail.com", found[0].evidence)
        self.assertEqual(found[0].severity, "low")

    def test_placeholder_domains_are_ignored(self) -> None:
        write(
            self.root,
            "src/user.py",
            'A = "user@example.com"\nB = "someone@test.com"\nC = "noreply@company.com"',
        )
        self.assertFalse([item for item in scan(self.root) if item.rule_id == "PII-001"])

    def test_same_email_across_files_merges(self) -> None:
        write(self.root, "src/a.py", 'EMAIL = "bob.lee@gmail.com"')
        write(self.root, "src/b.py", 'owner = "bob.lee@gmail.com"')
        found = [item for item in scan(self.root) if item.rule_id == "PII-001"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].detail["count"], 2)

    def test_test_directory_is_skipped(self) -> None:
        """测试夹具里的假邮箱不再计入（只留真实数据信号）。"""
        write(self.root, "tests/test_user.py", 'EMAIL = "carol@gmail.com"')
        found = [item for item in scan(self.root) if item.rule_id == "PII-001"]
        self.assertEqual(found, [])


class PhoneTests(PiiTestCase):
    def test_international_singapore_number(self) -> None:
        set_jurisdictions(self.root, ALL)
        write(self.root, "src/sms.py", 'PHONE = "+65 9123 4567"')
        found = [item for item in scan(self.root) if item.rule_id == "PII-002"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].detail["jurisdiction"], "sg-pdpa")
        self.assertIn("4567", found[0].evidence)
        self.assertNotIn("9123", found[0].evidence)

    def test_random_number_is_not_a_phone(self) -> None:
        set_jurisdictions(self.root, ALL)
        write(self.root, "src/const.py", "TIMEOUT_MS = 10000\nMAX_RETRY = 12345678")
        self.assertFalse([item for item in scan(self.root) if item.rule_id == "PII-002"])


class GovernmentIdTests(PiiTestCase):
    def test_singapore_nric_with_valid_checksum(self) -> None:
        set_jurisdictions(self.root, ALL)
        write(self.root, "src/form.py", 'NRIC = "S1234567D"')
        found = [item for item in scan(self.root) if item.rule_id == "PII-003"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].detail["jurisdiction"], "sg-pdpa")
        self.assertEqual(found[0].severity, "high")

    def test_singapore_nric_with_bad_checksum_is_ignored(self) -> None:
        set_jurisdictions(self.root, ALL)
        write(self.root, "src/form.py", 'NRIC = "S1234567A"')
        self.assertFalse([item for item in scan(self.root) if item.rule_id == "PII-003"])

    def test_thailand_id(self) -> None:
        set_jurisdictions(self.root, ALL)
        value = th_id("110170020345")
        write(self.root, "src/form.py", f'ID = "{value}"')
        found = [item for item in scan(self.root) if item.rule_id == "PII-003"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].detail["jurisdiction"], "th-pdpa")

    def test_indonesia_nik(self) -> None:
        set_jurisdictions(self.root, ALL)
        write(self.root, "src/form.py", 'NIK = "3171011509900001"')
        found = [item for item in scan(self.root) if item.rule_id == "PII-003"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].detail["jurisdiction"], "id-pdp")

    def test_malaysia_mykad(self) -> None:
        set_jurisdictions(self.root, ALL)
        write(self.root, "src/form.py", 'IC = "900115145678"')
        found = [item for item in scan(self.root) if item.rule_id == "PII-003"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].detail["jurisdiction"], "my-pdpa")

    def test_jurisdiction_gates_identifier_rules(self) -> None:
        set_jurisdictions(self.root, ["ph-dpa"])
        write(self.root, "src/form.py", 'NRIC = "S1234567D"')
        self.assertFalse([item for item in scan(self.root) if item.rule_id == "PII-003"])


class CardTests(PiiTestCase):
    def test_valid_card_number_is_high(self) -> None:
        write(self.root, "src/pay.py", 'CARD = "4532015112830366"')
        found = [item for item in scan(self.root) if item.rule_id == "PII-004"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "high")
        self.assertIn("0366", found[0].evidence)
        self.assertNotIn("4532015", found[0].evidence)

    def test_official_test_card_is_downgraded(self) -> None:
        write(self.root, "src/pay.py", 'CARD = "4242 4242 4242 4242"')
        found = [item for item in scan(self.root) if item.rule_id == "PII-004"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "low")
        self.assertTrue(found[0].detail["test_card"])

    def test_non_luhn_digits_are_ignored(self) -> None:
        write(self.root, "src/pay.py", 'ORDER = "4532015112830367"')
        self.assertFalse([item for item in scan(self.root) if item.rule_id == "PII-004"])

    def test_card_is_not_misread_as_national_id(self) -> None:
        set_jurisdictions(self.root, ALL)
        write(self.root, "src/pay.py", 'CARD = "4532015112830366"')
        found = scan(self.root)
        self.assertFalse([item for item in found if item.rule_id == "PII-003"])
        self.assertEqual(len([item for item in found if item.rule_id == "PII-004"]), 1)


class LogAndSnapshotTests(PiiTestCase):
    def test_log_with_pii_interpolation(self) -> None:
        write(self.root, "src/notify.py", 'print(f"notify {CUSTOMER_EMAIL}")\n')
        found = [item for item in scan(self.root) if item.rule_id == "PII-006"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].severity, "high")

    def test_log_without_pii_is_ignored(self) -> None:
        write(self.root, "src/notify.py", 'print(f"notify {USER_ID}")\n')
        self.assertFalse([item for item in scan(self.root) if item.rule_id == "PII-006"])

    def test_email_snapshot(self) -> None:
        rows = "\n".join(f'{{"email": "user{index}@gmail.com"}}' for index in range(25))
        write(self.root, "data/users.json", rows)
        found = [item for item in scan(self.root) if item.rule_id == "PII-005"]
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].detail["email_count"], 25)


class InvariantTests(PiiTestCase):
    def test_report_never_contains_raw_values(self) -> None:
        set_jurisdictions(self.root, ALL)
        write(self.root, "src/user.py", 'EMAIL = "alice.tan@gmail.com"\nNRIC = "S1234567D"')
        result = run_scan(self.root, load_config(self.root), offline=True, only=["pii"])
        payload = json.dumps(result.to_dict(), ensure_ascii=False)
        self.assertNotIn("alice.tan@gmail.com", payload)
        self.assertNotIn("S1234567D", payload)
        self.assertNotIn("alice.tan", payload)

    def test_disabled_scanner_returns_nothing(self) -> None:
        write(self.root, ".provemark.toml", "[pii]\nenabled = false")
        write(self.root, "src/user.py", 'EMAIL = "alice.tan@gmail.com"')
        self.assertFalse(scan(self.root))

    def test_scanner_is_registered(self) -> None:
        from provemark.engine import SCANNER_MAP

        self.assertIn("pii", SCANNER_MAP)


if __name__ == "__main__":
    unittest.main()
