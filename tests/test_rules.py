from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from provemark.config import LicensePolicy, load_config
from provemark.models import Finding
from provemark.rules import license_data, secrets
from provemark.rules.catalog import catalog
from provemark.scanners import supply
from provemark.score import compute


class SecretRuleTests(unittest.TestCase):
    def test_masks_keep_only_edges(self) -> None:
        masked = secrets.mask("sk-abcdefghijklmnopqrstuvwxyz")
        self.assertTrue(masked.startswith("sk-a"))
        self.assertIn("****", masked)
        self.assertNotIn("ghijklmn", masked)

    def test_placeholder_detection(self) -> None:
        self.assertTrue(secrets.looks_placeholder("your-api-key-here"))
        self.assertTrue(secrets.looks_placeholder("sk-xxxxxxxxxxxxxxxx"))
        self.assertFalse(secrets.looks_placeholder("sk-proj-Q7mZ2pLx9TvR4sKd8WnB3yHf6"))

    def test_entropy_separates_random_from_words(self) -> None:
        self.assertGreater(secrets.shannon_entropy("a8Fk3LmQ9zXc2VbN7pRw"), 3.5)
        self.assertLess(secrets.shannon_entropy("passwordpassword"), 3.5)


class LicenseRuleTests(unittest.TestCase):
    def test_detects_apache_from_text(self) -> None:
        text = "Apache License\nVersion 2.0, January 2004\nhttp://www.apache.org/licenses/"
        self.assertEqual(license_data.detect_from_text(text), "Apache-2.0")

    def test_detects_mit_from_text(self) -> None:
        text = "MIT License\n\nPermission is hereby granted, free of charge, to any person"
        self.assertEqual(license_data.detect_from_text(text), "MIT")

    def test_or_expression_picks_allowed_option(self) -> None:
        policy = LicensePolicy()
        status, effective = license_data.evaluate("Apache-2.0 OR GPL-3.0-only", policy)
        self.assertEqual(status, "allow")
        self.assertEqual(effective, ["Apache-2.0"])

    def test_and_expression_uses_most_restrictive(self) -> None:
        policy = LicensePolicy()
        status, _ = license_data.evaluate("MIT AND GPL-3.0-only", policy)
        self.assertEqual(status, "deny")

    def test_unknown_license(self) -> None:
        policy = LicensePolicy()
        status, _ = license_data.evaluate("", policy)
        self.assertEqual(status, "unknown")

    def test_alias_normalization(self) -> None:
        self.assertEqual(license_data.normalize_spdx("Apache 2.0"), "Apache-2.0")
        self.assertEqual(license_data.normalize_spdx("MIT License"), "MIT")


class SupplyTests(unittest.TestCase):
    def test_levenshtein(self) -> None:
        self.assertEqual(supply.levenshtein("lodash", "lodash"), 0)
        self.assertEqual(supply.levenshtein("lodahs", "lodash"), 2)
        self.assertEqual(supply.levenshtein("", "abc"), 3)


class ScoreTests(unittest.TestCase):
    def _finding(self, severity: str, category: str = "ai", confidence: float = 1.0) -> Finding:
        return Finding(
            rule_id="T-001",
            category=category,
            severity=severity,
            title="t",
            message="m",
            confidence=confidence,
        )

    def test_clean_repo_scores_full(self) -> None:
        score = compute([])
        self.assertEqual(score.total, 100)
        self.assertEqual(score.grade, "A")

    def test_single_high_deducts(self) -> None:
        score = compute([self._finding("high")])
        self.assertEqual(score.total, 92)
        self.assertEqual(score.grade, "A")

    def test_medium_flood_is_capped(self) -> None:
        findings = [self._finding("medium") for _ in range(200)]
        score = compute(findings)
        self.assertGreaterEqual(score.total, 70)

    def test_critical_is_not_capped(self) -> None:
        findings = [self._finding("critical", "secrets")]
        score = compute(findings)
        self.assertLessEqual(score.total, 65)
        self.assertEqual(score.grade, "D")

    def test_more_findings_lower_score(self) -> None:
        few = compute([self._finding("medium") for _ in range(1)])
        many = compute([self._finding("medium") for _ in range(6)])
        self.assertGreater(few.total, many.total)

    def test_low_confidence_deducts_less(self) -> None:
        sure = compute([self._finding("high")])
        unsure = compute([self._finding("high", confidence=0.5)])
        self.assertGreater(unsure.total, sure.total)
        self.assertAlmostEqual(
            unsure.deductions["ai"] / sure.deductions["ai"], 0.3, places=2
        )

    def test_zero_confidence_costs_nothing(self) -> None:
        score = compute([self._finding("high", confidence=0.0)])
        self.assertEqual(score.total, 100)
        self.assertEqual(score.counts["high"], 1)

    def test_confidence_does_not_change_reported_counts(self) -> None:
        findings = [self._finding("high", confidence=0.4) for _ in range(3)]
        score = compute(findings)
        self.assertEqual(score.counts["high"], 3)

    def test_low_confidence_flood_scores_higher(self) -> None:
        sure = compute([self._finding("medium", confidence=1.0) for _ in range(4)])
        unsure = compute([self._finding("medium", confidence=0.3) for _ in range(4)])
        self.assertGreater(unsure.total, sure.total)

    def test_confidence_still_capped(self) -> None:
        findings = [self._finding("medium", confidence=1.0) for _ in range(300)]
        score = compute(findings)
        self.assertGreaterEqual(score.total, 70)


class ConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_reads_policy_file(self) -> None:
        (self.root / ".provemark.toml").write_text(
            """
[project]
kind = "app"
license = "MIT"

[gate]
fail_on = "critical"

[license]
deny = ["GPL-3.0-only"]

[[ignore]]
rule = "SCP-007"
reason = "上游模板暂不固定 SHA"
expires = "2099-01-01"
""",
            encoding="utf-8",
        )
        config = load_config(self.root)
        self.assertEqual(config.project_kind, "app")
        self.assertEqual(config.fail_on, "critical")
        self.assertEqual(config.license_policy.deny, ["GPL-3.0-only"])
        self.assertEqual(len(config.ignore), 1)
        self.assertFalse(config.ignore[0].is_expired())

    def test_ignore_requires_reason(self) -> None:
        (self.root / ".provemark.toml").write_text(
            '[[ignore]]\nrule = "SCP-007"\n', encoding="utf-8"
        )
        with self.assertRaises(Exception):
            load_config(self.root)

    def test_expired_ignore_is_detected(self) -> None:
        (self.root / ".provemark.toml").write_text(
            '[[ignore]]\nrule = "SCP-007"\nreason = "临时"\nexpires = "2020-01-01"\n',
            encoding="utf-8",
        )
        config = load_config(self.root)
        self.assertTrue(config.ignore[0].is_expired())

    def test_exclude_patterns(self) -> None:
        config = load_config(self.root)
        self.assertTrue(config.is_excluded("node_modules/react/index.js"))
        self.assertTrue(config.is_excluded(".git/config"))
        self.assertFalse(config.is_excluded("src/app.py"))


class CatalogTests(unittest.TestCase):
    def test_every_rule_has_explanation(self) -> None:
        entries = catalog()
        for rule_id in ("AI-012", "DEP-001", "LIC-004", "LIC-009", "HYG-006", "SCP-004", "SEC-001"):
            self.assertIn(rule_id, entries)
            self.assertTrue(entries[rule_id].get("remediation"))


if __name__ == "__main__":
    unittest.main()
