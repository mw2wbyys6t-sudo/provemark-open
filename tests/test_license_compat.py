from __future__ import annotations

import unittest

from provemark.rules import license_compat as compat


class MatrixTests(unittest.TestCase):
    def assert_verdict(self, project: str, dependency: str, expected: str) -> None:
        verdict, reason = compat.verdict(project, dependency)
        self.assertEqual(verdict, expected, f"{project} × {dependency}：{reason}")

    def test_spec_cases(self) -> None:
        self.assert_verdict("MIT", "GPL-3.0-only", compat.INCOMPATIBLE)
        self.assert_verdict("Apache-2.0", "GPL-2.0-only", compat.INCOMPATIBLE)
        self.assert_verdict("MIT", "MIT", compat.OK)

    def test_copyleft_versions(self) -> None:
        self.assert_verdict("GPL-2.0-only", "GPL-3.0-only", compat.INCOMPATIBLE)
        self.assert_verdict("GPL-2.0-or-later", "GPL-3.0-only", compat.OK)
        self.assert_verdict("LGPL-3.0-only", "GPL-2.0-only", compat.INCOMPATIBLE)
        self.assert_verdict("GPL-3.0-only", "MPL-2.0", compat.OK)
        self.assert_verdict("GPL-3.0-only", "EPL-2.0", compat.INCOMPATIBLE)

    def test_weak_copyleft_is_conditional(self) -> None:
        self.assert_verdict("MIT", "MPL-2.0", compat.CONDITIONAL)
        self.assert_verdict("MIT", "LGPL-2.1-only", compat.CONDITIONAL)
        self.assert_verdict("GPL-2.0-only", "MPL-2.0", compat.CONDITIONAL)

    def test_expression_handling(self) -> None:
        self.assert_verdict("MIT", "MIT OR GPL-3.0-only", compat.OK)
        self.assert_verdict("MIT", "MIT AND GPL-3.0-only", compat.INCOMPATIBLE)

    def test_unknown_licenses(self) -> None:
        self.assert_verdict("MIT", "Custom-Proprietary", compat.UNKNOWN)
        self.assert_verdict("Custom-Proprietary", "MIT", compat.UNKNOWN)
        self.assert_verdict("MIT", "", compat.UNKNOWN)

    def test_apache_into_gpl2_explains_patent_clause(self) -> None:
        verdict, reason = compat.verdict("GPL-2.0-only", "Apache-2.0")
        self.assertEqual(verdict, compat.INCOMPATIBLE)
        self.assertIn("专利", reason)

    def test_classes_cover_variants(self) -> None:
        self.assertEqual(compat.compat_class("GPL-3.0"), "gpl3")
        self.assertEqual(compat.compat_class("GPL-3.0-or-later"), "gpl3")
        self.assertEqual(compat.compat_class("LGPL-2.1-or-later"), "lgpl2")
        self.assertEqual(compat.compat_class(""), "unknown")


if __name__ == "__main__":
    unittest.main()
