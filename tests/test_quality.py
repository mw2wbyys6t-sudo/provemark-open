from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from provemark.config import load_config
from provemark.engine import run_scan

CASE_ROOT = Path(__file__).resolve().parent / "quality" / "cases"
PRECISION_FLOOR = 0.85
RECALL_FLOOR = 0.90


def seed_license_cache(cache_dir: Path, mapping: dict[str, str]) -> None:
    """为离线用例预置许可证缓存，避免质量评测依赖网络。"""
    entries: dict[str, dict] = {}
    for key, value in mapping.items():
        entry = {"ts": time.time(), "value": value}
        entries[f"lic:depsdev:{key}"] = entry
        entries[f"lic:registry:{key}"] = entry
    cache_dir.mkdir(parents=True, exist_ok=True)
    (cache_dir / "cache.json").write_text(json.dumps(entries), encoding="utf-8")


def case_names() -> list[str]:
    selected = os.environ.get("QUALITY_CASE", "").strip()
    if selected:
        return [selected]
    if not CASE_ROOT.is_dir():
        return []
    return sorted(path.name for path in CASE_ROOT.iterdir() if path.is_dir())


def load_case(name: str) -> dict:
    return json.loads((CASE_ROOT / name / "case.json").read_text(encoding="utf-8"))


def evaluate(name: str) -> dict:
    meta = load_case(name)
    root = CASE_ROOT / name
    licenses = {str(key): str(value) for key, value in (meta.get("licenses") or {}).items()}
    with tempfile.TemporaryDirectory() as cache_dir:
        os.environ["PROVEMARK_CACHE_DIR"] = cache_dir
        if licenses:
            seed_license_cache(Path(cache_dir), licenses)
        try:
            result = run_scan(root, load_config(root), offline=True)
        finally:
            os.environ.pop("PROVEMARK_CACHE_DIR", None)
    scope = {str(item) for item in meta.get("scope", [])}
    found = {finding.rule_id for finding in result.findings if not scope or finding.rule_id in scope}
    expected = {str(item) for item in meta.get("expect", [])}
    forbidden = {str(item) for item in meta.get("forbid", [])}
    limits = {str(key): int(value) for key, value in (meta.get("max_findings") or {}).items()}
    counts = {
        rule_id: sum(1 for finding in result.findings if finding.rule_id == rule_id)
        for rule_id in limits
    }
    over_limit = {
        rule_id: counts[rule_id] for rule_id, limit in limits.items() if counts[rule_id] > limit
    }
    true_positive = found & expected
    false_negative = expected - found
    false_positive = (found - expected) | (found & forbidden)
    return {
        "name": name,
        "risk": meta.get("risk", ""),
        "found": sorted(found),
        "expected": sorted(expected),
        "forbidden": sorted(forbidden),
        "tp": len(true_positive),
        "fn": len(false_negative),
        "fp": len(false_positive),
        "missed": sorted(false_negative),
        "spurious": sorted(false_positive),
        "limits": limits,
        "counts": counts,
        "over_limit": over_limit,
    }


class DetectionQualityTests(unittest.TestCase):
    def test_cases_exist(self) -> None:
        self.assertTrue(case_names(), f"没有找到评测用例：{CASE_ROOT}")

    def test_each_case_matches_expectation(self) -> None:
        for name in case_names():
            with self.subTest(case=name):
                row = evaluate(name)
                self.assertFalse(
                    row["missed"],
                    f"{name} 漏报 {row['missed']}（应命中 {row['expected']}，实际 {row['found']}）",
                )
                self.assertFalse(
                    row["spurious"],
                    f"{name} 误报 {row['spurious']}（应命中 {row['expected']}，实际 {row['found']}）",
                )
                self.assertFalse(
                    row["over_limit"],
                    f"{name} 超出条数上限 {row['over_limit']}（全部计数 {row['counts']}）",
                )

    @unittest.skipIf(os.environ.get("QUALITY_CASE"), "单用例模式跳过汇总指标")
    def test_precision_and_recall_floors(self) -> None:
        rows = [evaluate(name) for name in case_names()]
        tp = sum(row["tp"] for row in rows)
        fp = sum(row["fp"] for row in rows)
        fn = sum(row["fn"] for row in rows)
        precision = tp / (tp + fp) if tp + fp else 1.0
        recall = tp / (tp + fn) if tp + fn else 1.0
        summary = "\n".join(
            f"  {row['name']}: found={row['found']} expected={row['expected']}" for row in rows
        )
        self.assertGreaterEqual(precision, PRECISION_FLOOR, f"precision={precision:.2f}\n{summary}")
        self.assertGreaterEqual(recall, RECALL_FLOOR, f"recall={recall:.2f}\n{summary}")


if __name__ == "__main__":
    unittest.main()
