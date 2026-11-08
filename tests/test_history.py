"""Progress history: record shape, dedupe, rotation, lifecycle, cross-project roll-up."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from provemark import history
from provemark.models import Finding, ScanResult, ScanStats, Score


def make_result(root: str, findings: list[Finding], *, score: int = 90, grade: str = "A") -> ScanResult:
    result = ScanResult(root=root)
    result.findings = findings
    result.score = Score(
        total=score,
        grade=grade,
        counts={name: 0 for name in ("critical", "high", "medium", "low", "info")},
    )
    result.stats = ScanStats(files_scanned=12, packages_total=3, duration_s=1.5)
    return result


def finding(rule: str, severity: str, path: str = "app.py", evidence: str = "") -> Finding:
    return Finding(
        rule_id=rule,
        category="security",
        severity=severity,
        title=f"{rule} title",
        message="m",
        path=path,
        evidence=evidence,
    )


class RecordTests(unittest.TestCase):
    def test_record_carries_metadata_only(self) -> None:
        secret_text = "AKIAIOSFODNN7EXAMPLE"
        result = make_result("/repo", [finding("SEC-001", "high", "config.py", secret_text)])
        record = history.record_from_scan(result, source="cli", mode="online")
        self.assertEqual(record["root"], "/repo")
        self.assertEqual(record["score"], 90)
        self.assertEqual(record["source"], "cli")
        self.assertEqual(record["files"], 12)
        entry = record["findings"][0]
        self.assertEqual(entry["r"], "SEC-001")
        self.assertEqual(entry["s"], "high")
        self.assertEqual(entry["p"], "config.py")
        self.assertTrue(entry["f"])
        # The evidence text (here a fake key) must never be stored.
        self.assertNotIn(secret_text, json.dumps(record))


class StorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "history.jsonl"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def append(self, *, root="/repo", score=90, severity="high", ts="2026-01-01T00:00:00Z", **kwargs):
        result = make_result(root, [finding("SEC-001", severity)] if severity else [], score=score)
        record = history.record_from_scan(result, **kwargs)
        record["ts"] = ts
        return history.append_record(record, path=self.path)

    def test_append_and_load_round_trip(self) -> None:
        self.assertIsNotNone(self.append(ts="2026-01-01T00:00:00Z"))
        records = history.load_history(self.path)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["root"], "/repo")

    def test_identical_rescan_is_collapsed(self) -> None:
        self.append(ts="2026-01-01T00:00:00Z")
        self.assertIsNone(self.append(ts="2026-01-01T00:20:00Z"))
        self.assertEqual(len(history.load_history(self.path)), 1)

    def test_identical_rescan_after_the_window_is_kept(self) -> None:
        self.append(ts="2026-01-01T00:00:00Z")
        appended = self.append(ts="2026-01-01T02:00:00Z")
        self.assertIsNotNone(appended)
        self.assertEqual(len(history.load_history(self.path)), 2)

    def test_a_changed_score_is_always_kept(self) -> None:
        self.append(score=80, ts="2026-01-01T00:00:00Z")
        self.assertIsNotNone(self.append(score=90, ts="2026-01-01T00:01:00Z"))
        self.assertEqual(len(history.load_history(self.path)), 2)

    def test_rotation_keeps_the_newest_per_root(self) -> None:
        for index in range(8):
            result = make_result("/repo", [finding("SEC-001", "high")], score=90 + index)
            record = history.record_from_scan(result)
            record["ts"] = f"2026-01-0{index + 1}T00:00:00Z"
            history.append_record(record, path=self.path, max_per_root=3)
        records = history.load_history(self.path)
        self.assertEqual(len(records), 3)
        self.assertEqual(records[-1]["score"], 97)

    def test_torn_line_does_not_sink_the_ledger(self) -> None:
        self.append(ts="2026-01-01T00:00:00Z")
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write('{"root": "/broken", "ts": ')
        records = history.load_history(self.path)
        self.assertEqual(len(records), 1)


class LifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "history.jsonl"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def record(self, ts: str, findings: list[Finding], score: int) -> None:
        result = make_result("/repo", findings, score=score)
        entry = history.record_from_scan(result)
        entry["ts"] = ts
        history.append_record(entry, path=self.path, dedupe_seconds=0)

    def test_fixed_and_reopened_are_tracked(self) -> None:
        a = finding("SEC-001", "high")
        b = finding("AI-005", "medium")
        self.record("2026-01-01T00:00:00Z", [a, b], 80)
        self.record("2026-01-02T00:00:00Z", [b], 90)  # a fixed
        progress = history.project_progress(history.load_history(self.path))
        self.assertEqual([entry["rule"] for entry in progress["open"]], ["AI-005"])
        self.assertEqual([entry["rule"] for entry in progress["fixed"]], ["SEC-001"])
        self.assertEqual(progress["delta_score"], 10)

        self.record("2026-01-03T00:00:00Z", [a, b], 85)  # a came back
        progress = history.project_progress(history.load_history(self.path))
        self.assertEqual({entry["rule"] for entry in progress["open"]}, {"SEC-001", "AI-005"})
        self.assertEqual({entry["rule"] for entry in progress["reopened"]}, {"SEC-001"})
        self.assertEqual(progress["reopened_count"], 1)

    def test_open_list_is_sorted_by_severity(self) -> None:
        self.record(
            "2026-01-01T00:00:00Z",
            [finding("LOW-1", "low"), finding("CRIT-1", "critical"), finding("MED-1", "medium")],
            50,
        )
        progress = history.project_progress(history.load_history(self.path))
        self.assertEqual([entry["severity"] for entry in progress["open"]], ["critical", "medium", "low"])

    def test_series_and_recent_windows(self) -> None:
        now = datetime.now(timezone.utc)
        old = (now - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        recent = (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.record(old, [finding("A-1", "high")], 70)
        self.record(recent, [finding("A-1", "high"), finding("B-1", "low")], 72)
        progress = history.project_progress(history.load_history(self.path), now=now)
        self.assertEqual(len(progress["series"]), 2)
        self.assertEqual(len(progress["new_recent"]), 1)


class ReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "history.jsonl"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def record(self, root: str, ts: str, findings: list[Finding], score: int) -> None:
        entry = history.record_from_scan(make_result(root, findings, score=score))
        entry["ts"] = ts
        history.append_record(entry, path=self.path, dedupe_seconds=0)

    def test_cross_project_report_aggregates(self) -> None:
        self.record("/a", "2026-01-01T00:00:00Z", [finding("X-1", "high")], 60)
        self.record("/b", "2026-01-02T00:00:00Z", [finding("Y-1", "low")], 95)
        report = history.build_report(history.load_history(self.path), path=self.path)
        self.assertEqual(report["totals"]["projects"], 2)
        self.assertEqual(report["totals"]["open"], 2)
        self.assertEqual(report["history_path"], str(self.path))
        self.assertEqual([project["root"] for project in report["projects"]], ["/b", "/a"])

    def test_days_filter_keeps_last_event_when_outside_window(self) -> None:
        now = datetime.now(timezone.utc)
        old = (now - timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.record("/a", old, [finding("X-1", "high")], 60)
        report = history.build_report(history.load_history(self.path), days=7, now=now, path=self.path)
        self.assertEqual(report["totals"]["projects"], 1)
        self.assertEqual(len(report["projects"][0]["series"]), 1)


if __name__ == "__main__":
    unittest.main()
