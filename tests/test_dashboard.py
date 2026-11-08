"""Dashboard rendering: structure, escaping, and the no-external-assets promise."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from provemark.history import build_report, project_progress
from provemark.report.dashboard import render_dashboard


def event(root: str, ts: str, score: int, counts: dict[str, int], findings: list[dict]) -> dict:
    base = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    base.update(counts)
    return {
        "v": 1,
        "ts": ts,
        "root": root,
        "score": score,
        "grade": "A" if score >= 90 else "B",
        "counts": base,
        "files": 10,
        "packages": 2,
        "reliable": True,
        "source": "cli",
        "findings": findings,
    }


def fp(name: str, rule: str, severity: str, path: str = "src/app.py") -> dict:
    return {"f": name, "r": rule, "s": severity, "p": path}


class DashboardTests(unittest.TestCase):
    def report(self, records: list[dict]) -> dict:
        return build_report(records, path="C:/history.jsonl")

    def test_empty_report_renders_guidance(self) -> None:
        document = render_dashboard(self.report([]))
        self.assertIn("<!doctype html>", document)
        self.assertIn("历史库还是空的", document)

    def test_cross_project_overview_lists_every_project(self) -> None:
        records = [
            event("/repo/a", "2026-01-01T00:00:00Z", 80, {"high": 1}, [fp("a1", "SEC-001", "high")]),
            event("/repo/a", "2026-01-02T00:00:00Z", 90, {}, []),
            event("/repo/b", "2026-01-02T00:00:00Z", 70, {"critical": 2}, [fp("b1", "VUL-001", "critical")]),
        ]
        document = render_dashboard(self.report(records))
        self.assertIn("/repo/a", document)
        self.assertIn("/repo/b", document)
        self.assertIn("跨项目总览", document)
        self.assertIn("分数时间线", document)
        self.assertIn("<svg", document)
        self.assertIn("未修复问题", document)

    def test_untrusted_text_is_escaped(self) -> None:
        nasty = '<script>alert("x")</script>'
        records = [
            event(nasty, "2026-01-01T00:00:00Z", 50, {"high": 1}, [fp("x1", "SEC-001", "high", nasty)]),
        ]
        document = render_dashboard(self.report(records))
        self.assertNotIn("<script>alert", document)
        self.assertIn("&lt;script&gt;", document)

    def test_no_external_assets_or_scripts(self) -> None:
        records = [
            event("/repo/a", "2026-01-01T00:00:00Z", 88, {"medium": 1}, [fp("a1", "AI-005", "medium")]),
        ]
        document = render_dashboard(self.report(records))
        self.assertNotIn("http://", document)
        self.assertNotIn("https://", document)
        self.assertNotIn("<script", document)
        self.assertNotIn("@import", document)
        self.assertIn("<style>", document)

    def test_lifecycle_survives_progress_to_dashboard(self) -> None:
        now = datetime.now(timezone.utc)
        day1 = (now - timedelta(days=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        day2 = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        records = [
            event("/repo/a", day1, 70, {"high": 2}, [fp("h1", "SEC-001", "high"), fp("h2", "SEC-002", "high")]),
            event("/repo/a", day2, 85, {"high": 1}, [fp("h2", "SEC-002", "high")]),
        ]
        progress = project_progress(records, now=now)
        self.assertEqual(progress["fixed_count"], 1)
        self.assertEqual(progress["open_count"], 1)
        document = render_dashboard(self.report(records))
        for expected in ("SEC-002", "较首次", "近 7 天"):
            self.assertIn(expected, document)


if __name__ == "__main__":
    unittest.main()
