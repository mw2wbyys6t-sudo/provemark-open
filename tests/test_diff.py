import contextlib
import io
import json
import re
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from provemark import diff
from provemark.cli import main


def run_cli(argv):
    """跑 CLI 但不把它的输出混进测试报告。"""
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer), contextlib.redirect_stderr(io.StringIO()):
        code = main(argv)
    return code, buffer.getvalue()


def finding(rule, severity, path="src/app.py", line=10, title="", **extra):
    item = {
        "rule_id": rule,
        "severity": severity,
        "title": title or f"{rule} 标题",
        "message": "",
        "path": path,
        "line": line,
        "remediation": "修好它",
        "fingerprint": extra.pop("fingerprint", f"{rule}:{path}:{line}"),
    }
    item.update(extra)
    return item


def report(findings, score=80, grade="B"):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for item in findings:
        counts[item["severity"]] += 1
    return {
        "tool": "provemark",
        "score": {"total": score, "grade": grade, "counts": counts},
        "findings": findings,
    }


class CompareTests(unittest.TestCase):
    def test_new_and_fixed_are_classified_by_fingerprint(self) -> None:
        base = report([finding("SEC-001", "critical", line=1), finding("HYG-001", "high", line=0)])
        head = report([finding("HYG-001", "high", line=0), finding("VUL-001", "high", line=42)])
        result = diff.compare(base, head)
        self.assertEqual([item["rule_id"] for item in result.added], ["VUL-001"])
        self.assertEqual([item["rule_id"] for item in result.fixed], ["SEC-001"])
        self.assertEqual(result.unchanged, 1)

    def test_moved_finding_counts_as_fixed_plus_added(self) -> None:
        """指纹包含行号：挪了位置就是「旧的一条没了、新的一条来了」。"""
        base = report([finding("VUL-001", "high", line=10)])
        head = report([finding("VUL-001", "high", line=55)])
        result = diff.compare(base, head)
        self.assertEqual(len(result.added), 1)
        self.assertEqual(len(result.fixed), 1)

    def test_missing_fingerprint_falls_back_to_location(self) -> None:
        base = report([finding("AI-001", "medium", fingerprint="")])
        head = report([finding("AI-001", "medium", fingerprint="")])
        result = diff.compare(base, head)
        self.assertEqual(result.added, [])
        self.assertEqual(result.unchanged, 1)

    def test_score_delta_and_regression_flag(self) -> None:
        worse = diff.compare(report([], score=90, grade="A"), report([finding("SEC-003", "critical")], score=40, grade="F"))
        self.assertEqual(worse.score_delta, -50)
        self.assertTrue(worse.regressed, "新增致命问题必须算退步")

        better = diff.compare(report([finding("SEC-003", "critical")], score=40, grade="F"), report([], score=90, grade="A"))
        self.assertEqual(better.score_delta, 50)
        self.assertFalse(better.regressed)

    def test_counts_survive_a_report_without_score_block(self) -> None:
        bare = {"findings": [finding("AI-001", "medium"), finding("AI-002", "info")]}
        result = diff.compare(bare, report([], score=100, grade="A"))
        self.assertEqual(result.base_counts["medium"], 1)
        self.assertEqual(result.base_counts["info"], 1)
        self.assertIsNone(result.base_score)


class RenderTests(unittest.TestCase):
    def test_markdown_starts_with_the_marker_so_the_comment_can_be_updated(self) -> None:
        result = diff.compare(report([]), report([]))
        text = diff.render_markdown(result)
        self.assertTrue(text.startswith(diff.MARKDOWN_MARKER))

    def test_markdown_escapes_pipes_and_collapses_newlines(self) -> None:
        nasty = finding("VUL-001", "high", title="a | b\n第二行")
        result = diff.compare(report([]), report([nasty]))
        text = diff.render_markdown(result)
        self.assertIn("a \\| b 第二行", text)
        row = [line for line in text.splitlines() if "VUL-001" in line][0]
        cells = re.split(r"(?<!\\)\|", row.strip())[1:-1]
        self.assertEqual(len(cells), 4, "标题里的竖线不能把表格撑歪")

    def test_markdown_limits_rows_and_says_how_many_are_left(self) -> None:
        many = [finding("AI-005", "high", line=index) for index in range(1, 12)]
        result = diff.compare(report([]), report(many))
        text = diff.render_markdown(result, max_items=3)
        self.assertEqual(text.count("| `AI-005`"), 3)
        self.assertIn("还有 8 条未列出", text)

    def test_repository_level_finding_has_no_line_suffix(self) -> None:
        repo_level = finding("HYG-001", "high", path="", line=0)
        result = diff.compare(report([]), report([repo_level]))
        text = diff.render_markdown(result)
        self.assertIn("仓库级", text)
        self.assertNotIn(":0", text)

    def test_text_and_json_render(self) -> None:
        result = diff.compare(report([finding("SEC-003", "critical")], score=40, grade="F"), report([], score=90, grade="A"))
        self.assertIn("+50", diff.render_text(result))
        payload = json.loads(diff.render(result, "json"))
        self.assertEqual(payload["score_delta"], 50)
        self.assertTrue(payload["fixed"])


class CliTests(unittest.TestCase):
    def _write(self, root: Path, name: str, payload: dict) -> Path:
        path = root / name
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return path

    def test_diff_writes_markdown(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = self._write(root, "base.json", report([finding("SEC-003", "critical")], score=40, grade="F"))
            head = self._write(root, "head.json", report([], score=90, grade="A"))
            out = root / "comment.md"
            code, _ = run_cli(["diff", str(base), str(head), "-o", str(out), "--label-base", "main", "--label-head", "PR"])
            self.assertEqual(code, 0)
            body = out.read_text(encoding="utf-8")
            self.assertTrue(body.startswith(diff.MARKDOWN_MARKER))
            self.assertIn("main", body)
            self.assertIn("PR", body)

    def test_missing_report_is_an_error_not_a_crash(self) -> None:
        with TemporaryDirectory() as tmp:
            head = self._write(Path(tmp), "head.json", report([]))
            code, _ = run_cli(["diff", str(Path(tmp) / "nope.json"), str(head)])
            self.assertEqual(code, 2)

    def test_not_a_provemark_report_is_rejected(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            bad = root / "bad.json"
            bad.write_text('{"hello": "world"}', encoding="utf-8")
            good = self._write(root, "head.json", report([]))
            self.assertEqual(run_cli(["diff", str(bad), str(good)])[0], 2)

    def test_fail_on_regression_exits_one(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            base = self._write(root, "base.json", report([], score=95, grade="A"))
            head = self._write(root, "head.json", report([finding("SEC-003", "critical")], score=50, grade="F"))
            self.assertEqual(run_cli(["diff", str(base), str(head), "--fail-on-regression"])[0], 1)
            self.assertEqual(run_cli(["diff", str(base), str(head)])[0], 0)


if __name__ == "__main__":
    unittest.main()
