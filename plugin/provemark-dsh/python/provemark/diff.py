"""Compare two scan reports.

A single `provemark scan` answers "how bad is it now". A pull request needs a
different question answered: **what did this change do?** Two reports (base and
head) are compared by fingerprint, and the result is rendered as a comment a
reviewer can act on.

Only the JSON reports are read — nothing is scanned here, so this stays cheap
enough to run on every pull request.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
SEVERITY_LABEL = {
    "critical": "致命",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "提示",
}
# 评论要能被工作流「就地更新」，而不是每推一次就多一条。
MARKDOWN_MARKER = "<!-- provemark-diff -->"


class DiffError(Exception):
    """The input is not a usable scan report."""


def load_report(path: str | Path) -> dict[str, Any]:
    """Read one `provemark scan -f json` report."""
    file = Path(path)
    if not file.is_file():
        raise DiffError(f"找不到报告文件：{file}")
    try:
        data = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise DiffError(f"读不了 {file}：{exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise DiffError(f"{file} 不是 provemark 的 JSON 报告（缺少 findings）")
    return data


def _rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return len(SEVERITY_ORDER)


def _key(finding: dict[str, Any]) -> str:
    fingerprint = str(finding.get("fingerprint") or "").strip()
    if fingerprint:
        return fingerprint
    # 老报告可能没有 fingerprint：退化成「规则 + 位置 + 标题」，宁可多算一条变更，
    # 也不要把同一个问题因为缺指纹而当成「修好了」。
    return "|".join(
        str(finding.get(name, "")) for name in ("rule_id", "path", "line", "title")
    )


def _counts(report: dict[str, Any]) -> dict[str, int]:
    score = report.get("score")
    if isinstance(score, dict) and isinstance(score.get("counts"), dict):
        return {name: int(score["counts"].get(name, 0)) for name in SEVERITY_ORDER}
    counts = {name: 0 for name in SEVERITY_ORDER}
    for finding in report["findings"]:
        severity = str(finding.get("severity", "info"))
        counts[severity if severity in counts else "info"] += 1
    return counts


def _score(report: dict[str, Any]) -> int | None:
    score = report.get("score")
    if isinstance(score, dict):
        total = score.get("total")
        if isinstance(total, int):
            return total
    return None


def _grade(report: dict[str, Any]) -> str:
    score = report.get("score")
    if isinstance(score, dict):
        return str(score.get("grade") or "")
    return ""


def _sorted(findings: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        findings,
        key=lambda item: (_rank(str(item.get("severity", "info"))), str(item.get("path", "")), int(item.get("line") or 0)),
    )


@dataclass
class DiffResult:
    base_label: str
    head_label: str
    base_score: int | None
    head_score: int | None
    base_grade: str
    head_grade: str
    base_counts: dict[str, int]
    head_counts: dict[str, int]
    added: list[dict[str, Any]] = field(default_factory=list)
    fixed: list[dict[str, Any]] = field(default_factory=list)
    unchanged: int = 0

    @property
    def score_delta(self) -> int | None:
        if self.base_score is None or self.head_score is None:
            return None
        return self.head_score - self.base_score

    @property
    def regressed(self) -> bool:
        return any(
            str(item.get("severity")) in ("critical", "high") for item in self.added
        )


def compare(base: dict[str, Any], head: dict[str, Any], *, base_label: str = "base", head_label: str = "head") -> DiffResult:
    """Diff two reports by fingerprint."""
    base_map: dict[str, dict[str, Any]] = {}
    for finding in base["findings"]:
        base_map.setdefault(_key(finding), finding)
    head_map: dict[str, dict[str, Any]] = {}
    for finding in head["findings"]:
        head_map.setdefault(_key(finding), finding)

    added = [finding for key, finding in head_map.items() if key not in base_map]
    fixed = [finding for key, finding in base_map.items() if key not in head_map]
    unchanged = len(head_map) - len(added)

    return DiffResult(
        base_label=base_label,
        head_label=head_label,
        base_score=_score(base),
        head_score=_score(head),
        base_grade=_grade(base),
        head_grade=_grade(head),
        base_counts=_counts(base),
        head_counts=_counts(head),
        added=_sorted(added),
        fixed=_sorted(fixed),
        unchanged=max(unchanged, 0),
    )


def _severity_tally(counts: dict[str, int]) -> str:
    parts = [f"{SEVERITY_LABEL[name]} {counts[name]}" for name in SEVERITY_ORDER if counts.get(name)]
    return " · ".join(parts) if parts else "无"


def _score_text(score: int | None, grade: str) -> str:
    if score is None:
        return "—"
    return f"{score}/100 {grade}".strip()


def render_text(result: DiffResult) -> str:
    delta = result.score_delta
    if delta is None:
        head_line = f"分数 {_score_text(result.head_score, result.head_grade)}"
    else:
        sign = f"+{delta}" if delta > 0 else str(delta)
        head_line = f"分数 {_score_text(result.head_score, result.head_grade)}（{sign}）"
    lines = [
        f"Provemark 对比 · {result.base_label} → {result.head_label}",
        f"  {head_line}",
        f"  {result.base_label}：{_severity_tally(result.base_counts)}",
        f"  {result.head_label}：{_severity_tally(result.head_counts)}",
        f"  新增 {len(result.added)} · 修掉 {len(result.fixed)} · 未变 {result.unchanged}",
    ]
    if result.added:
        lines.append("")
        lines.append("新增：")
        for finding in result.added:
            lines.append(
                f"  [{finding.get('severity')}] {finding.get('rule_id')} "
                f"{finding.get('title', '')} {finding.get('path', '')}:{finding.get('line', 0)}"
            )
    if result.fixed:
        lines.append("")
        lines.append("修掉：")
        for finding in result.fixed:
            lines.append(
                f"  [{finding.get('severity')}] {finding.get('rule_id')} "
                f"{finding.get('title', '')} {finding.get('path', '')}:{finding.get('line', 0)}"
            )
    return "\n".join(lines)


def _cell(value: Any, limit: int = 120) -> str:
    text = " ".join(str(value).replace("|", "\\|").split())
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


def _location(finding: dict[str, Any]) -> str:
    path = str(finding.get("path") or "").strip()
    if not path:
        return "仓库级"
    line = finding.get("line") or 0
    try:
        number = int(line)
    except (TypeError, ValueError):
        number = 0
    return f"{path}:{number}" if number > 0 else path


def _finding_row(finding: dict[str, Any]) -> str:
    return (
        f"| `{_cell(finding.get('rule_id', ''), 20)}` "
        f"| {_cell(finding.get('title', ''), 60)} "
        f"| `{_cell(_location(finding), 80)}` "
        f"| {_cell(finding.get('remediation', ''), 160)} |"
    )


def render_markdown(result: DiffResult, *, max_items: int = 8) -> str:
    """A pull-request comment. Starts with MARKDOWN_MARKER so it can be updated in place."""
    delta = result.score_delta
    if delta is None:
        headline = f"分数 **{_score_text(result.head_score, result.head_grade)}**"
    elif delta > 0:
        headline = f"分数 **{_score_text(result.head_score, result.head_grade)}**（+{delta}）"
    elif delta < 0:
        headline = f"分数 **{_score_text(result.head_score, result.head_grade)}**（{delta}）"
    else:
        headline = f"分数 **{_score_text(result.head_score, result.head_grade)}**（持平）"

    lines = [
        MARKDOWN_MARKER,
        "## 🛡️ Provemark 对比",
        "",
        f"{headline} — `{result.base_label}` → `{result.head_label}`",
        "",
        "| 级别 | " + result.base_label + " | " + result.head_label + " | 变化 |",
        "| --- | :---: | :---: | :---: |",
    ]
    for name in SEVERITY_ORDER:
        before = result.base_counts.get(name, 0)
        after = result.head_counts.get(name, 0)
        change = after - before
        change_text = "—" if change == 0 else (f"+{change}" if change > 0 else str(change))
        lines.append(f"| {SEVERITY_LABEL[name]} | {before} | {after} | {change_text} |")

    lines.append("")
    if not result.added and not result.fixed:
        lines.append("这次改动没有新增也没有修掉问题。")
    else:
        lines.append(f"**新增 {len(result.added)} · 修掉 {len(result.fixed)} · 未变 {result.unchanged}**")

    if result.added:
        lines.extend(["", f"### 🆕 新增（{len(result.added)}）", "", "| 规则 | 问题 | 位置 | 修法 |", "| --- | --- | --- | --- |"])
        for finding in result.added[:max_items]:
            lines.append(_finding_row(finding))
        if len(result.added) > max_items:
            lines.append("")
            lines.append(f"还有 {len(result.added) - max_items} 条未列出，完整清单见 PR 的 SARIF 结果。")

    if result.fixed:
        lines.extend(["", f"### ✅ 修掉（{len(result.fixed)}）", "", "| 规则 | 问题 | 位置 |", "| --- | --- | --- |"])
        for finding in result.fixed[:max_items]:
            lines.append(
                f"| `{_cell(finding.get('rule_id', ''), 20)}` | {_cell(finding.get('title', ''), 60)} | `{_cell(_location(finding), 80)}` |"
            )
        if len(result.fixed) > max_items:
            lines.append("")
            lines.append(f"还有 {len(result.fixed) - max_items} 条未列出。")

    lines.extend(
        [
            "",
            "---",
            "",
            "<sub>由 `provemark diff` 生成，只作参考：分数是「权重 × 置信度」的可解释信号，不是安全评级。"
            "门禁结论以 CI 的 `provemark scan --fail-on high` 为准。</sub>",
        ]
    )
    return "\n".join(lines)


def render(result: DiffResult, fmt: str, *, max_items: int = 8) -> str:
    if fmt == "markdown":
        return render_markdown(result, max_items=max_items)
    if fmt == "json":
        return json.dumps(_as_json(result), ensure_ascii=False, indent=2)
    return render_text(result)


def _as_json(result: DiffResult) -> dict[str, Any]:
    def brief(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [
            {
                "rule_id": item.get("rule_id"),
                "severity": item.get("severity"),
                "title": item.get("title"),
                "path": item.get("path"),
                "line": item.get("line"),
                "remediation": item.get("remediation"),
                "fingerprint": item.get("fingerprint"),
            }
            for item in findings
        ]

    return {
        "base": {"label": result.base_label, "score": result.base_score, "grade": result.base_grade, "counts": result.base_counts},
        "head": {"label": result.head_label, "score": result.head_score, "grade": result.head_grade, "counts": result.head_counts},
        "score_delta": result.score_delta,
        "added": brief(result.added),
        "fixed": brief(result.fixed),
        "unchanged": result.unchanged,
        "regressed": result.regressed,
    }
