from __future__ import annotations

import os
import sys
import unicodedata

from ..models import CATEGORIES, SEVERITIES, SEVERITY_LABEL, SEVERITY_RANK, Finding, Score, ScanResult
from .. import ecosystems

WIDTH = 78
SEVERITY_COLOR = {
    "critical": "\033[97;41m",
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[96m",
    "info": "\033[90m",
}
GRADE_COLOR = {"A": "\033[92m", "B": "\033[92m", "C": "\033[93m", "D": "\033[91m", "F": "\033[91m"}
DIM = "\033[90m"
BOLD = "\033[1m"
RESET = "\033[0m"


def use_color(stream=None) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    stream = stream or sys.stdout
    return bool(getattr(stream, "isatty", lambda: False)())


def _c(text: str, code: str, enabled: bool) -> str:
    return f"{code}{text}{RESET}" if enabled else text


def _bar(value: float, width: int = 10) -> str:
    filled = int(round(max(0.0, min(100.0, value)) / 100 * width))
    return "█" * filled + "░" * (width - filled)


def _short(text: str, limit: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _display_width(text: str) -> int:
    return sum(2 if unicodedata.east_asian_width(char) in ("W", "F") else 1 for char in text)


def _pad(text: str, width: int) -> str:
    return text + " " * max(0, width - _display_width(text))


def _score_line(result: ScanResult, color: bool) -> str:
    score: Score | None = result.score
    if score is None:
        return ""
    grade = score.grade
    note = "" if score.reliable else _c("  (数据不完整)", "\033[93m", color)
    return (
        f"  {_c('分数', BOLD, color)} {_c(str(score.total), BOLD, color)} / 100"
        f"   {_c('等级 ' + grade, GRADE_COLOR.get(grade, ''), color)}{note}"
    )


def _ecosystem_line(result: ScanResult) -> str:
    counts: dict[str, int] = {}
    for package in result.packages:
        counts[package.ecosystem] = counts.get(package.ecosystem, 0) + 1
    if not counts:
        return ""
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    shown = " · ".join(f"{ecosystems.label_of(name)} {count}" for name, count in ordered[:6])
    hidden = len(ordered) - 6
    suffix = f" 等 {len(ordered)} 个生态" if hidden > 0 else ""
    return f"  技术栈：{shown}{suffix}"


def render(result: ScanResult, *, verbose: bool = False, color: bool | None = None) -> str:
    color = use_color() if color is None else color
    lines: list[str] = []
    lines.append("")
    lines.append(_c(f"  Provemark v{result.tool_version}", BOLD, color) + _c(f"   {result.root}", DIM, color))
    lines.append("  " + "─" * (WIDTH - 2))
    lines.append(_score_line(result, color))

    stats = result.stats
    minutes = stats.duration_s
    meta = (
        f"  {stats.files_scanned} 个文件 · {stats.packages_total} 个依赖 · {minutes:.1f}s"
        f"{' · 联网' if stats.network_used else ' · 离线'}"
    )
    lines.append(_c(meta, DIM, color))
    stack = _ecosystem_line(result)
    if stack:
        lines.append(_c(stack, DIM, color))
    lines.append("")

    if result.findings:
        lines.append(f"  {_c('维度', BOLD, color)}")
        for category, label in CATEGORIES.items():
            count = sum(1 for finding in result.findings if finding.category == category)
            if not count:
                continue
            value = (result.score.by_category.get(category, 100.0) if result.score else 100.0)
            severities = [
                f"{SEVERITY_LABEL[severity]}{sum(1 for f in result.findings if f.category == category and f.severity == severity)}"
                for severity in SEVERITIES
                if any(f.category == category and f.severity == severity for f in result.findings)
            ]
            lines.append(
                f"  {_pad(label, 14)} {_bar(value)} {count:>3} 条   " + _c(" ".join(severities), DIM, color)
            )
        lines.append("")

    counts = result.counts_by_severity()
    chips = []
    for severity in SEVERITIES:
        if counts.get(severity):
            chips.append(_c(f" {SEVERITY_LABEL[severity]} {counts[severity]} ", SEVERITY_COLOR[severity], color))
    if chips:
        lines.append("  " + "  ".join(chips))
        lines.append("")

    ordered = result.sorted_findings()
    shown = ordered if verbose else [f for f in ordered if SEVERITY_RANK[f.severity] <= SEVERITY_RANK["high"]][:8]
    if shown:
        header = "全部问题" if verbose else "需要优先处理"
        lines.append(f"  {_c(header, BOLD, color)}")
        for finding in shown:
            label = SEVERITY_LABEL[finding.severity]
            tag = _c(f"[{label}]", SEVERITY_COLOR[finding.severity], color)
            suspect = _c("  · 需人工确认", DIM, color) if finding.confidence < 0.6 else ""
            lines.append(
                f"  {tag} {_c(finding.rule_id, BOLD, color)}  {_short(finding.title, 60)}{suspect}"
            )
            location = finding.path + (f":{finding.line}" if finding.line else "")
            if location:
                occurrences = int(finding.detail.get("count", 0) or 0)
                if occurrences > 1:
                    location += f"  （同一凭据共 {occurrences} 处）"
                lines.append(_c(f"        {location}", DIM, color))
            lines.append(f"        → {_short(finding.remediation or finding.message, WIDTH - 12)}")
        lines.append("")

    hidden = len(ordered) - len(shown)
    if hidden > 0:
        lines.append(_c(f"  还有 {hidden} 条未显示：加 --verbose 查看全部，或 -o report.html 生成报告", DIM, color))
        lines.append("")

    if result.suppressed:
        lines.append(_c(f"  已按基线豁免 {len(result.suppressed)} 条", DIM, color))
    if stats.packages_unverified:
        lines.append(_c(f"  {stats.packages_unverified} 个依赖版本无法确定，漏洞检查未覆盖", DIM, color))
    for note in stats.notes:
        lines.append(_c(f"  注意：{note}", "\033[93m" if color else "", color))
    if result.findings and result.score and result.score.total >= 90:
        lines.append(_c("  仓库状态良好，继续保持。", "\033[92m", color))
    lines.append("")
    return "\n".join(lines)


def render_finding_detail(finding: Finding) -> str:
    lines = [
        f"{finding.rule_id}  {finding.title}",
        f"级别：{SEVERITY_LABEL[finding.severity]}    维度：{CATEGORIES[finding.category]}",
    ]
    if finding.path:
        lines.append(f"位置：{finding.path}" + (f":{finding.line}" if finding.line else ""))
    lines.append(f"说明：{finding.message}")
    if finding.evidence:
        lines.append(f"证据：{finding.evidence}")
    if finding.remediation:
        lines.append(f"修法：{finding.remediation}")
    if finding.reference:
        lines.append(f"参考：{finding.reference}")
    if finding.confidence < 1.0:
        lines.append(f"置信度：{finding.confidence:.0%}（低于门禁阈值时不会阻断提交）")
    lines.append(f"指纹：{finding.fingerprint}")
    return "\n".join(lines)
