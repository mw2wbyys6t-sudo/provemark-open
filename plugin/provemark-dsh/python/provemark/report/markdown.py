from __future__ import annotations

from ..models import CATEGORIES, SEVERITIES, SEVERITY_LABEL, ScanResult


def _cell(text: str) -> str:
    return " ".join(str(text).split()).replace("|", "\\|")


def render(result: ScanResult) -> str:
    lines: list[str] = []
    score = result.score
    lines.append(f"# Provemark 扫描报告：`{result.root}`")
    lines.append("")
    lines.append(f"- 扫描时间：{result.scanned_at}")
    lines.append(f"- 工具版本：v{result.tool_version}")
    if score:
        reliability = "" if score.reliable else "（数据不完整，仅供参考）"
        lines.append(f"- 总分：**{score.total} / 100**（等级 {score.grade}）{reliability}")
    lines.append(
        f"- 规模：{result.stats.files_scanned} 个文件 · {result.stats.packages_total} 个依赖"
        f" · 耗时 {result.stats.duration_s:.1f}s"
    )
    lines.append("")

    counts = result.counts_by_severity()
    lines.append("| 致命 | 高危 | 中危 | 低危 | 提示 |")
    lines.append("| --- | --- | --- | --- | --- |")
    lines.append(
        "| "
        + " | ".join(str(counts.get(severity, 0)) for severity in SEVERITIES)
        + " |"
    )
    lines.append("")

    lines.append("## 维度分布")
    lines.append("")
    lines.append("| 维度 | 问题数 | 得分 |")
    lines.append("| --- | --- | --- |")
    for category, label in CATEGORIES.items():
        count = sum(1 for finding in result.findings if finding.category == category)
        if not count:
            continue
        value = score.by_category.get(category, 100.0) if score else 100.0
        lines.append(f"| {label} | {count} | {value:.0f} |")
    lines.append("")

    lines.append("## 问题清单")
    lines.append("")
    ordered = result.sorted_findings()
    if not ordered:
        lines.append("没有发现问题。")
        lines.append("")
    for severity in SEVERITIES:
        group = [finding for finding in ordered if finding.severity == severity]
        if not group:
            continue
        lines.append(f"### {SEVERITY_LABEL[severity]}（{len(group)}）")
        lines.append("")
        for finding in group:
            location = finding.path + (f":{finding.line}" if finding.line else "")
            lines.append(f"#### `{finding.rule_id}` {finding.title}")
            lines.append("")
            if location:
                lines.append(f"- 位置：`{location}`")
            lines.append(f"- 说明：{_cell(finding.message)}")
            if finding.evidence:
                lines.append(f"- 证据：`{_cell(finding.evidence)}`")
            if finding.remediation:
                lines.append(f"- 修法：{_cell(finding.remediation)}")
            if finding.reference:
                lines.append(f"- 参考：{finding.reference}")
            lines.append(f"- 指纹：`{finding.fingerprint}`")
            lines.append("")

    if result.suppressed:
        lines.append(f"## 已豁免（{len(result.suppressed)}）")
        lines.append("")
        for finding in result.suppressed:
            lines.append(f"- `{finding.rule_id}` {finding.title} — {finding.path}")
        lines.append("")

    notes = result.stats.notes
    if notes:
        lines.append("## 数据说明")
        lines.append("")
        for note in notes:
            lines.append(f"- {note}")
        lines.append("")

    lines.append("## 复现")
    lines.append("")
    lines.append("```bash")
    lines.append(f"provemark scan {result.root} --format markdown -o report.md")
    lines.append("```")
    lines.append("")
    return "\n".join(lines)
