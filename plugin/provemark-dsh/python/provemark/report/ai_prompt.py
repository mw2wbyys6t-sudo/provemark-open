from __future__ import annotations

from ..models import CATEGORIES, SEVERITY_LABEL, ScanResult

MAX_TASKS = 60


def render(result: ScanResult, *, test_command: str = "") -> str:
    ordered = result.sorted_findings()
    if not ordered:
        return "本次扫描没有发现问题，无需生成修复任务。\n"

    tasks = ordered[:MAX_TASKS]
    lines: list[str] = []
    lines.append("# Provemark 修复任务")
    lines.append("")
    lines.append(f"仓库：`{result.root}`")
    lines.append(f"扫描时间：{result.scanned_at}")
    if result.score:
        lines.append(f"当前分数：{result.score.total} / 100（等级 {result.score.grade}）")
    lines.append("")
    lines.append("## 执行约束")
    lines.append("")
    lines.append("- 只修改下面列出的问题，不要顺带重构、改名或调整无关代码。")
    lines.append("- 不要引入新的第三方依赖；如果确实必要，先说明理由并给出替代方案。")
    lines.append("- 不要删除已有测试；如果行为发生变化，补充或更新对应测试。")
    lines.append("- 不要在任何文件里写入真实密钥；凭据统一从环境变量读取。")
    lines.append("- 每一项修改后，说明你改了什么、为什么，以及如何验证。")
    if test_command:
        lines.append(f"- 全部修改完成后运行：`{test_command}`")
    lines.append("")
    lines.append(f"## 任务清单（{len(tasks)} 项）")
    lines.append("")

    for index, finding in enumerate(tasks, start=1):
        location = finding.path + (f":{finding.line}" if finding.line else "")
        lines.append(
            f"### {index}. [{SEVERITY_LABEL[finding.severity]}][{CATEGORIES[finding.category]}] "
            f"{finding.title}"
        )
        lines.append("")
        if location:
            lines.append(f"- 位置：`{location}`")
        lines.append(f"- 规则：`{finding.rule_id}`")
        if finding.evidence:
            lines.append(f"- 现状：`{finding.evidence}`")
        lines.append(f"- 说明：{finding.message}")
        if finding.remediation:
            lines.append(f"- 期望：{finding.remediation}")
        if finding.reference:
            lines.append(f"- 参考：{finding.reference}")
        lines.append("- 完成判定：该问题在重新扫描时不再出现，且相关测试通过。")
        lines.append("")

    if len(ordered) > MAX_TASKS:
        lines.append(f"> 另有 {len(ordered) - MAX_TASKS} 条问题未列出，请先修复以上部分后重新生成。")
        lines.append("")
    lines.append("## 验证")
    lines.append("")
    lines.append("```bash")
    lines.append("provemark scan --fail-on high")
    if test_command:
        lines.append(test_command)
    lines.append("```")
    lines.append("")
    return "\n".join(lines)
