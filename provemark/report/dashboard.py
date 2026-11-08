"""Self-contained HTML progress dashboard.

One file, no network, no JavaScript framework, no external asset: the charts are
inline SVG written by this module, so the document opens from a USB stick, an
email attachment or a CI artifact and looks the same. Every interpolated value
goes through ``html.escape`` — the numbers come from scans, but paths and rule
ids are still untrusted text.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Any, Iterable

SEVERITY_LABELS = {
    "critical": "致命",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "提示",
}
SEVERITY_COLORS = {
    "critical": "#f87171",
    "high": "#fb923c",
    "medium": "#facc15",
    "low": "#60a5fa",
    "info": "#94a3b8",
}
GRADE_COLORS = {"A": "#34d399", "B": "#a3e635", "C": "#facc15", "D": "#fb923c", "E": "#f87171"}

CSS = """
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;padding:32px 28px 64px;background:#0b1220;color:#e2e8f0;
  font:14px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
h1{font-size:24px;margin:0 0 4px;letter-spacing:.02em}
h2{font-size:16px;margin:0 0 12px;color:#cbd5e1;font-weight:600}
h3{font-size:13px;margin:0 0 8px;color:#94a3b8;font-weight:600;letter-spacing:.04em;text-transform:uppercase}
.meta{color:#64748b;font-size:12px}
.wrap{max-width:1120px;margin:0 auto}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:22px 0 28px}
.kpi{background:#111a2e;border:1px solid #1e293b;border-radius:12px;padding:14px 16px}
.kpi .label{color:#94a3b8;font-size:12px}
.kpi .value{font-size:28px;font-weight:650;line-height:1.2;margin-top:4px}
.kpi .sub{color:#64748b;font-size:12px;margin-top:2px}
.panel{background:#111a2e;border:1px solid #1e293b;border-radius:14px;padding:18px 20px;margin:0 0 20px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:#94a3b8;font-weight:600;font-size:12px;padding:8px 10px;border-bottom:1px solid #1e293b}
td{padding:9px 10px;border-bottom:1px solid #16213a;vertical-align:middle}
tr:last-child td{border-bottom:none}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
.muted{color:#64748b}
.path{color:#cbd5e1;word-break:break-all}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:600;margin-right:6px}
.sev-critical{background:rgba(248,113,113,.16);color:#fca5a5}
.sev-high{background:rgba(251,146,60,.16);color:#fdba74}
.sev-medium{background:rgba(250,204,21,.16);color:#fde047}
.sev-low{background:rgba(96,165,250,.16);color:#93c5fd}
.sev-info{background:rgba(148,163,184,.16);color:#cbd5e1}
.grade{font-weight:700;padding:2px 10px;border-radius:8px;background:rgba(52,211,153,.14);color:#6ee7b7}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
@media (max-width:860px){.grid{grid-template-columns:1fr}}
figure{margin:0}
figcaption{color:#64748b;font-size:12px;margin-top:6px}
.empty{color:#64748b;padding:28px 0;text-align:center}
details{margin-top:14px}
summary{cursor:pointer;color:#94a3b8;font-size:13px}
footer{color:#475569;font-size:12px;margin-top:24px;border-top:1px solid #16213a;padding-top:14px}
"""


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _fmt_ts(value: Any) -> str:
    text = str(value or "")
    return text.replace("T", " ").replace("Z", "") if text else "—"


def _fmt_score(value: Any) -> str:
    return "—" if value is None else str(int(value))


def _delta(value: Any) -> str:
    if value is None:
        return '<span class="muted">—</span>'
    number = int(value)
    if number > 0:
        return f'<span style="color:#6ee7b7">▲ {number}</span>'
    if number < 0:
        return f'<span style="color:#fca5a5">▼ {abs(number)}</span>'
    return '<span class="muted">持平</span>'


def _count_chips(counts: dict[str, int]) -> str:
    chips = []
    for name in ("critical", "high", "medium", "low", "info"):
        number = int((counts or {}).get(name, 0))
        if number <= 0:
            continue
        chips.append(f'<span class="badge sev-{name}">{SEVERITY_LABELS[name]} {number}</span>')
    return "".join(chips) or '<span class="muted">无</span>'


# --------------------------------------------------------------------- charts
def _polyline_points(values: list[float], width: float, height: float, pad: float = 6.0) -> str:
    if not values:
        return ""
    if len(values) == 1:
        values = [values[0], values[0]]
    top = max(values)
    bottom = min(values)
    span = max(1.0, top - bottom)
    step = (width - pad * 2) / max(1, len(values) - 1)
    points = []
    for index, value in enumerate(values):
        x = pad + step * index
        y = pad + (height - pad * 2) * (1 - (value - bottom) / span)
        points.append(f"{x:.1f},{y:.1f}")
    return " ".join(points)


def _sparkline(series: Iterable[dict[str, Any]], width: int = 132, height: int = 30) -> str:
    scores = [float(item["score"]) for item in series if item.get("score") is not None]
    if not scores:
        return '<span class="muted">—</span>'
    points = _polyline_points(scores, width, height, pad=3)
    color = "#34d399" if len(scores) < 2 or scores[-1] >= scores[0] else "#f87171"
    last_x = width - 3
    last_y = points.split(" ")[-1].split(",")[1]
    return (
        f'<svg width="{width}" height="{height}" viewBox="0 0 {width} {height}" aria-hidden="true">'
        f'<polyline fill="none" stroke="{color}" stroke-width="1.8" stroke-linecap="round" '
        f'stroke-linejoin="round" points="{points}"/>'
        f'<circle cx="{last_x:.1f}" cy="{last_y}" r="2.2" fill="{color}"/></svg>'
    )


def _score_chart(series: list[dict[str, Any]], width: int = 540, height: int = 170) -> str:
    scores = [item for item in series if item.get("score") is not None]
    if not scores:
        return '<p class="empty">还没有分数记录</p>'
    values = [float(item["score"]) for item in scores]
    pad_left, pad_bottom, pad_top = 34, 22, 12
    plot_w = width - pad_left - 12
    plot_h = height - pad_bottom - pad_top
    low = min(values)
    high = max(values)
    if high == low:
        low, high = max(0.0, low - 2), min(100.0, high + 2)
    span = max(1.0, high - low)
    step = plot_w / max(1, len(values) - 1)
    points = []
    for index, value in enumerate(values):
        x = pad_left + step * index
        y = pad_top + plot_h * (1 - (value - low) / span)
        points.append(f"{x:.1f},{y:.1f}")
    line = " ".join(points)
    area = f"{pad_left},{pad_top + plot_h} {line} {pad_left + step * (len(values) - 1):.1f},{pad_top + plot_h}"
    grid = []
    for fraction in (0.0, 0.5, 1.0):
        y = pad_top + plot_h * fraction
        value = round(high - (high - low) * fraction)
        grid.append(
            f'<line x1="{pad_left}" y1="{y:.1f}" x2="{width - 12}" y2="{y:.1f}" stroke="#1e293b" stroke-width="1"/>'
            f'<text x="{pad_left - 8}" y="{y + 4:.1f}" fill="#475569" font-size="10" text-anchor="end">{value}</text>'
        )
    dots = "".join(
        f'<circle cx="{point.split(",")[0]}" cy="{point.split(",")[1]}" r="2.4" fill="#34d399"/>'
        for point in points
    )
    first_label = _fmt_ts(scores[0].get("ts"))
    last_label = _fmt_ts(scores[-1].get("ts"))
    return (
        f'<svg width="100%" viewBox="0 0 {width} {height}" role="img" aria-label="分数时间线">'
        f'{"".join(grid)}'
        f'<polygon points="{area}" fill="rgba(52,211,153,.10)"/>'
        f'<polyline points="{line}" fill="none" stroke="#34d399" stroke-width="2" stroke-linejoin="round"/>'
        f"{dots}"
        f'<text x="{pad_left}" y="{height - 4}" fill="#475569" font-size="10">{_e(first_label)}</text>'
        f'<text x="{width - 12}" y="{height - 4}" fill="#475569" font-size="10" text-anchor="end">{_e(last_label)}</text>'
        f"</svg>"
    )


def _open_chart(series: list[dict[str, Any]], width: int = 540, height: int = 170) -> str:
    if not series:
        return '<p class="empty">还没有记录</p>'
    pad_left, pad_bottom, pad_top = 34, 22, 12
    plot_w = width - pad_left - 12
    plot_h = height - pad_bottom - pad_top
    totals = [sum(int((item.get("counts") or {}).get(name, 0)) for name in SEVERITY_LABELS) for item in series]
    top = max(1, max(totals))
    step = plot_w / max(1, len(series))
    bar_w = max(1.5, min(10.0, step * 0.6))
    bars = []
    for index, item in enumerate(series):
        x = pad_left + step * index + (step - bar_w) / 2
        cursor = pad_top + plot_h
        for name in ("critical", "high", "medium", "low", "info"):
            number = int((item.get("counts") or {}).get(name, 0))
            if number <= 0:
                continue
            h = plot_h * number / top
            cursor -= h
            bars.append(
                f'<rect x="{x:.1f}" y="{cursor:.1f}" width="{bar_w:.1f}" height="{h:.1f}" '
                f'fill="{SEVERITY_COLORS[name]}" opacity="0.85"/>'
            )
    grid = []
    for fraction in (0.0, 0.5, 1.0):
        y = pad_top + plot_h * fraction
        value = round(top * (1 - fraction))
        grid.append(
            f'<line x1="{pad_left}" y1="{y:.1f}" x2="{width - 12}" y2="{y:.1f}" stroke="#1e293b" stroke-width="1"/>'
            f'<text x="{pad_left - 8}" y="{y + 4:.1f}" fill="#475569" font-size="10" text-anchor="end">{value}</text>'
        )
    return (
        f'<svg width="100%" viewBox="0 0 {width} {height}" role="img" aria-label="未修复问题数量">'
        f'{"".join(grid)}{"".join(bars)}</svg>'
    )


# ----------------------------------------------------------------------- page
def _kpis(report: dict[str, Any]) -> str:
    totals = report.get("totals", {})
    by_severity = totals.get("by_severity", {}) or {}
    open_total = int(totals.get("open", 0))
    serious = int(by_severity.get("critical", 0)) + int(by_severity.get("high", 0))
    cards = [
        ("项目", str(int(totals.get("projects", 0))), f'共 {int(totals.get("scans", 0))} 次扫描'),
        ("未修复问题", str(open_total), f"其中致命/高危 {serious}"),
        ("近 7 天修复", str(int(totals.get("fixed_recent", 0))), f'新增 {int(totals.get("new_recent", 0))}'),
        ("复发", str(int(totals.get("reopened", 0))), "修好后又出现"),
    ]
    return "".join(
        f'<div class="kpi"><div class="label">{_e(label)}</div>'
        f'<div class="value">{_e(value)}</div><div class="sub">{_e(sub)}</div></div>'
        for label, value, sub in cards
    )


def _overview_rows(projects: list[dict[str, Any]]) -> str:
    rows = []
    for project in projects:
        current = project.get("current", {}) or {}
        counts = current.get("counts", {}) or {}
        grade = str(current.get("grade", "") or "")
        grade_color = GRADE_COLORS.get(grade, "#94a3b8")
        rows.append(
            "<tr>"
            f'<td class="path">{_e(project.get("root", ""))}</td>'
            f'<td><strong>{_e(_fmt_score(current.get("score")))}</strong></td>'
            f'<td><span class="grade" style="background:rgba(255,255,255,.06);color:{grade_color}">{_e(grade or "—")}</span></td>'
            f"<td>{_count_chips(counts)}</td>"
            f'<td>{_e(project.get("open_count", 0))}</td>'
            f'<td>{_e(len(project.get("fixed_recent", []) or []))} / {_e(len(project.get("new_recent", []) or []))}</td>'
            f"<td>{_sparkline(project.get('series', []))}</td>"
            f'<td class="muted">{_e(_fmt_ts(project.get("last_ts")))}</td>'
            "</tr>"
        )
    if not rows:
        return '<tr><td colspan="8" class="empty">还没有任何扫描记录：先跑一次 <code>provemark scan &lt;项目&gt;</code>。</td></tr>'
    head = (
        "<tr><th>项目</th><th>分数</th><th>等级</th><th>当前问题</th><th>未修复</th>"
        "<th>7天 修复/新增</th><th>趋势</th><th>最近扫描</th></tr>"
    )
    return head + "".join(rows)


def _finding_rows(open_entries: list[dict[str, Any]], *, now: datetime, limit: int = 14) -> str:
    rows = []
    for entry in open_entries[:limit]:
        severity = str(entry.get("severity", "info"))
        first = entry.get("first_ts", "")
        age = "—"
        try:
            first_dt = datetime.fromisoformat(str(first).replace("Z", "+00:00"))
            age = f"{(now - first_dt).days} 天"
        except (TypeError, ValueError):
            age = "—"
        reopened = "· 复发" if entry.get("reopened") else ""
        rows.append(
            "<tr>"
            f'<td><span class="badge sev-{_e(severity)}">{_e(SEVERITY_LABELS.get(severity, severity))}</span></td>'
            f'<td class="mono">{_e(entry.get("rule", ""))}</td>'
            f'<td class="path">{_e(entry.get("path", "") or "（仓库级）")}</td>'
            f'<td class="muted">{_e(age)}{_e(reopened)}</td>'
            "</tr>"
        )
    if not rows:
        return '<tr><td colspan="4" class="empty">没有未修复问题</td></tr>'
    return "<tr><th>级别</th><th>规则</th><th>位置</th><th>首次出现</th></tr>" + "".join(rows)


def _project_panel(project: dict[str, Any], *, now: datetime) -> str:
    current = project.get("current", {}) or {}
    series = project.get("series", []) or []
    delta = project.get("delta_score")
    open_count = int(project.get("open_count", 0))
    fixed_count = int(project.get("fixed_count", 0))
    reopened_count = int(project.get("reopened_count", 0))
    kpis = "".join(
        f'<div class="kpi"><div class="label">{_e(label)}</div><div class="value">{value}</div>'
        f'<div class="sub">{_e(sub)}</div></div>'
        for label, value, sub in (
            ("当前分数", _e(_fmt_score(current.get("score"))), f"等级 {_e(current.get('grade', '—'))}"),
            ("较首次", _delta(delta), f'{_e(project.get("scans", 0))} 次扫描'),
            ("未修复", _e(open_count), f"累计修掉 {fixed_count}"),
            ("复发", _e(reopened_count), f'覆盖 {_e(project.get("subjects", 0))} 条问题'),
        )
    )
    return (
        '<section class="panel">'
        f'<h2>{_e(project.get("root", ""))}</h2>'
        f'<div class="kpis" style="margin-top:14px">{kpis}</div>'
        '<div class="grid">'
        f'<figure><h3>分数时间线</h3>{_score_chart(series)}'
        f'<figcaption>共 {len(series)} 个记录点，首次 {_e(_fmt_ts(project.get("first_ts")))}</figcaption></figure>'
        f'<figure><h3>未修复问题数</h3>{_open_chart(series)}'
        '<figcaption>按严重度堆叠：红致命 · 橙高危 · 黄中危 · 蓝低危</figcaption></figure>'
        "</div>"
        f"<h3 style='margin-top:18px'>未修复问题（{open_count}）</h3>"
        f'<table>{_finding_rows(project.get("open", []) or [], now=now)}</table>'
        "</section>"
    )


def render_dashboard(report: dict[str, Any], *, title: str = "Provemark 进度") -> str:
    """Render the whole dashboard as one HTML document."""
    now = datetime.now(timezone.utc)
    generated = str(report.get("generated_at") or "") or now.strftime("%Y-%m-%dT%H:%M:%SZ")
    projects = report.get("projects", []) or []
    panels = "".join(_project_panel(project, now=now) for project in projects)
    if not projects:
        panels = '<section class="panel"><p class="empty">历史库还是空的。扫描一次任意项目后，这里会出现它的时间线与问题生命周期。</p></section>'
    body = (
        f'<div class="wrap">'
        f"<header><h1>{_e(title)}</h1>"
        f'<div class="meta">生成于 {_e(_fmt_ts(generated))} · 历史库 {_e(report.get("history_path", ""))}</div></header>'
        f'<section class="kpis">{_kpis(report)}</section>'
        f'<section class="panel"><h2>跨项目总览</h2>'
        f'<table>{_overview_rows(projects)}</table></section>'
        f"{panels}"
        f'<footer>由 Provemark 本地生成 · 不含源码、不含密钥 · '
        f"判定口径：存在致命/高危即阻断 · 数据来自本机的扫描历史</footer>"
        f"</div>"
    )
    return (
        "<!doctype html>\n"
        '<html lang="zh-CN"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{_e(title)}</title><style>{CSS}</style></head>"
        f"<body>{body}</body></html>\n"
    )
