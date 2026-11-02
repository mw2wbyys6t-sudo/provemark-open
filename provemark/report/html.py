from __future__ import annotations

import html
from pathlib import Path

from ..models import CATEGORIES, SEVERITIES, SEVERITY_LABEL, ScanResult

CSS = """
*,*::before,*::after{box-sizing:border-box}
:root{
  --bg:#f5f6f8;--card:#ffffff;--ink:#151a21;--muted:#69707d;--line:#e4e7ec;
  --accent:#2f6df6;--accent-soft:#eaf0ff;
  --critical:#c62828;--high:#e2521b;--medium:#c47f00;--low:#2f80ed;--info:#7b8794;
  --ok:#1f9254;--warn:#c47f00;--bad:#c62828;
  --radius:14px;
}
@media (prefers-color-scheme:dark){
  :root{--bg:#0e1116;--card:#161b22;--ink:#e7ebf0;--muted:#98a1ae;--line:#242b35;--accent:#6f9bff;--accent-soft:#1a2333;
  --critical:#ff7b72;--high:#ff9d6b;--medium:#e3b341;--low:#79b8ff;--info:#8b96a3;--ok:#4ac26b}
}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--ink);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Hiragino Sans GB","Noto Sans SC","Microsoft YaHei",sans-serif;
  font-size:15px;line-height:1.65;-webkit-font-smoothing:antialiased}
code,pre,.mono{font-family:ui-monospace,SFMono-Regular,"SF Mono",Menlo,Consolas,"Liberation Mono",monospace}
.page{max-width:1060px;margin:0 auto;padding:40px 24px 72px}
.top{display:flex;align-items:baseline;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:32px}
.brand{display:flex;align-items:center;gap:10px;font-weight:650;letter-spacing:-.01em}
.logo{width:26px;height:26px;border-radius:8px;background:linear-gradient(135deg,#2f6df6,#7c4dff);
  display:grid;place-items:center;color:#fff;font-size:13px}
.ver{font-size:11px;color:var(--muted);border:1px solid var(--line);border-radius:999px;padding:1px 7px;font-weight:500}
.meta{font-size:12.5px;color:var(--muted);display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.meta code{background:var(--card);border:1px solid var(--line);padding:2px 8px;border-radius:7px;font-size:12px}
.hero{display:grid;grid-template-columns:230px 1fr;gap:22px;align-items:stretch;margin-bottom:22px}
@media(max-width:720px){.hero{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius)}
.score-card{display:flex;flex-direction:column;align-items:center;justify-content:center;padding:26px 18px;gap:6px;position:relative}
.ring{position:relative;width:150px;height:150px}
.ring svg{transform:rotate(-90deg)}
.ring .num{position:absolute;inset:0;display:grid;place-items:center;text-align:center}
.ring .num b{display:block;font-size:44px;line-height:1;letter-spacing:-.03em}
.ring .num span{font-size:11.5px;color:var(--muted);letter-spacing:.08em}
.grade{margin-top:6px;font-size:12px;font-weight:600;padding:3px 12px;border-radius:999px;
  border:1px solid currentColor;letter-spacing:.06em}
.summary{padding:26px 28px;display:flex;flex-direction:column;justify-content:center;gap:14px}
h1{margin:0;font-size:23px;line-height:1.35;letter-spacing:-.02em;font-weight:650}
.lede{margin:0;color:var(--muted);font-size:13.5px}
.chips{display:flex;flex-wrap:wrap;gap:8px}
.chip{display:inline-flex;align-items:center;gap:6px;font-size:12.5px;padding:4px 11px;border-radius:999px;
  border:1px solid var(--line);background:var(--bg);font-weight:550}
.chip i{width:7px;height:7px;border-radius:50%;background:currentColor;display:inline-block}
.facts{display:flex;flex-wrap:wrap;gap:18px;font-size:12.5px;color:var(--muted);border-top:1px dashed var(--line);padding-top:12px}
.facts b{color:var(--ink);font-weight:600}
h2{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);font-weight:600;margin:34px 0 14px}
.cats{display:grid;grid-template-columns:repeat(auto-fill,minmax(168px,1fr));gap:12px}
.cat{padding:14px 16px;border-radius:12px;background:var(--card);border:1px solid var(--line)}
.cat-top{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:8px}
.cat-name{font-size:13px;font-weight:600}
.cat-count{font-size:12px;color:var(--muted)}
.mini{height:5px;border-radius:3px;background:var(--line);overflow:hidden}
.mini span{display:block;height:100%;border-radius:3px}
.toolbar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin:18px 0 6px;position:sticky;top:0;
  padding:10px 0;background:linear-gradient(var(--bg) 72%,transparent);z-index:5}
.btn{font:inherit;font-size:12.5px;padding:6px 13px;border-radius:999px;border:1px solid var(--line);
  background:var(--card);color:var(--ink);cursor:pointer;font-weight:550}
.btn:hover{border-color:var(--accent);color:var(--accent)}
.btn[aria-pressed="true"]{background:var(--accent);border-color:var(--accent);color:#fff}
.search{flex:1;min-width:180px;font:inherit;font-size:13px;padding:7px 13px;border-radius:999px;
  border:1px solid var(--line);background:var(--card);color:var(--ink)}
.search:focus{outline:2px solid var(--accent);outline-offset:1px;border-color:transparent}
.finding{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px 18px 14px;
  margin-bottom:10px;border-left:3px solid var(--line)}
.finding[data-sev="critical"]{border-left-color:var(--critical)}
.finding[data-sev="high"]{border-left-color:var(--high)}
.finding[data-sev="medium"]{border-left-color:var(--medium)}
.finding[data-sev="low"]{border-left-color:var(--low)}
.finding[data-sev="info"]{border-left-color:var(--info)}
.f-head{display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
.sev{font-size:11px;font-weight:650;letter-spacing:.04em;padding:1px 8px;border-radius:5px;color:#fff;flex:none}
.sev-critical{background:var(--critical)}.sev-high{background:var(--high)}.sev-medium{background:var(--medium)}
.sev-low{background:var(--low)}.sev-info{background:var(--info)}
.rid{font-size:11.5px;color:var(--muted);border:1px solid var(--line);border-radius:5px;padding:0 6px}
.f-head h3{margin:0;font-size:15px;font-weight:600;flex:1;min-width:200px;letter-spacing:-.01em}
.loc{font-size:12px;color:var(--muted)}
.msg{margin:8px 0 0;font-size:13.5px;color:var(--ink)}
details{margin-top:10px}
summary{cursor:pointer;font-size:12.5px;color:var(--accent);font-weight:550;list-style:none}
summary::-webkit-details-marker{display:none}
summary::before{content:"▸ ";font-size:10px}
details[open] summary::before{content:"▾ "}
pre.evidence{margin:10px 0 8px;background:var(--bg);border:1px solid var(--line);border-radius:9px;
  padding:10px 12px;font-size:12px;overflow-x:auto;white-space:pre-wrap;word-break:break-word}
.fix{margin:6px 0;font-size:13px}
.fix b{font-size:11px;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);display:block;margin-bottom:2px}
.ref{margin:6px 0 0;font-size:12.5px}
a{color:var(--accent);text-decoration:none;border-bottom:1px solid color-mix(in srgb,var(--accent) 35%,transparent)}
.fp{display:flex;gap:8px;align-items:center;margin-top:10px;font-size:11.5px;color:var(--muted)}
.fp code{background:var(--bg);border:1px solid var(--line);padding:2px 7px;border-radius:6px}
.fp button{font:inherit;font-size:11.5px;background:none;border:1px solid var(--line);border-radius:6px;
  padding:2px 8px;cursor:pointer;color:var(--muted)}
.fp button:hover{color:var(--accent);border-color:var(--accent)}
.empty{padding:44px;text-align:center;color:var(--muted);background:var(--card);border:1px dashed var(--line);border-radius:var(--radius)}
.notes{font-size:12.5px;color:var(--muted)}
.notes ul{margin:8px 0 0;padding-left:18px}
.notes li{margin:3px 0}
footer{margin-top:40px;padding-top:16px;border-top:1px solid var(--line);font-size:11.5px;color:var(--muted);
  display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
.hide{display:none!important}
@media print{.toolbar,.fp button{display:none}body{background:#fff}.page{padding:0}}
"""


def _e(text: object) -> str:
    return html.escape(str(text), quote=True)


def _grade_color(grade: str) -> str:
    return {"A": "var(--ok)", "B": "var(--ok)", "C": "var(--warn)", "D": "var(--bad)", "F": "var(--bad)"}.get(
        grade, "var(--muted)"
    )


def _ring(total: int, grade: str) -> str:
    radius = 62
    circumference = 2 * 3.1415926 * radius
    dash = circumference * max(0, min(100, total)) / 100
    color = _grade_color(grade)
    return (
        f'<div class="ring">'
        f'<svg width="150" height="150" viewBox="0 0 150 150" aria-hidden="true">'
        f'<circle cx="75" cy="75" r="{radius}" fill="none" stroke="var(--line)" stroke-width="11"/>'
        f'<circle cx="75" cy="75" r="{radius}" fill="none" stroke="{color}" stroke-width="11" '
        f'stroke-linecap="round" stroke-dasharray="{dash:.1f} {circumference:.1f}"/>'
        f"</svg>"
        f'<div class="num"><b style="color:{color}">{total}</b><span>/ 100</span></div>'
        f"</div>"
        f'<div class="grade" style="color:{color}">等级 {_e(grade)}</div>'
    )


def _category_cards(result: ScanResult) -> str:
    parts: list[str] = []
    for category, label in CATEGORIES.items():
        count = sum(1 for finding in result.findings if finding.category == category)
        if not count:
            continue
        value = result.score.by_category.get(category, 100.0) if result.score else 100.0
        color = "var(--ok)" if value >= 90 else "var(--medium)" if value >= 70 else "var(--high)" if value >= 50 else "var(--critical)"
        parts.append(
            f'<div class="cat"><div class="cat-top"><span class="cat-name">{_e(label)}</span>'
            f'<span class="cat-count">{count} 条 · {value:.0f} 分</span></div>'
            f'<div class="mini"><span style="width:{value:.0f}%;background:{color}"></span></div></div>'
        )
    return "".join(parts)


def _finding_card(finding) -> str:
    location = finding.path + (f":{finding.line}" if finding.line else "")
    occurrences = int(finding.detail.get("count", 0) or 0)
    if location and occurrences > 1:
        location += f"（同一凭据共 {occurrences} 处）"
    search_blob = " ".join(
        [finding.rule_id, finding.title, finding.path, finding.message, str(finding.line)]
    ).lower()
    details: list[str] = []
    if finding.evidence:
        details.append(f'<pre class="evidence">{_e(finding.evidence)}</pre>')
    if finding.remediation:
        details.append(f'<div class="fix"><b>怎么修</b>{_e(finding.remediation)}</div>')
    if finding.reference:
        ref = finding.reference
        link = f'<a href="{_e(ref)}" rel="noreferrer noopener" target="_blank">{_e(ref)}</a>'
        details.append(f'<div class="ref">{link}</div>')
    details.append(
        f'<div class="fp"><span>指纹</span><code>{finding.fingerprint}</code>'
        f'<button data-copy="{finding.fingerprint}" type="button">复制</button></div>'
    )
    return (
        f'<article class="finding" data-sev="{finding.severity}" data-cat="{finding.category}" '
        f'data-search="{_e(search_blob)}">'
        f'<div class="f-head"><span class="sev sev-{finding.severity}">{_e(SEVERITY_LABEL[finding.severity])}</span>'
        f'<span class="rid">{_e(finding.rule_id)}</span>'
        f"<h3>{_e(finding.title)}</h3>"
        + (f'<span class="loc mono">{_e(location)}</span>' if location else "")
        + f'</div><p class="msg">{_e(finding.message)}</p>'
        f"<details><summary>证据与修复建议</summary>{''.join(details)}</details>"
        f"</article>"
    )


def render(result: ScanResult) -> str:
    score = result.score
    total = score.total if score else 0
    grade = score.grade if score else "-"
    counts = result.counts_by_severity()
    ordered = result.sorted_findings()
    repo_name = Path(result.root).name or result.root
    reliability = "" if not score or score.reliable else "数据不完整，分数仅供参考"

    chips = "".join(
        f'<span class="chip" style="color:var(--{severity})"><i></i>{SEVERITY_LABEL[severity]} {counts[severity]}</span>'
        for severity in SEVERITIES
        if counts.get(severity)
    )
    if not chips:
        chips = '<span class="chip" style="color:var(--ok)"><i></i>没有发现问题</span>'

    filters = ['<button class="btn" data-filter="all" aria-pressed="true" type="button">全部 ' + str(len(ordered)) + "</button>"]
    for severity in SEVERITIES:
        if counts.get(severity):
            filters.append(
                f'<button class="btn" data-filter="{severity}" aria-pressed="false" type="button">'
                f"{SEVERITY_LABEL[severity]} {counts[severity]}</button>"
            )

    cards = "".join(_finding_card(finding) for finding in ordered)
    if not cards:
        cards = '<div class="empty">本次扫描没有发现问题。<br>保持这个状态，比修一次要省力得多。</div>'

    notes = "".join(f"<li>{_e(note)}</li>" for note in result.stats.notes)
    suppressed = (
        f'<li>已按基线豁免 {len(result.suppressed)} 条（未计入分数）</li>' if result.suppressed else ""
    )

    head = (
        "<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>Provemark 报告 · {_e(repo_name)}</title>"
        f"<style>{CSS}</style></head><body><div class=\"page\">"
    )

    body = (
        '<header class="top"><div class="brand"><span class="logo">◈</span>Provemark'
        f'<span class="ver">v{_e(result.tool_version)}</span></div>'
        f'<div class="meta"><code>{_e(result.root)}</code><span>·</span><span>{_e(result.scanned_at)}</span></div>'
        "</header>"
        '<section class="hero">'
        f'<div class="card score-card">{_ring(total, grade)}</div>'
        '<div class="card summary">'
        f"<h1>{_e(repo_name)} 的仓库体检结果</h1>"
        f'<p class="lede">{"数据不完整，分数仅供参考。" if reliability else "以下问题按严重度排序，每条都给出可执行的修法。"}</p>'
        f'<div class="chips">{chips}</div>'
        '<div class="facts">'
        f"<span>文件 <b>{result.stats.files_scanned}</b></span>"
        f"<span>依赖 <b>{result.stats.packages_total}</b></span>"
        f"<span>直接依赖 <b>{result.stats.packages_direct}</b></span>"
        f"<span>耗时 <b>{result.stats.duration_s:.1f}s</b></span>"
        f"<span>数据源 <b>{'联网' if result.stats.network_used else '离线'}</b></span>"
        "</div></div></section>"
    )

    cats = _category_cards(result)
    section_cats = f"<h2>维度分布</h2><div class=\"cats\">{cats}</div>" if cats else ""

    toolbar = (
        '<h2>问题明细</h2><div class="toolbar">'
        + "".join(filters)
        + '<input class="search" type="search" placeholder="搜索规则 / 文件 / 关键词" aria-label="搜索问题">'
        "</div>"
    )

    notes_block = ""
    if notes or suppressed:
        notes_block = (
            '<h2>数据说明</h2><div class="notes"><ul>'
            f"{notes}{suppressed}"
            "<li>漏洞数据来自 OSV.dev，依赖许可证来自 deps.dev / 包注册表，均标注在每条问题的来源字段中。</li>"
            "<li>许可证结论是工程判断，不构成法律意见。</li>"
            f"</ul></div>"
        )

    footer = (
        '<footer><span>Provemark · 本地扫描，代码未离开本机</span>'
        f"<span>生成于 {_e(result.scanned_at)}</span></footer>"
    )

    script = """
<script>
(function(){
  var buttons=document.querySelectorAll('[data-filter]');
  var search=document.querySelector('.search');
  var items=Array.prototype.slice.call(document.querySelectorAll('.finding'));
  var active='all';
  function apply(){
    var q=(search&&search.value||'').trim().toLowerCase();
    items.forEach(function(el){
      var sevOk=active==='all'||el.dataset.sev===active;
      var qOk=!q||(el.dataset.search||'').indexOf(q)>=0;
      el.classList.toggle('hide',!(sevOk&&qOk));
    });
  }
  buttons.forEach(function(btn){
    btn.addEventListener('click',function(){
      active=btn.dataset.filter;
      buttons.forEach(function(b){b.setAttribute('aria-pressed',String(b===btn));});
      apply();
    });
  });
  if(search){search.addEventListener('input',apply);}
  document.querySelectorAll('[data-copy]').forEach(function(btn){
    btn.addEventListener('click',function(){
      var text=btn.getAttribute('data-copy');
      if(navigator.clipboard){navigator.clipboard.writeText(text).then(function(){
        var old=btn.textContent;btn.textContent='已复制';setTimeout(function(){btn.textContent=old;},1200);
      });}
    });
  });
})();
</script>
"""
    return head + body + section_cats + toolbar + '<div id="findings">' + cards + "</div>" + notes_block + footer + script + "</div></body></html>"
