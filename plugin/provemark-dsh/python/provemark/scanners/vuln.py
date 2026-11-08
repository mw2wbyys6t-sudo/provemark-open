from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from ..models import Finding, Package
from ..net import NetworkError, http_json
from .. import ecosystems
from .base import Context, make_finding

OSV_QUERY = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
QUERY_TTL = 6 * 3600
DETAIL_TTL = 30 * 24 * 3600
MAX_DETAIL_FETCH = 400
COMMIT_SHA = re.compile(r"[0-9a-f]{40}", re.IGNORECASE)
SEVERITY_MAP = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
}
REMEDIATION = {
    "PyPI": '升级到 {name}>={target}（pip install -U "{name}>={target}"），并同步清单下限。',
    "npm": "升级到 {name}@{target}（npm install {name}@{target}），并提交锁文件。",
    "Go": "执行 go get {name}@v{target} && go mod tidy。",
    "crates.io": "把 {name} 升级到 {target}（cargo update -p {name}）。",
    "Maven": "在 pom.xml / build.gradle 中把 {name} 升到 {target}，并执行依赖树检查。",
    "NuGet": "执行 dotnet add package {name} --version {target}。",
    "RubyGems": "执行 bundle update {name}（目标 {target}）。",
    "Packagist": "执行 composer update {name}（目标 {target}）。",
    "Pub": "执行 flutter pub upgrade {name}（目标 {target}）。",
    "Hex": "执行 mix deps.update {name}（目标 {target}）。",
    "CRAN": '执行 install.packages("{name}") 并确认版本不低于 {target}。',
    "Hackage": "执行 cabal update && cabal build，把 {name} 约束到 >= {target}。",
    "Julia": '在 REPL 中执行 Pkg.update("{name}")（目标 {target}）。',
    "ConanCenter": "执行 conan install 并锁定 {name}/{target}。",
    "vcpkg": "执行 vcpkg upgrade {name}（目标 {target}）。",
    "GitHub Actions": "把该 Action 固定到修复后的 commit SHA，并同步 workflow。",
}


def _chunks(items: list[Package], size: int = 200) -> list[list[Package]]:
    return [items[index : index + size] for index in range(0, len(items), size)]


def _has_rating(detail: dict[str, Any]) -> bool:
    database = detail.get("database_specific") or {}
    if str(database.get("severity") or "").upper() in SEVERITY_MAP:
        return True
    for affected in detail.get("affected") or []:
        aff_sev = str((affected.get("database_specific") or {}).get("severity") or "").upper()
        if aff_sev in SEVERITY_MAP:
            return True
    return bool(detail.get("severity"))


def _severity_from_detail(detail: dict[str, Any]) -> str:
    database = detail.get("database_specific") or {}
    severity = str(database.get("severity") or "").upper()
    if severity in SEVERITY_MAP:
        return SEVERITY_MAP[severity]
    for affected in detail.get("affected") or []:
        aff_db = (affected.get("database_specific") or {})
        aff_sev = str(aff_db.get("severity") or "").upper()
        if aff_sev in SEVERITY_MAP:
            return SEVERITY_MAP[aff_sev]
    if detail.get("severity"):
        return "medium"
    return "medium"


def _fixed_versions(detail: dict[str, Any], package: Package) -> list[str]:
    fixed: list[str] = []
    for affected in detail.get("affected") or []:
        pkg = affected.get("package") or {}
        if pkg.get("name") and pkg.get("name") != package.ref:
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                value = event.get("fixed")
                if value and value not in fixed:
                    fixed.append(str(value))
    return fixed


def _detail(ctx: Context, vuln_id: str) -> dict[str, Any] | None:
    key = f"osv:detail:{vuln_id}"
    cached = ctx.cache.get(key, DETAIL_TTL)
    if isinstance(cached, dict):
        return cached
    try:
        data = http_json(f"{OSV_VULN}{vuln_id}", timeout=ctx.config.timeout, retries=1)
    except NetworkError:
        ctx.network_failed = True
        return None
    if isinstance(data, dict):
        ctx.cache.set(key, data)
        ctx.network_used = True
        return data
    return None


def _query_batch(ctx: Context, packages: list[Package]) -> dict[str, list[str]]:
    queries = [
        {"package": {"name": package.ref, "ecosystem": package.ecosystem}, "version": package.version}
        for package in packages
        if package.version
    ]
    try:
        data = http_json(OSV_QUERY, {"queries": queries}, timeout=ctx.config.timeout, retries=1)
    except NetworkError as exc:
        ctx.network_failed = True
        ctx.note(f"OSV 查询失败，漏洞数据不完整：{exc}")
        return {}
    ctx.network_used = True
    results: dict[str, list[str]] = {}
    if not isinstance(data, dict):
        return results
    for package, result in zip(packages, data.get("results") or []):
        vulns = (result or {}).get("vulns") or []
        if not vulns:
            ctx.cache.set(f"osv:query:{package.key}", [])
            continue
        ids = [str(v.get("id")) for v in vulns if v.get("id")]
        ctx.cache.set(f"osv:query:{package.key}", ids)
        results[package.key] = ids
    return results


def _is_commit_pinned(package: Package) -> bool:
    """A GitHub Action pinned to a 40-hex commit SHA.

    Pinning by SHA is the recommended practice and is exactly reproducible, but
    OSV cannot answer a SHA query (it knows tags/versions, not commits). Such a
    dependency is *pinned*, not "missing a version" — the lockfile remediation
    DEP-003 suggests does not apply, so it is reported as a note instead.
    """
    if package.ecosystem != "GitHub Actions":
        return False
    return bool(COMMIT_SHA.fullmatch(str(package.declared or package.version or "").strip()))


def scan(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    candidates: list[Package] = []
    unknown: list[Package] = []
    pinned: list[Package] = []

    for package in ctx.deps.packages:
        if not ecosystems.osv_supported(package.ecosystem):
            continue
        if package.locator.startswith(("url:", "file:", "git")):
            continue
        if not package.version:
            if _is_commit_pinned(package):
                pinned.append(package)
            else:
                unknown.append(package)
            continue
        candidates.append(package)

    ctx.unverified_packages = len(unknown) + len(pinned)
    # Only the default install is the package's own surface. A floating version
    # inside an optional extra or a dev group is resolved by whoever installs it
    # (consumer / CI), so it belongs in a note, not in a "generate a lockfile"
    # finding the package cannot act on.
    unknown_runtime = [package for package in unknown if package.scope == "runtime"]
    unknown_optional = [package for package in unknown if package.scope != "runtime"]
    if unknown_runtime:
        sample = "、".join(f"{p.name}" for p in unknown_runtime[:8])
        findings.append(
            make_finding(
                "DEP-003",
                "dependency",
                "info",
                "有依赖无法确定版本，漏洞检查覆盖不到",
                f"共 {len(unknown_runtime)} 个依赖只声明了版本范围（例如 `>=1.2`），没有锁文件就无法知道实际装了什么。"
                f"示例：{sample}。",
                remediation="生成并提交锁文件（pip-compile / npm install / cargo generate-lockfile），让版本可复现。",
                detail={"count": len(unknown_runtime)},
            )
        )
    if unknown_optional:
        sample = "、".join(f"{p.name}" for p in unknown_optional[:8])
        ctx.note(
            f"{len(unknown_optional)} 个 dev / 可选依赖只声明了版本范围（{sample}）："
            "这类依赖由使用方或 CI 的解析器决定实际版本，本次未做漏洞查询。"
        )
    if pinned:
        sample = "、".join(package.name for package in pinned[:6])
        suffix = "…" if len(pinned) > 6 else ""
        ctx.note(
            f"{len(pinned)} 个 GitHub Action 按 commit SHA 固定（{sample}{suffix}）："
            "OSV 只接受版本号、无法按 SHA 查询，因此这几个未做漏洞查询；"
            "SHA 固定本身是可复现的推荐做法，可用 Dependabot 跟踪更新。"
        )

    if ctx.offline or not ctx.config.network_enabled:
        if ctx.deps.packages:
            ctx.note(f"离线模式：{len(candidates)} 个依赖未做漏洞查询")
        return findings

    if not candidates:
        return findings

    ids_by_package: dict[str, list[str]] = {}
    pending: list[Package] = []
    cache_hits = 0
    for package in candidates:
        cached = ctx.cache.get(f"osv:query:{package.key}", QUERY_TTL)
        if isinstance(cached, list):
            ids_by_package[package.key] = [str(item) for item in cached]
            cache_hits += 1
        else:
            pending.append(package)
    for chunk in _chunks(pending):
        ids_by_package.update(_query_batch(ctx, chunk))

    if cache_hits and not ctx.network_used and not ctx.offline and ctx.config.network_enabled:
        ctx.note(f"漏洞数据来自本地缓存（{cache_hits} 个依赖，查询缓存 6 小时），本次未联网校验")

    if not ids_by_package and not ctx.network_used:
        ctx.note("漏洞数据不可用，本次结论不包含依赖漏洞")
        return findings

    unique_ids: list[str] = []
    for ids in ids_by_package.values():
        for vuln_id in ids:
            if vuln_id not in unique_ids:
                unique_ids.append(vuln_id)

    details: dict[str, dict[str, Any]] = {}
    if unique_ids:
        pending = unique_ids[:MAX_DETAIL_FETCH]
        with ThreadPoolExecutor(max_workers=6) as pool:
            for vuln_id, detail in zip(pending, pool.map(lambda vid: _detail(ctx, vid), pending)):
                if detail is not None:
                    details[vuln_id] = detail
        if len(unique_ids) > MAX_DETAIL_FETCH:
            ctx.note(f"公告数量过多，仅获取前 {MAX_DETAIL_FETCH} 条的详情")

    package_by_key = {package.key: package for package in candidates}
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for package_key, ids in ids_by_package.items():
        package = package_by_key.get(package_key)
        if package is None:
            continue
        known: list[dict[str, Any]] = []
        unknown_ids: list[str] = []
        for vuln_id in ids:
            detail = details.get(vuln_id)
            if detail is None:
                unknown_ids.append(vuln_id)
                continue
            severity = _severity_from_detail(detail)
            if package.scope == "dev" and severity in ("critical", "high"):
                severity = "medium"
            summary = str(detail.get("summary") or detail.get("details") or "").strip().split("\n")[0][:240]
            aliases = [alias for alias in (detail.get("aliases") or []) if str(alias).startswith("CVE")]
            known.append(
                {
                    "id": vuln_id,
                    "severity": severity,
                    "aliases": aliases,
                    "fixed": _fixed_versions(detail, package),
                    "summary": summary,
                    "rating": _has_rating(detail),
                }
            )

        if known:
            # One dependency with eight advisories is ONE upgrade decision, not
            # eight findings: aggregate per package so the top of the report is
            # not a single package repeated, while keeping every advisory id.
            known.sort(key=lambda item: (order.get(item["severity"], 9), item["id"]))
            worst = min(known, key=lambda item: order.get(item["severity"], 9))["severity"]
            fixed_all: list[str] = []
            for item in known:
                for version in item["fixed"]:
                    if version not in fixed_all:
                        fixed_all.append(version)
            fixed_text = "、".join(fixed_all[:3]) if fixed_all else "公告未给出明确修复版本"
            if len(known) == 1:
                single = known[0]
                title = f"{package.name} {package.version} 存在已知漏洞（{single['id']}）"
                message = f"{single['summary']} 受影响版本：{package.version}；修复版本：{fixed_text}。"
            else:
                listing = "、".join(
                    f"{item['id']}{('/' + '/'.join(item['aliases'])) if item['aliases'] else ''}"
                    for item in known[:6]
                )
                more = f" 等 {len(known)} 条" if len(known) > 6 else ""
                title = f"{package.name} {package.version} 存在 {len(known)} 个已知漏洞"
                message = (
                    f"同一版本命中 {len(known)} 条公告，其中最高为 {worst}：{listing}{more}。"
                    f"受影响版本：{package.version}；建议直接升到 {fixed_text}。"
                )
            unrated = [item["id"] for item in known if not item["rating"]]
            if unrated:
                message += "（部分公告没有严重度评级，按中危处理：" + "、".join(unrated[:3]) + "）"
            findings.append(
                make_finding(
                    "DEP-001",
                    "dependency",
                    worst,
                    title,
                    message,
                    path=_manifest_path(package),
                    evidence=f"{package.name}=={package.version}",
                    remediation=_remediation(package, fixed_all),
                    reference=f"https://osv.dev/vulnerability/{known[0]['id']}",
                    source="osv",
                    detail={
                        "package": package.name,
                        "ecosystem": package.ecosystem,
                        "version": package.version,
                        "scope": package.scope,
                        "count": len(known),
                        "advisory": known[0]["id"],
                        "advisories": [
                            {
                                "id": item["id"],
                                "severity": item["severity"],
                                "aliases": item["aliases"],
                                "fixed": item["fixed"],
                            }
                            for item in known
                        ],
                        "aliases": known[0]["aliases"],
                        "fixed": fixed_all,
                    },
                )
            )

        if unknown_ids:
            findings.append(
                make_finding(
                    "DEP-004",
                    "dependency",
                    "medium",
                    f"{package.name} 命中 {len(unknown_ids)} 条安全公告但未获取详情",
                    "这些公告对应的版本存在风险，但未能获取详情（网络或限流），请手动确认受影响范围："
                    + "、".join(unknown_ids[:6])
                    + ("…" if len(unknown_ids) > 6 else ""),
                    path=_manifest_path(package),
                    evidence=f"{package.name} {package.version}",
                    remediation=f"打开 https://osv.dev/vulnerability/{unknown_ids[0]} 查看修复版本并升级。",
                    reference=f"https://osv.dev/vulnerability/{unknown_ids[0]}",
                    source="osv",
                    detail={"package": package.name, "version": package.version, "ids": unknown_ids},
                )
            )
    return findings


def _manifest_path(package: Package) -> str:
    return package.manifest.split(";")[0] if package.manifest else ""


def _remediation(package: Package, fixed: list[str]) -> str:
    if not fixed:
        return f"确认 {package.name} 是否仍在使用；无修复版本时考虑替换等价库或隔离调用点。"
    target = fixed[-1]
    template = REMEDIATION.get(package.ecosystem)
    if template:
        return template.format(name=package.name, target=target)
    return f"升级 {package.name} 到 {target}。"
