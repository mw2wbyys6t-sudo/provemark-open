from __future__ import annotations

import json
import re
import tomllib
import urllib.parse
from concurrent.futures import ThreadPoolExecutor

from ..models import Finding, Package
from ..net import NetworkError, http_json, http_text
from ..rules import license_compat as compat
from ..rules import license_data as data
from .. import ecosystems
from .base import Context, make_finding

DEPS_DEV = "https://api.deps.dev/v3alpha/systems/{system}/packages/{name}/versions/{version}"
LICENSE_TTL = 7 * 24 * 3600
MAX_FINDINGS = 150
LICENSE_FILE_NAMES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "LICENCE")


def _license_file(ctx: Context) -> tuple[str, str]:
    for name in LICENSE_FILE_NAMES:
        path = ctx.root / name
        if path.is_file():
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            return data.detect_from_text(text), name
    return "", ""


def _manifest_license(ctx: Context) -> tuple[str, str]:
    for info in ctx.files:
        if info.rel.count("/") > 0:
            continue
        if info.path.name == "package.json":
            try:
                payload = json.loads(info.text())
            except json.JSONDecodeError:
                continue
            value = payload.get("license")
            if isinstance(value, dict):
                value = value.get("type")
            if isinstance(value, str) and value.strip():
                return data.normalize_spdx(value), "package.json"
        if info.path.name == "Cargo.toml":
            try:
                payload = tomllib.loads(info.text())
            except tomllib.TOMLDecodeError:
                continue
            value = (payload.get("package") or {}).get("license")
            if isinstance(value, str) and value.strip():
                return data.normalize_spdx(value), "Cargo.toml"
        if info.path.name == "pyproject.toml":
            try:
                payload = tomllib.loads(info.text())
            except tomllib.TOMLDecodeError:
                continue
            value = (payload.get("project") or {}).get("license")
            if isinstance(value, dict):
                value = value.get("text") or value.get("file")
            if isinstance(value, str) and value.strip():
                return data.normalize_spdx(value), "pyproject.toml"
            poetry = ((payload.get("tool") or {}).get("poetry") or {}).get("license")
            if isinstance(poetry, str) and poetry.strip():
                return data.normalize_spdx(poetry), "pyproject.toml"
    return "", ""


def _pypi_license(ctx: Context, package: Package) -> str:
    payload = http_json(
        f"https://pypi.org/pypi/{urllib.parse.quote(package.ref)}/{urllib.parse.quote(package.version)}/json",
        timeout=ctx.config.timeout,
        retries=0,
    )
    if not isinstance(payload, dict):
        return ""
    info = payload.get("info") or {}
    result = str(info.get("license") or "")
    if not result or len(result) > 60:
        for classifier in info.get("classifiers") or []:
            if isinstance(classifier, str) and classifier.startswith("License ::"):
                return classifier
    return result


def _npm_license(ctx: Context, package: Package) -> str:
    payload = http_json(
        f"https://registry.npmjs.org/{urllib.parse.quote(package.ref, safe='@/')}/"
        f"{urllib.parse.quote(package.version)}",
        timeout=ctx.config.timeout,
        retries=0,
    )
    if not isinstance(payload, dict):
        return ""
    value = payload.get("license")
    if isinstance(value, dict):
        value = value.get("type")
    return str(value or "")


def _crates_license(ctx: Context, package: Package) -> str:
    payload = http_json(
        f"https://crates.io/api/v1/crates/{urllib.parse.quote(package.ref)}/"
        f"{urllib.parse.quote(package.version)}",
        timeout=ctx.config.timeout,
        retries=0,
    )
    if not isinstance(payload, dict):
        return ""
    return str((payload.get("version") or {}).get("license") or "")


def _packagist_license(ctx: Context, package: Package) -> str:
    payload = http_json(
        f"https://repo.packagist.org/p2/{package.ref}.json", timeout=ctx.config.timeout, retries=0
    )
    if not isinstance(payload, dict):
        return ""
    versions = (payload.get("packages") or {}).get(package.ref) or []
    target = package.version.lstrip("v")
    for item in versions:
        if not isinstance(item, dict):
            continue
        if str(item.get("version") or "").lstrip("v") != target:
            continue
        licenses = item.get("license") or []
        return " OR ".join(str(entry) for entry in licenses if entry)
    return ""


def _rubygems_license(ctx: Context, package: Package) -> str:
    payload = http_json(
        f"https://rubygems.org/api/v1/versions/{urllib.parse.quote(package.ref)}.json",
        timeout=ctx.config.timeout,
        retries=0,
    )
    if not isinstance(payload, list):
        return ""
    for item in payload:
        if not isinstance(item, dict) or str(item.get("number") or "") != package.version:
            continue
        licenses = item.get("licenses") or []
        return " OR ".join(str(entry) for entry in licenses if entry)
    return ""


def _hex_license(ctx: Context, package: Package) -> str:
    payload = http_json(
        f"https://hex.pm/api/packages/{urllib.parse.quote(package.ref)}",
        timeout=ctx.config.timeout,
        retries=0,
    )
    if not isinstance(payload, dict):
        return ""
    licenses = (payload.get("meta") or {}).get("licenses") or []
    return " OR ".join(str(entry) for entry in licenses if entry)


def _cran_license(ctx: Context, package: Package) -> str:
    text = http_text(
        f"https://cran.r-project.org/web/packages/{urllib.parse.quote(package.ref)}/DESCRIPTION",
        timeout=ctx.config.timeout,
    )
    for line in text.splitlines():
        if line.lower().startswith("license:"):
            return line.split(":", 1)[1].strip()
    return ""


def _hackage_license(ctx: Context, package: Package) -> str:
    name = package.ref
    version = package.version
    text = http_text(
        f"https://hackage.haskell.org/package/{urllib.parse.quote(name)}-{urllib.parse.quote(version)}/"
        f"{urllib.parse.quote(name)}.cabal",
        timeout=ctx.config.timeout,
    )
    for line in text.splitlines():
        if line.lower().startswith("license:"):
            return line.split(":", 1)[1].strip()
    return ""


def _maven_license(ctx: Context, package: Package) -> str:
    group, _, artifact = package.ref.partition(":")
    if not artifact:
        return ""
    group_path = group.replace(".", "/")
    url = (
        f"https://repo1.maven.org/maven2/{group_path}/{artifact}/{package.version}/"
        f"{artifact}-{package.version}.pom"
    )
    text = http_text(url, timeout=ctx.config.timeout)
    names = re.findall(r"<license>.*?<name>([^<]+)</name>", text, re.S)
    return " OR ".join(dict.fromkeys(name.strip() for name in names if name.strip()))


def _raw_license_url(url: str) -> str:
    target = url.replace("http://", "https://", 1)
    match = re.match(r"https://github\.com/([^/]+)/([^/]+)/blob/(.+)", target)
    if match:
        return (
            f"https://raw.githubusercontent.com/{match.group(1)}/{match.group(2)}/"
            f"{match.group(3)}"
        )
    return target


def _nuget_license(ctx: Context, package: Package) -> str:
    name = package.ref.lower()
    url = f"https://api.nuget.org/v3-flatcontainer/{name}/{package.version}/{name}.nuspec"
    text = http_text(url, timeout=ctx.config.timeout)
    expression = re.search(r'<license[^>]*type="expression"[^>]*>([^<]+)</license>', text)
    if expression:
        return expression.group(1).strip()
    license_url = re.search(r"<licenseUrl>([^<]+)</licenseUrl>", text)
    if not license_url:
        return ""
    target = license_url.group(1).strip()
    if "licenses.nuget.org/" in target:
        return target.rstrip("/").rsplit("/", 1)[-1]
    osi = re.search(r"opensource\.org/licenses/([a-z0-9.\-]+?)(?:-license)?(?:\.php|\.html)?/?$", target.lower())
    if osi:
        return osi.group(1).upper()
    if not target.lower().startswith("http"):
        return ""
    try:
        license_text = http_text(_raw_license_url(target), timeout=ctx.config.timeout)
    except NetworkError:
        return ""
    detected = data.detect_from_text(license_text[:200000])
    if detected:
        return detected
    plain = re.sub(r"<[^>]+>", " ", license_text)
    return data.detect_from_text(plain[:200000])


REGISTRY_FETCHERS = {
    "pypi": _pypi_license,
    "npm": _npm_license,
    "crates": _crates_license,
    "packagist": _packagist_license,
    "rubygems": _rubygems_license,
    "hex": _hex_license,
    "cran": _cran_license,
    "hackage": _hackage_license,
    "maven": _maven_license,
    "nuget": _nuget_license,
}


def _registry_license(ctx: Context, package: Package, *, allow_network: bool = True) -> str:
    kind = ecosystems.registry_kind(package.ecosystem)
    if not kind or kind not in REGISTRY_FETCHERS:
        return ""
    cache_key = f"lic:registry:{package.ecosystem}:{package.ref}@{package.version}"
    cached = ctx.cache.get(cache_key, LICENSE_TTL)
    if isinstance(cached, str):
        return cached
    if not allow_network:
        return ""
    try:
        result = REGISTRY_FETCHERS[kind](ctx, package)
    except NetworkError:
        ctx.network_failed = True
        return ""
    ctx.network_used = True
    if result:
        ctx.cache.set(cache_key, result)
    return result


def _package_license(ctx: Context, package: Package, *, allow_network: bool = True) -> str:
    if not package.version:
        return ""
    system = ecosystems.depsdev_system(package.ecosystem)
    if not system:
        return _registry_license(ctx, package, allow_network=allow_network)
    cache_key = f"lic:depsdev:{package.key}"
    cached = ctx.cache.get(cache_key, LICENSE_TTL)
    if isinstance(cached, str):
        return cached
    if not allow_network:
        return ""
    version = package.version
    if package.ecosystem == "Go" and not version.startswith("v"):
        version = f"v{version}"
    url = DEPS_DEV.format(
        system=system,
        name=urllib.parse.quote(package.ref, safe=""),
        version=urllib.parse.quote(version, safe=""),
    )
    try:
        payload = http_json(url, timeout=ctx.config.timeout, retries=0)
    except NetworkError:
        return _registry_license(ctx, package, allow_network=allow_network)
    if not isinstance(payload, dict):
        return _registry_license(ctx, package, allow_network=allow_network)
    ctx.network_used = True
    licenses = [str(item) for item in (payload.get("licenses") or []) if item]
    meaningful = [
        item for item in licenses if item.strip().lower() not in ("non-standard", "unknown", "noassertion")
    ]
    result = " OR ".join(meaningful)
    if not result:
        result = _registry_license(ctx, package, allow_network=allow_network)
    if result:
        ctx.cache.set(cache_key, result)
    return result


def _manifest_of(package: Package) -> str:
    return package.manifest.split(";")[0] if package.manifest else ""


def _severity_for(status: str, scope: str, policy) -> str:
    if status == "deny":
        return "high" if scope != "dev" else "medium"
    if status == "unknown":
        return policy.unknown if scope != "dev" else "low"
    if status == "warn":
        return "low" if scope != "dev" else "info"
    return "info"


def _project_identity(ctx: Context) -> tuple[str, str, str, str, str]:
    file_spdx, file_name = _license_file(ctx)
    manifest_spdx, manifest_source = _manifest_license(ctx)
    declared = data.normalize_spdx(ctx.config.project_license) or manifest_spdx
    return file_spdx, file_name, manifest_spdx, manifest_source, declared


def _project_findings(ctx: Context, identity: tuple[str, str, str, str, str]) -> list[Finding]:
    findings: list[Finding] = []
    file_spdx, file_name, _manifest_spdx, manifest_source, declared = identity

    if file_name and not file_spdx:
        findings.append(
            make_finding(
                "LIC-003",
                "license",
                "medium",
                "许可证文件无法自动识别",
                f"{file_name} 存在，但内容不匹配任何常见许可证模板；托管平台的许可证检查通常也会判为未知。",
                path=file_name,
                remediation="用 SPDX 标准文本替换，或在清单中显式声明 license 字段。",
                reference="https://spdx.org/licenses/",
            )
        )
    if file_spdx and declared and file_spdx.split("-")[0] != declared.split("-")[0]:
        findings.append(
            make_finding(
                "LIC-002",
                "license",
                "medium",
                "许可证声明与 LICENSE 文件不一致",
                f"{manifest_source or '配置'} 声明为 {declared}，但 {file_name} 内容是 {file_spdx}。"
                "两者不一致时，下游无法判断该按哪个执行。",
                path=file_name,
                remediation="统一为同一个 SPDX 标识，并同步 README 中的许可证说明。",
                detail={"declared": declared, "detected": file_spdx},
            )
        )
    if file_spdx and ctx.config.allowed_licenses_project:
        if file_spdx not in ctx.config.allowed_licenses_project:
            findings.append(
                make_finding(
                    "LIC-007",
                    "license",
                    "low",
                    "项目自身许可证不在团队白名单内",
                    f"项目使用 {file_spdx}，但策略中的 project.allowed_licenses 未包含它。",
                    path=file_name or "",
                    remediation="确认这是有意选择；若团队统一使用宽松许可证，请调整 LICENSE。",
                )
            )
    return findings


def resolve_licenses(ctx: Context, targets: list[Package] | None = None) -> dict[str, str]:
    if targets is None:
        targets = [
            package
            for package in ctx.deps.packages
            if package.version and ecosystems.license_lookup_supported(package.ecosystem)
        ]
    resolved: dict[str, str] = {}
    if ctx.offline or not ctx.config.network_enabled:
        for package in targets:
            expression = _package_license(ctx, package, allow_network=False)
            if expression:
                resolved[package.key] = expression
        missing = len(targets) - len(resolved)
        if missing:
            ctx.note(f"离线模式：{missing} 个依赖没有缓存的许可证数据，本次不判定")
    else:
        with ThreadPoolExecutor(max_workers=12) as pool:
            for package, expression in zip(targets, pool.map(lambda p: _package_license(ctx, p), targets)):
                if expression:
                    resolved[package.key] = expression
    ctx.license_resolved.update(resolved)
    return resolved


def scan(ctx: Context) -> list[Finding]:
    identity = _project_identity(ctx)
    findings: list[Finding] = _project_findings(ctx, identity)
    project_spdx = identity[4] or identity[0]
    matrix_active = bool(project_spdx) and compat.compat_class(project_spdx) != "unknown"

    targets = [
        package
        for package in ctx.deps.packages
        if package.version and ecosystems.license_lookup_supported(package.ecosystem)
    ]
    uncovered: dict[str, int] = {}
    for package in ctx.deps.packages:
        if package.version and not ecosystems.license_lookup_supported(package.ecosystem):
            uncovered[package.ecosystem] = uncovered.get(package.ecosystem, 0) + 1
    for ecosystem, count in sorted(uncovered.items()):
        reason = ecosystems.get(ecosystem).note or "该生态暂无自动许可证数据源"
        ctx.note(f"{ecosystems.label_of(ecosystem)}：{reason}，{count} 个依赖的许可证需人工确认")

    if not targets:
        return findings

    policy = ctx.config.license_policy
    resolved = resolve_licenses(ctx, targets)

    known: list[tuple[Package, str, str, list[str]]] = []
    evaluated: list[tuple[Package, str, str, list[str]]] = []
    unknown_by_ecosystem: dict[str, list[Package]] = {}
    for package in targets:
        if package.name in policy.exceptions:
            continue
        expression = resolved.get(package.key, "")
        if not expression and (ctx.offline or not ctx.config.network_enabled):
            continue
        status, effective = data.evaluate(expression, policy)
        if status == "unknown":
            unknown_by_ecosystem.setdefault(package.ecosystem, []).append(package)
            continue
        evaluated.append((package, status, expression, effective))
        if status != "allow":
            known.append((package, status, expression, effective))

    for ecosystem, packages in sorted(unknown_by_ecosystem.items()):
        sample = "、".join(f"{p.name}@{p.version}" for p in packages[:8])
        all_dev = all(p.scope == "dev" for p in packages)
        findings.append(
            make_finding(
                "LIC-005",
                "license",
                "low" if all_dev else policy.unknown,
                f"{len(packages)} 个 {ecosystem} 依赖的许可证无法确定",
                f"未能从 deps.dev / 注册表获取这些依赖的许可证：{sample}"
                + ("…" if len(packages) > 8 else "")
                + "。未知许可证等于没有明确授权，商用前需要人工确认。",
                path=_manifest_of(packages[0]),
                evidence=f"{len(packages)} 个 {ecosystem} 包",
                remediation="打开依赖仓库确认 LICENSE；确认不了就替换，或在 license.exceptions 中登记已知结论。",
                reference="https://spdx.org/licenses/",
                source="deps.dev",
                detail={
                    "ecosystem": ecosystem,
                    "count": len(packages),
                    "packages": [f"{p.name}@{p.version}" for p in packages[:60]],
                },
            )
        )

    verdicts: dict[str, tuple[str, str]] = {}
    if matrix_active:
        for package, _status, expression, _effective in evaluated:
            verdicts[package.key] = compat.verdict(project_spdx, expression)

    pair_groups: dict[tuple[str, str], list[Package]] = {}
    matrix_emitted = 0
    for package, status, expression, _effective in evaluated:
        if not matrix_active or status == "deny":
            continue
        verdict, reason = verdicts.get(package.key, (compat.UNKNOWN, ""))
        if verdict == compat.INCOMPATIBLE:
            if matrix_emitted >= MAX_FINDINGS:
                break
            matrix_emitted += 1
            findings.append(
                make_finding(
                    "LIC-009",
                    "license",
                    "medium" if package.scope == "dev" else "high",
                    f"{package.name} 的 {expression} 与项目许可证 {project_spdx} 冲突",
                    f"{reason}；当前项目以 {project_spdx} 发布，引入该依赖会改变分发义务。",
                    path=_manifest_of(package),
                    evidence=f"{package.name} {package.version or package.declared}".strip(),
                    remediation=(
                        "替换为兼容许可证的依赖；或调整项目许可证；"
                        "或在 license.exceptions 登记并说明分发方式。"
                    ),
                    reference="https://spdx.org/licenses/",
                    source="deps.dev",
                    confidence=0.85,
                    detail={
                        "package": package.name,
                        "version": package.version,
                        "dependency_license": expression,
                        "project_license": project_spdx,
                        "verdict": compat.INCOMPATIBLE,
                        "reason": reason,
                    },
                )
            )
        elif verdict == compat.UNKNOWN:
            pair_groups.setdefault((project_spdx, expression or "UNKNOWN"), []).append(package)

    if pair_groups:
        pairs = []
        for (project, dependency), packages in list(pair_groups.items())[:5]:
            pairs.append(
                {
                    "project": project,
                    "dependency": dependency,
                    "packages": [f"{item.name}@{item.version}" for item in packages[:10]],
                }
            )
        summary = "、".join(f"{item['project']} × {item['dependency']}" for item in pairs)
        findings.append(
            make_finding(
                "LIC-010",
                "license",
                "info",
                f"有 {len(pairs)} 组许可证组合无法自动判定",
                f"这些组合不在兼容矩阵内，需要人工确认能否一起分发：{summary}。",
                remediation="查阅两份许可证原文，确认分发义务；必要时咨询法务。",
                reference="https://spdx.org/licenses/",
                confidence=0.5,
                detail={"pairs": pairs},
            )
        )

    known.sort(key=lambda item: (item[1] != "deny", item[0].scope == "dev", item[0].name))
    for index, (package, status, expression, effective) in enumerate(known):
        if index >= MAX_FINDINGS:
            findings.append(
                make_finding(
                    "LIC-008",
                    "license",
                    "info",
                    f"还有 {len(known) - MAX_FINDINGS} 个依赖的许可证问题未逐条列出",
                    "依赖树较大时报告只列出最需要处理的部分，完整清单见 JSON 输出。",
                    remediation="先用 `--format json` 导出完整列表，再按 deny → unknown 的顺序处理。",
                    detail={"remaining": len(known) - MAX_FINDINGS},
                )
            )
            break
        license_text = expression or "UNKNOWN"
        family = data.family_of(effective[0]) if effective else "unknown"
        severity = _severity_for(status, package.scope, policy)
        verdict, reason = verdicts.get(package.key, (compat.UNKNOWN, ""))
        if status == "deny":
            rule_id = "LIC-004"
            if verdict == compat.OK:
                severity = "info"
                title = f"{package.name} 使用 {license_text}（策略禁止，但与项目许可证兼容）"
                message = (
                    f"{data.explain(effective[0] if effective else license_text)}"
                    f"项目本身以 {project_spdx} 发布，这条属于策略层面的禁止，两者在组合上是兼容的。"
                )
                remediation = (
                    f"若整个项目确实以 {project_spdx} 发布，可把 {license_text} 加入 license.allow；"
                    "否则保留当前策略。"
                )
            else:
                title = f"{package.name} 使用 {license_text}，与当前项目许可证冲突"
                message = (
                    f"{data.explain(effective[0] if effective else license_text)}"
                    + (f"{reason}；" if verdict == compat.INCOMPATIBLE else "")
                    + f"你的项目以 {project_spdx or '宽松许可证'} 发布时，引入该依赖会改变分发义务。"
                )
                remediation = (
                    f"优先替换为宽松许可证的等价实现；若确实需要，把项目整体切换为兼容许可证，"
                    f"或在策略中登记例外（license.exceptions）并说明分发方式。"
                )
        elif status == "warn":
            rule_id = "LIC-006"
            title = f"{package.name} 使用 {license_text}（弱传染）"
            message = data.explain(effective[0] if effective else license_text)
            remediation = "保留许可证与 NOTICE 声明；如果修改了该依赖的源码，需要公开被修改的文件。"
        else:
            rule_id = "LIC-005"
            title = f"{package.name} 的许可证无法确定"
            message = (
                f"未能从 deps.dev / 注册表获取 {package.name} {package.version or ''} 的许可证。"
                "未知许可证等于没有明确授权，商用前必须人工确认。"
            )
            remediation = "打开该包的仓库确认 LICENSE；若确实没有许可证，替换或联系作者。"
        findings.append(
            make_finding(
                rule_id,
                "license",
                severity,
                title,
                message,
                path=(package.manifest.split(";")[0] if package.manifest else ""),
                evidence=f"{package.name} {package.version or package.declared}".strip(),
                remediation=remediation,
                reference="https://spdx.org/licenses/",
                source="deps.dev",
                detail={
                    "package": package.name,
                    "version": package.version,
                    "licenses": effective or [license_text],
                    "family": family,
                    "status": status,
                    "scope": package.scope,
                },
            )
        )
    return findings
