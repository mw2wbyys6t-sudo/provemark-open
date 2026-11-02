from __future__ import annotations

import json
import os
import re
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from .. import ecosystems, yaml_lite
from ..models import Finding, Package
from ..rules import license_data as license_rules
from .base import Context, make_finding

FOSSA_CONFIG_NAMES = (".fossa.yml", ".fossa.yaml")
FOSSA_DEPS_NAMES = ("fossa-deps.yml", "fossa-deps.yaml", "fossa-deps.json")
SBOM_NAMES = ("sbom.json", "bom.json", "fossa-sbom.json", "cyclonedx.json", "cyclonedx-1.json")
SBOM_MAX_BYTES = 20 * 1024 * 1024
CI_PREFIXES = (".github/workflows/",)
CI_FILES = (".gitlab-ci.yml", "azure-pipelines.yml", ".circleci/config.yml", "Jenkinsfile", ".travis.yml")
VENDOR_NAMES = {
    "vendor",
    "vendored",
    "third_party",
    "third-party",
    "thirdparty",
    "external",
    "bower_components",
    "jspm_packages",
    "node_modules",
    "pods",
    "carthage",
}
FOSSA_DEP_TYPES = {
    "bower",
    "cargo",
    "carthage",
    "composer",
    "cpan",
    "renv",
    "gem",
    "git",
    "go",
    "hackage",
    "hex",
    "maven",
    "npm",
    "nuget",
    "paket",
    "pub",
    "pypi",
    "cocoapods",
    "swift",
    "url",
    "apk",
    "deb",
    "rpm-generic",
}
MAX_SAMPLES = 12


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _load_structured(path: Path) -> tuple[Any, str]:
    if path.suffix.lower() == ".json":
        try:
            return json.loads(_read_text(path)), ""
        except json.JSONDecodeError as exc:
            return None, f"JSON 解析失败：{exc.msg}"
    try:
        return yaml_lite.load(_read_text(path)), ""
    except Exception as exc:  # noqa: BLE001 - 极简 YAML 解析失败时降级
        return None, f"YAML 解析失败：{type(exc).__name__}"


def _find(root: Path, names: tuple[str, ...]) -> Path | None:
    for name in names:
        candidate = root / name
        if candidate.is_file():
            return candidate
    return None


def _rel(path: Path, root: Path) -> str:
    return ecosystems.rel_path(path, root)


def _as_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    return []


def _section(config: dict, *keys: str) -> dict:
    current: Any = config
    for key in keys:
        if not isinstance(current, dict):
            return {}
        current = current.get(key)
    return current if isinstance(current, dict) else {}


def _patterns(config: dict) -> list[str]:
    patterns = _as_list(_section(config, "paths").get("exclude"))
    patterns += _as_list(_section(config, "targets").get("exclude"))
    return [str(item) for item in patterns]


def _covers(patterns: list[str], target: str) -> bool:
    normalized = target.strip("/")
    for pattern in patterns:
        cleaned = pattern.strip().strip("/")
        if not cleaned:
            continue
        if cleaned == normalized or normalized.startswith(cleaned + "/"):
            return True
        if fnmatch(normalized, cleaned) or fnmatch(normalized + "/", cleaned):
            return True
    return False


def vendor_dirs(root: Path, limit: int = 20000) -> list[str]:
    found: list[str] = []
    visited = 0
    for dirpath, dirnames, _ in os.walk(root):
        visited += 1
        if visited > limit:
            break
        current = Path(dirpath)
        rel_dir = current.relative_to(root).as_posix()
        depth = 0 if rel_dir == "." else rel_dir.count("/") + 1
        dirnames[:] = [name for name in dirnames if name not in (".git", ".hg", ".svn")]
        if depth >= 4:
            dirnames[:] = []
            continue
        keep: list[str] = []
        for name in dirnames:
            lowered = name.lower()
            if lowered in VENDOR_NAMES:
                rel = name if rel_dir == "." else f"{rel_dir}/{name}"
                found.append(rel)
                continue
            keep.append(name)
        dirnames[:] = keep
    return found


def _check_config_version(path: Path, root: Path, config: dict) -> list[Finding]:
    version = config.get("version")
    if version == 3 or str(version) == "3":
        return []
    return [
        make_finding(
            "FOS-005",
            "hygiene",
            "low",
            "FOSSA 配置文件版本不是 3",
            f"{_rel(path, root)} 的 version 为 {version!r}。FOSSA CLI 当前按 v3 结构解析配置，"
            "旧结构里的键名与之不同，可能被静默忽略（例如你以为排除了目录，实际没有生效）。",
            path=_rel(path, root),
            remediation="迁移到 `version: 3`，并按新结构重命名 `cli` / `paths` / `targets` / `vendoredDependencies`。",
            reference="https://docs.fossa.com/docs/cli/references/files/fossa-yml",
        )
    ]


def _check_scope(ctx: Context, path: Path, config: dict) -> list[Finding]:
    findings: list[Finding] = []
    patterns = _patterns(config)
    dirs = sorted(
        {
            ecosystems.rel_path(manifest, ctx.root).rsplit("/", 1)[0]
            for manifest in ctx.deps.manifests
            if "/" in ecosystems.rel_path(manifest, ctx.root)
        }
    )
    only = _as_list(_section(config, "paths").get("only")) + _as_list(
        _section(config, "targets").get("only")
    )
    only_paths = [
        str(item).strip().strip("/")
        for item in only
        if isinstance(item, (str, int)) and str(item).strip()
    ]
    if len(dirs) >= 3 and not only:
        sample = "、".join(dirs[:5]) + ("…" if len(dirs) > 5 else "")
        findings.append(
            make_finding(
                "FOS-001",
                "license",
                "medium",
                "多包仓库未限制 FOSSA 分析范围",
                f"检测到 {len(dirs)} 个包含依赖清单的目录（{sample}），但 .fossa.yml 没有 "
                "`paths.only` / `targets.only`。FOSSA 会把它们全部并进同一个项目，"
                "测试样本、示例工程也会进入许可证统计，导致报告条目虚高且难以定位。",
                path=_rel(path, ctx.root),
                evidence=f"{len(dirs)} 个清单目录",
                remediation=(
                    "在 `.fossa.yml` 中限定范围，例如：\n"
                    "```yaml\nversion: 3\npaths:\n  only:\n"
                    + "".join(f"    - {name}/\n" for name in dirs[:5])
                    + "```"
                ),
                detail={"directories": dirs[:40]},
            )
        )

    vendors = vendor_dirs(ctx.root)

    def _inside_only(name: str) -> bool:
        if not only_paths:
            return True
        return any(name == base or name.startswith(base + "/") for base in only_paths)

    uncovered = [
        name for name in vendors if not _covers(patterns, name) and _inside_only(name)
    ]
    if uncovered:
        sample = "、".join(uncovered[:5]) + ("…" if len(uncovered) > 5 else "")
        findings.append(
            make_finding(
                "FOS-002",
                "license",
                "medium",
                "vendored / 依赖目录没有从 FOSSA 扫描中排除",
                f"仓库内存在 {len(uncovered)} 个第三方代码目录（{sample}），但 .fossa.yml 的 "
                "`paths.exclude` 没有覆盖它们。这些目录里通常自带清单文件，FOSSA 会把其中的包"
                "再分析一遍，同一个依赖以不同来源重复出现在许可证报告里；开启第一方扫描后，"
                "里面的 LICENSE 还会被算进本项目。",
                path=_rel(path, ctx.root),
                evidence=sample,
                remediation=(
                    "把它们加入排除列表，或改用 vendored-dependencies 显式声明：\n"
                    "```yaml\nversion: 3\npaths:\n  exclude:\n"
                    + "".join(f"    - {name}/\n" for name in uncovered[:5])
                    + "```"
                ),
                detail={"directories": uncovered[:40]},
            )
        )
    return findings


def _check_deps_file(ctx: Context, path: Path) -> list[Finding]:
    data, error = _load_structured(path)
    rel = _rel(path, ctx.root)
    if error:
        return [
            make_finding(
                "FOS-003",
                "supply",
                "medium",
                "fossa-deps 文件无法解析",
                f"{rel} 解析失败（{error}）。FOSSA 会静默跳过整个文件，手工声明的依赖不会被扫描。",
                path=rel,
                remediation="修正缩进与引号；版本号请加引号（如 `version: \"1.0\"`），否则 YAML 会当成数字。",
                reference="https://docs.fossa.com/docs/cli/references/files/fossa-deps",
            )
        ]
    if not isinstance(data, dict):
        return []

    findings: list[Finding] = []
    referenced = _as_list(data.get("referenced-dependencies"))
    bad_type: list[str] = []
    missing_version: list[str] = []
    missing_name: list[str] = []
    for item in referenced:
        if not isinstance(item, dict):
            continue
        dep_type = str(item.get("type") or "")
        name = str(item.get("name") or "")
        version = str(item.get("version") or "")
        if not name:
            missing_name.append(dep_type or "(无 type)")
            continue
        if dep_type not in FOSSA_DEP_TYPES:
            bad_type.append(f"{dep_type or '(空)'}:{name}")
        if not version:
            missing_version.append(name)
    if bad_type:
        findings.append(
            make_finding(
                "FOS-003",
                "supply",
                "medium",
                "fossa-deps 里的依赖类型不被 FOSSA 支持",
                "以下条目的 `type` 不在 FOSSA 支持列表内，`fossa analyze` 会跳过或报错："
                + "、".join(bad_type[:MAX_SAMPLES]),
                path=rel,
                evidence="、".join(bad_type[:6]),
                remediation="改用支持的类型（pypi / npm / maven / gem / nuget / go / cargo / composer / pub / hex …）。",
                reference="https://docs.fossa.com/docs/cli/features/manual-dependencies",
                detail={"invalid": bad_type[:40]},
            )
        )
    if missing_name:
        findings.append(
            make_finding(
                "FOS-003",
                "supply",
                "medium",
                "fossa-deps 条目缺少 name",
                f"{len(missing_name)} 个 referenced-dependencies 条目没有 `name`，FOSSA 无法定位依赖。",
                path=rel,
                remediation="补齐 name（与注册表里的包名完全一致，含作用域与大小写规则）。",
            )
        )
    if missing_version:
        findings.append(
            make_finding(
                "FOS-003",
                "supply",
                "low",
                "fossa-deps 条目没有固定版本",
                f"{len(missing_version)} 个条目未写 `version`，FOSSA 会取注册表最新版，"
                f"许可证结论会随后续发布漂移：{'、'.join(missing_version[:MAX_SAMPLES])}",
                path=rel,
                evidence="、".join(missing_version[:6]),
                remediation="补上精确版本并加引号，例如 `version: \"2.1.7\"`。",
                detail={"packages": missing_version[:40]},
            )
        )

    custom = _as_list(data.get("custom-dependencies"))
    unlicensed = [
        str(item.get("name") or "?")
        for item in custom
        if isinstance(item, dict) and not str(item.get("license") or "").strip()
    ]
    if unlicensed:
        findings.append(
            make_finding(
                "FOS-003",
                "supply",
                "medium",
                "custom-dependencies 缺少 license",
                "custom-dependencies 必须自带 `license`，否则 FOSSA 只能标为未知："
                + "、".join(unlicensed[:MAX_SAMPLES]),
                path=rel,
                evidence="、".join(unlicensed[:6]),
                remediation="补 `license: MIT`（或 SPDX 表达式），并在 metadata 里写 homepage 便于追溯。",
            )
        )

    missing_path: list[str] = []
    for item in _as_list(data.get("vendored-dependencies")):
        if not isinstance(item, dict):
            continue
        target = str(item.get("path") or "")
        if target and not (ctx.root / target).exists():
            missing_path.append(f"{item.get('name') or '?'} → {target}")
    if missing_path:
        findings.append(
            make_finding(
                "FOS-003",
                "supply",
                "medium",
                "vendored-dependencies 指向的路径不存在",
                "FOSSA 需要把源码打包上传做许可证扫描，路径不存在时该依赖不会出现在报告里："
                + "；".join(missing_path[:MAX_SAMPLES]),
                path=rel,
                evidence="；".join(missing_path[:6]),
                remediation="修正 path，或改用 remote-dependencies 指向归档 URL。",
                detail={"missing": missing_path[:40]},
            )
        )

    bad_remote = [
        str(item.get("name") or "?")
        for item in _as_list(data.get("remote-dependencies"))
        if isinstance(item, dict)
        and (not str(item.get("url") or "").lower().startswith(("http://", "https://")))
    ]
    if bad_remote:
        findings.append(
            make_finding(
                "FOS-003",
                "supply",
                "medium",
                "remote-dependencies 缺少可下载的 URL",
                "以下条目没有合法的 `url`，FOSSA 无法下载归档做许可证扫描："
                + "、".join(bad_remote[:MAX_SAMPLES]),
                path=rel,
                remediation="补 http(s) 归档地址；内网地址需要 FOSSA 侧可访问。",
            )
        )
    return findings


def _ci_files(ctx: Context) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    for info in ctx.files:
        rel = info.rel
        if rel.startswith(CI_PREFIXES) and rel.endswith((".yml", ".yaml")):
            rows.append((rel, info.text()))
        elif rel in CI_FILES:
            rows.append((rel, info.text()))
    return rows


def _check_gate(ctx: Context, config_path: Path | None, deps_path: Path | None) -> list[Finding]:
    ci_rows = _ci_files(ctx)
    analyze_hit: tuple[str, int] | None = None
    has_test = False
    for rel, text in ci_rows:
        for lineno, line in enumerate(text.splitlines(), start=1):
            if re.search(r"\bfossa\s+analyze\b", line):
                analyze_hit = analyze_hit or (rel, lineno)
            if re.search(r"\bfossa\s+test\b", line):
                has_test = True
    if analyze_hit is None or has_test:
        return []
    rel, lineno = analyze_hit
    return [
        make_finding(
            "FOS-004",
            "supply",
            "medium",
            "CI 只上传 FOSSA 分析结果，没有门禁",
            f"{rel}:{lineno} 调用了 `fossa analyze`，但在已扫描到的 CI 配置里没有 `fossa test`。"
            "analyze 只把依赖图传给 FOSSA 生成报告，不会让构建失败——"
            "许可证冲突和新漏洞会一路合并进去。",
            path=rel,
            line=lineno,
            evidence="fossa analyze（无 fossa test）",
            remediation=(
                "在 analyze 之后加一步：`fossa test --format json`（有问题时返回退出码 1）；"
                "只想管新增问题时用 `fossa test --diff origin/main`。"
            ),
            reference="https://docs.fossa.com/docs/cli/references/subcommands/test",
        )
    ]


def _discover_sbom(ctx: Context) -> Path | None:
    if ctx.sbom is not None:
        return ctx.sbom if ctx.sbom.is_file() else None
    for name in SBOM_NAMES:
        candidate = ctx.root / name
        if candidate.is_file():
            return candidate
    for candidate in sorted(ctx.root.glob("*.spdx.json")):
        if candidate.is_file():
            return candidate
    return None


def _load_sbom(path: Path) -> tuple[list[tuple[str, str, str]], str]:
    try:
        size = path.stat().st_size
    except OSError:
        return [], "无法读取文件"
    if size > SBOM_MAX_BYTES:
        return [], "文件超过 20MB，已跳过"
    text = _read_text(path)
    if not text.strip():
        return [], "文件为空"
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [], "不是合法 JSON（当前只支持 CycloneDX / SPDX 的 JSON 输出）"
    if not isinstance(data, dict):
        return [], "SBOM 顶层结构无法识别"

    components: list[tuple[str, str, str]] = []
    if str(data.get("bomFormat") or "") == "CycloneDX" or isinstance(data.get("components"), list):
        for item in _as_list(data.get("components")):
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            if not name:
                continue
            version = str(item.get("version") or "").strip()
            components.append((name, version, _cyclonedx_license(item)))
        return components, ""
    if "SPDX" in str(data.get("spdxVersion") or "") or isinstance(data.get("packages"), list):
        for item in _as_list(data.get("packages")):
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            if not name:
                continue
            version = str(item.get("versionInfo") or "").strip()
            expression = str(item.get("licenseConcluded") or "").strip()
            if expression.upper() in ("", "NOASSERTION", "NONE"):
                expression = str(item.get("licenseDeclared") or "").strip()
            if expression.upper() in ("NOASSERTION", "NONE"):
                expression = ""
            components.append((name, version, expression))
        return components, ""
    return [], "无法识别的 SBOM 格式"


def _cyclonedx_license(item: dict) -> str:
    parts: list[str] = []
    for entry in _as_list(item.get("licenses")):
        if not isinstance(entry, dict):
            continue
        expression = str(entry.get("expression") or "").strip()
        if expression:
            parts.append(expression)
            continue
        license_obj = entry.get("license")
        if isinstance(license_obj, dict):
            identifier = str(license_obj.get("id") or license_obj.get("name") or "").strip()
            if identifier:
                parts.append(identifier)
    return " OR ".join(dict.fromkeys(parts))


def _family(expression: str) -> str:
    normalized = license_rules.normalize_spdx(expression)
    if not normalized:
        return "unknown"
    return license_rules.family_of(normalized)


def _local_licenses(ctx: Context) -> dict[str, tuple[Package, str]]:
    table: dict[str, tuple[Package, str]] = {}
    for package in ctx.deps.packages:
        expression = ctx.license_resolved.get(package.key, "")
        table.setdefault(package.name.lower(), (package, expression))
    return table


def _check_sbom(ctx: Context) -> list[Finding]:
    path = _discover_sbom(ctx)
    if path is None:
        return []
    components, error = _load_sbom(path)
    rel = _rel(path, ctx.root)
    if error:
        return [
            make_finding(
                "FOS-006",
                "license",
                "low",
                "SBOM 无法解析，未能与 FOSSA 结论对齐",
                f"{rel}：{error}。请用 `fossa report attribution --format cyclonedx-json` 或 "
                "`--format spdx-json` 重新导出。",
                path=rel,
                remediation="重新导出标准 SBOM 后再跑一次扫描。",
            )
        ]
    if not components:
        return []

    offline = ctx.offline or not ctx.config.network_enabled
    local = _local_licenses(ctx)
    findings: list[Finding] = []

    conflicts: list[dict[str, str]] = []
    uncovered: list[str] = []
    unknown_filled: list[str] = []
    for name, version, expression in components:
        entry = local.get(name.lower())
        if entry is None:
            uncovered.append(f"{name}@{version}" if version else name)
            continue
        package, local_expression = entry
        if not expression or offline:
            continue
        local_family = _family(local_expression)
        remote_family = _family(expression)
        if local_family == "unknown" and remote_family != "unknown":
            unknown_filled.append(f"{name} = {expression}")
            continue
        if (
            local_family != "unknown"
            and remote_family != "unknown"
            and local_family != remote_family
        ):
            conflicts.append(
                {
                    "package": name,
                    "version": package.version or version,
                    "local": local_expression,
                    "external": expression,
                    "local_family": local_family,
                    "external_family": remote_family,
                }
            )

    if conflicts:
        sample = "；".join(
            f"{item['package']}（本地 {item['local']} / SBOM {item['external']}）" for item in conflicts[:6]
        )
        findings.append(
            make_finding(
                "FOS-006",
                "license",
                "medium",
                "FOSSA SBOM 与本地许可证结论不一致",
                f"{len(conflicts)} 个依赖的许可证判定不同：{sample}"
                + ("…" if len(conflicts) > 6 else "")
                + "。任何一边都可能过期（本地看的是注册表元数据，FOSSA 看的是扫描结果），需要人工确认。",
                path=rel,
                evidence=f"{len(conflicts)} 处冲突",
                remediation="打开冲突依赖的仓库确认 LICENSE；以 LICENSE 原文为准，并把结论写进 license.exceptions 说明依据。",
                source="fossa-sbom",
                confidence=0.85,
                detail={"conflicts": conflicts[:40]},
            )
        )

    if unknown_filled:
        findings.append(
            make_finding(
                "FOS-007",
                "license",
                "info",
                "FOSSA SBOM 可以补全本地无法确定的许可证",
                f"{len(unknown_filled)} 个依赖本地查不到许可证，但 SBOM 里有："
                + "、".join(unknown_filled[:MAX_SAMPLES])
                + ("…" if len(unknown_filled) > MAX_SAMPLES else ""),
                path=rel,
                evidence=f"{len(unknown_filled)} 个依赖",
                remediation=(
                    "核对无误后登记为已知结论，避免每次扫描都重复提示：\n"
                    "```toml\n[license.exceptions]\n"
                    + "".join(
                        f'"{item.split(" = ")[0]}" = "FOSSA SBOM 显示 {item.split(" = ")[1]}"\n'
                        for item in unknown_filled[:8]
                    )
                    + "```"
                ),
                source="fossa-sbom",
                detail={"packages": unknown_filled[:40]},
            )
        )

    if uncovered:
        missing = [name for name in uncovered if name]
        if missing:
            findings.append(
                make_finding(
                    "FOS-008",
                    "license",
                    "info",
                    "SBOM 里有本地没有解析到的组件",
                    f"{len(missing)} 个组件只出现在 SBOM 里（"
                    + "、".join(missing[:MAX_SAMPLES])
                    + ("…" if len(missing) > MAX_SAMPLES else "")
                    + "）。通常是 vendored 代码、私有包或我们尚未支持的清单格式——"
                    "这部分依赖的漏洞与许可证，本工具给不出结论。",
                    path=rel,
                    evidence=f"{len(missing)} 个组件",
                    remediation="若来自 vendored 代码，用 fossa-deps 的 vendored-dependencies 显式声明；若来自新的清单格式，补一个解析器。",
                    source="fossa-sbom",
                    detail={"components": missing[:60]},
                )
            )
    return findings


def scan(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    config_path = _find(ctx.root, FOSSA_CONFIG_NAMES)
    deps_path = _find(ctx.root, FOSSA_DEPS_NAMES)

    if config_path is not None:
        config, error = _load_structured(config_path)
        if error or not isinstance(config, dict):
            findings.append(
                make_finding(
                    "FOS-005",
                    "hygiene",
                    "medium",
                    ".fossa.yml 无法解析",
                    f"{_rel(config_path, ctx.root)} 解析失败（{error or '顶层不是映射'}），FOSSA 会退回默认行为。",
                    path=_rel(config_path, ctx.root),
                    remediation="修正 YAML 结构；缩进必须用空格，且顶层是 `version: 3`。",
                )
            )
        else:
            findings.extend(_check_config_version(config_path, ctx.root, config))
            findings.extend(_check_scope(ctx, config_path, config))

    if deps_path is not None:
        findings.extend(_check_deps_file(ctx, deps_path))

    findings.extend(_check_gate(ctx, config_path, deps_path))
    findings.extend(_check_sbom(ctx))
    return findings
