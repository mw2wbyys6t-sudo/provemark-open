from __future__ import annotations

import datetime as dt
import time
from pathlib import Path

from . import score as scoring
from .config import Config
from .models import Finding, ScanResult, ScanStats
from .scanners import (
    ai_code,
    deps,
    files,
    fossa,
    license as license_scanner,
    pii,
    repo,
    secrets,
    security as security_scanner,
    supply,
    vuln,
    vcs,
)
from .scanners.base import Context

SCANNER_ORDER = ("repo", "secrets", "pii", "security", "ai", "dependency", "license", "supply", "fossa")
SCANNER_MAP = {
    "repo": repo.scan,
    "secrets": secrets.scan,
    "pii": pii.scan,
    "security": security_scanner.scan,
    "ai": ai_code.scan,
    "dependency": vuln.scan,
    "license": license_scanner.scan,
    "supply": supply.scan,
    "fossa": fossa.scan,
}
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def run_scan(
    root: Path,
    config: Config,
    *,
    offline: bool = False,
    staged_only: bool = False,
    only: list[str] | None = None,
    skip: list[str] | None = None,
    sbom: str | None = None,
) -> ScanResult:
    started = time.time()
    root = root.resolve()
    result = ScanResult(root=str(root), scanned_at=_now())

    if not root.is_dir():
        raise FileNotFoundError(f"目录不存在：{root}")

    collected, file_notes = files.collect_files(root, config)
    deps_result = deps.collect(root, config)
    cache = _build_cache()
    staged: set[str] | None = None
    if staged_only:
        staged_list = vcs.staged_files(root)
        if staged_list is None:
            raise RuntimeError("--staged 需要在 Git 仓库中使用，且当前环境无法读取暂存区")
        staged = set(staged_list)

    context = Context(
        root=root,
        config=config,
        files=collected,
        deps=deps_result,
        cache=cache,
        offline=offline,
        staged=staged,
        sbom=Path(sbom).expanduser().resolve() if sbom else None,
    )
    context.notes.extend(file_notes)
    context.notes.extend(deps_result.notes)

    selected = [name for name in SCANNER_ORDER if _enabled(name, only, skip)]
    findings: list[Finding] = []
    for name in selected:
        scanner = SCANNER_MAP[name]
        try:
            findings.extend(scanner(context))
        except Exception as exc:  # noqa: BLE001 - 单个扫描器失败不应中断整次扫描
            context.note(f"{name} 扫描器执行失败：{type(exc).__name__}: {exc}")

    findings = _apply_overrides(findings, config)
    findings = _apply_floor(findings, config)
    findings, suppressed, expired = _apply_baseline(findings, config)

    result.findings = findings
    result.suppressed = suppressed
    result.expired_ignores = expired
    result.packages = deps_result.packages

    total_packages = len(deps_result.packages)
    unreliable = (
        total_packages >= 3 and context.unverified_packages / total_packages > 0.5
    ) or context.network_failed
    result.score = scoring.compute(findings, reliable=not unreliable)

    stats = ScanStats(
        files_scanned=len(collected),
        bytes_scanned=sum(item.size for item in collected),
        packages_total=total_packages,
        packages_direct=sum(1 for package in deps_result.packages if package.direct),
        packages_unverified=context.unverified_packages,
        duration_s=time.time() - started,
        network_used=context.network_used,
        notes=list(dict.fromkeys(context.notes)),
    )
    if context.network_failed:
        stats.notes.append("联网查询失败：漏洞/许可证数据不完整，分数仅供参考")
    if total_packages >= 3 and context.unverified_packages / total_packages > 0.5:
        stats.notes.append("超过一半依赖无法确定版本，分数仅供参考")
    stats.notes.extend(_calibration_notes(findings))
    result.stats = stats
    cache.save()
    return result


def _calibration_notes(findings: list[Finding]) -> list[str]:
    """给大仓库/框架代码补一句分数怎么读，避免把启发式当判决。"""
    total = len(findings)
    if total < 80:
        return []
    ai_count = sum(1 for finding in findings if finding.category == "ai")
    if ai_count * 2 >= total:
        return [
            f"命中以 AI 代码质量类为主（{ai_count}/{total} 条）：成熟框架/库的惯用写法"
            "（宽泛 except、抽象方法 NotImplementedError、模板引擎 eval）会被这类规则命中；"
            "优先看 critical/high 与新增趋势，分数是下限不是判决。"
        ]
    if total >= 200:
        return [
            f"命中较多（{total} 条）：建议先用 `--only security,dependency` 看高风险维度，"
            "再按严重度分批处理；分数是信号，不是判决。"
        ]
    return []


def _enabled(name: str, only: list[str] | None, skip: list[str] | None) -> bool:
    if only:
        return name in only
    if skip:
        return name not in skip
    return True


def _build_cache():
    from .cache import Cache

    return Cache()


def _apply_overrides(findings: list[Finding], config: Config) -> list[Finding]:
    if not config.severity_overrides:
        return findings
    for finding in findings:
        override = config.severity_overrides.get(finding.rule_id.upper())
        if override and override in SEVERITY_RANK:
            finding.severity = override
    return findings


def _apply_floor(findings: list[Finding], config: Config) -> list[Finding]:
    floor = config.severity_floor
    if floor not in SEVERITY_RANK:
        return findings
    limit = SEVERITY_RANK[floor]
    return [finding for finding in findings if SEVERITY_RANK[finding.severity] <= limit]


def _apply_baseline(findings: list[Finding], config: Config):
    if not config.ignore:
        return findings, [], []
    kept: list[Finding] = []
    suppressed: list[Finding] = []
    expired: list[Finding] = []
    today = dt.date.today()
    expired_rules = set()

    for finding in findings:
        matched = None
        for rule in config.ignore:
            if rule.matches(finding):
                matched = rule
                break
        if matched is None:
            kept.append(finding)
            continue
        if matched.is_expired(today):
            kept.append(finding)
            key = matched.fingerprint or matched.rule or matched.path
            if key not in expired_rules:
                expired_rules.add(key)
                expired.append(
                    Finding(
                        rule_id="IGN-001",
                        category="hygiene",
                        severity="medium",
                        title="豁免已过期，问题重新计分",
                        message=(
                            f"豁免「{matched.reason or '未填写原因'}」已于 {matched.expires} 过期，"
                            "请修复对应问题或续期。"
                        ),
                        path=finding.path,
                        remediation="修复该问题，或执行 `provemark ignore` 重新登记理由与新的到期时间。",
                    )
                )
            continue
        if finding.severity == "critical":
            kept.append(finding)
            expired.append(
                Finding(
                    rule_id="IGN-002",
                    category="hygiene",
                    severity="high",
                    title="致命问题不允许被基线豁免",
                    message=f"{finding.rule_id} 属于致命级别，必须在本次修复，而不是加进基线。",
                    path=finding.path,
                    line=finding.line,
                    remediation="轮换泄漏凭据 / 移除恶意依赖后再扫描。",
                )
            )
            continue
        suppressed.append(finding)

    return kept + expired, suppressed, expired


def _now() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def gate_failed(result: ScanResult, fail_on: str, min_confidence: float = 0.0) -> bool:
    if fail_on == "none":
        return False
    limit = SEVERITY_RANK.get(fail_on, 1)
    return any(
        SEVERITY_RANK[finding.severity] <= limit and finding.confidence >= min_confidence
        for finding in result.findings
    )
