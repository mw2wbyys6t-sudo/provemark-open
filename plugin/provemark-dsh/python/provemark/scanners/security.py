"""应用层漏洞扫描器（`--only security`）。

覆盖 OWASP Top 10 里能在源码里直接看见的高信号模式：注入（SQL/命令/模板/脚本）、
路径穿越、SSRF、反序列化、XSS、弱哈希/弱随机/弱加密、TLS 校验关闭、JWT 校验关闭、
Cookie 安全属性、调试模式、XXE、C 内存函数、容器提权与 GitHub Actions 脚本注入。

每条 finding 带 CWE 与 OWASP 映射，便于和标准条目对照、也便于在报告里解释。
"""
from __future__ import annotations

from pathlib import Path

from ..rules import security_patterns as rules
from .base import Context, make_finding
from .codemask import code_mask

LANG_BY_SUFFIX = {
    ".py": "py",
    ".pyi": "py",
    ".js": "js",
    ".jsx": "js",
    ".mjs": "js",
    ".cjs": "js",
    ".ts": "ts",
    ".tsx": "ts",
    ".go": "go",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
}
DOWNGRADE = {"critical": "high", "high": "medium", "medium": "low", "low": "info", "info": "info"}
SCRIPT_DIRS = ("scripts/", "tools/", "examples/", "training/", "benchmarks/", "docs/", "doc/")
GENERATED_TOKENS = (
    ".min.js",
    ".min.css",
    ".d.ts",
    "_pb2.py",
    ".pb.go",
    ".pb.gw.go",
    ".gen.go",
    "zz_generated",
    "_generated",
    ".g.dart",
)
MAX_LOCATIONS = 5
COMPOSE_NAMES = ("docker-compose", "compose.")
DOCKERFILE_NAMES = ("dockerfile",)


def _lang(path: Path) -> str | None:
    return LANG_BY_SUFFIX.get(path.suffix.lower())


def _skip(info) -> bool:
    lowered = info.rel.lower()
    if info.path.name in rules.SELF_PATTERN_FILES:
        return True
    if "/rules/" in f"/{lowered}" and lowered.endswith(".py"):
        return True
    return any(token in lowered for token in GENERATED_TOKENS)


def _context_flags(info, ctx: Context) -> tuple[bool, bool]:
    lowered = info.rel.lower()
    is_test = info.is_test
    is_script = any(token in lowered for token in SCRIPT_DIRS)
    return is_test, is_script


def _adjust(severity: str, confidence: float, is_test: bool, is_script: bool) -> tuple[str, float]:
    if is_test:
        return DOWNGRADE.get(severity, severity), min(confidence, 0.5)
    if is_script:
        return DOWNGRADE.get(severity, severity), min(confidence, 0.6)
    return severity, confidence


def _emit(info, rule: dict, hits: list[tuple[int, str, str, float]], is_test: bool):
    """Aggregate one rule's hits in one file into a single finding."""
    first_line, first_snippet, severity, confidence = hits[0]
    locations = [f"{info.rel}:{line}" for line, _, _, _ in hits[:MAX_LOCATIONS]]
    more = f"（本文件共 {len(hits)} 处）" if len(hits) > 1 else ""
    note = " 命中位于测试代码，已降级。" if is_test else ""
    return make_finding(
        str(rule["id"]),
        "security",
        severity,
        f"{rule['title']}{more}",
        str(rule["message"]) + note,
        path=info.rel,
        line=first_line,
        evidence=first_snippet[:200],
        remediation=str(rule["remediation"]),
        reference=f"https://cwe.mitre.org/data/definitions/{str(rule['cwe']).split('-')[-1]}.html",
        confidence=confidence,
        detail={
            "cwe": rule["cwe"],
            "owasp": rule["owasp"],
            "count": len(hits),
            "locations": locations,
        },
    )


def _code_findings(ctx: Context, info, lang: str) -> list:
    is_test, is_script = _context_flags(info, ctx)
    try:
        mask = code_mask(info.lines, lang)
    except Exception:  # noqa: BLE001 - masking must never take the scanner down
        mask = [True] * len(info.lines)
    buckets: dict[str, list[tuple[int, str, str, float]]] = {}
    for index, line in enumerate(info.lines):
        if not mask[index]:
            continue
        stripped = line.strip()
        if not stripped or len(line) > 2000:
            continue
        for rule in rules.SECURITY_PATTERNS:
            languages = rule["languages"]  # type: ignore[assignment]
            if lang not in languages and "generic" not in languages:
                continue
            match = rule["pattern"].search(line)  # type: ignore[union-attr]
            if not match:
                continue
            severity = str(rule["severity"])
            escalate = rule.get("escalate_on")
            if escalate is not None and escalate.search(line):  # type: ignore[union-attr]
                severity = str(rule.get("escalated_severity") or severity)
            confidence = float(rule.get("confidence", 0.85))
            if is_test and rule.get("test_severity"):
                severity = str(rule["test_severity"])
                confidence = min(confidence, 0.5)
            else:
                severity, confidence = _adjust(severity, confidence, is_test, is_script)
            buckets.setdefault(str(rule["id"]), []).append(
                (index + 1, stripped, severity, confidence)
            )
    findings = []
    for rule_id, hits in buckets.items():
        rule = next(item for item in rules.SECURITY_PATTERNS if item["id"] == rule_id)
        findings.append(_emit(info, rule, hits, is_test))
    return findings


def _workflow_findings(ctx: Context, info) -> list:
    """GitHub Actions: untrusted event fields interpolated into a `run:` step."""
    rule = rules.ACTIONS_INJECTION
    hits: list[tuple[int, str]] = []
    text = info.text()
    if "run:" not in text:
        return []
    for index, line in enumerate(info.lines):
        if not rule["pattern"].search(line):  # type: ignore[union-attr]
            continue
        hits.append((index + 1, line.strip()))
    if not hits:
        return []
    first_line, first_snippet = hits[0]
    more = f"（本文件共 {len(hits)} 处）" if len(hits) > 1 else ""
    return [
        make_finding(
            str(rule["id"]),
            "security",
            str(rule["severity"]),
            f"{rule['title']}{more}",
            str(rule["message"]),
            path=info.rel,
            line=first_line,
            evidence=first_snippet[:200],
            remediation=str(rule["remediation"]),
            reference="https://securitylab.github.com/research/github-actions-untrusted-input/",
            confidence=float(rule.get("confidence", 0.8)),
            detail={
                "cwe": rule["cwe"],
                "owasp": rule["owasp"],
                "count": len(hits),
                "locations": [f"{info.rel}:{line}" for line, _ in hits[:MAX_LOCATIONS]],
            },
        )
    ]


def _container_findings(ctx: Context, info) -> list:
    rule = next(item for item in rules.SECURITY_PATTERNS if item["id"] == "VUL-018")
    hits = [
        (index + 1, line.strip())
        for index, line in enumerate(info.lines)
        if rule["pattern"].search(line)  # type: ignore[union-attr]
    ]
    if not hits:
        return []
    first_line, first_snippet = hits[0]
    more = f"（本文件共 {len(hits)} 处）" if len(hits) > 1 else ""
    return [
        make_finding(
            "VUL-018",
            "security",
            str(rule["severity"]),
            f"{rule['title']}{more}",
            str(rule["message"]),
            path=info.rel,
            line=first_line,
            evidence=first_snippet[:200],
            remediation=str(rule["remediation"]),
            reference="https://cwe.mitre.org/data/definitions/250.html",
            confidence=float(rule.get("confidence", 0.85)),
            detail={
                "cwe": rule["cwe"],
                "owasp": rule["owasp"],
                "count": len(hits),
                "locations": [f"{info.rel}:{line}" for line, _ in hits[:MAX_LOCATIONS]],
            },
        )
    ]


def _is_container_config(info) -> bool:
    lowered = info.rel.lower()
    name = info.path.name.lower()
    if name.startswith(DOCKERFILE_NAMES) or name.endswith(".dockerfile"):
        return True
    if lowered.endswith((".yml", ".yaml")):
        return any(token in lowered for token in COMPOSE_NAMES)
    return False


def scan(ctx: Context) -> list:
    findings = []
    for info in ctx.scoped_files():
        lowered = info.rel.lower()
        if lowered.startswith(".github/workflows/") and lowered.endswith((".yml", ".yaml")):
            findings.extend(_workflow_findings(ctx, info))
            continue
        if _is_container_config(info):
            findings.extend(_container_findings(ctx, info))
            continue
        if not info.is_code or _skip(info):
            continue
        lang = _lang(info.path)
        if lang is None:
            continue
        findings.extend(_code_findings(ctx, info, lang))
    return findings
