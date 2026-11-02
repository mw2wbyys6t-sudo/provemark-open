from __future__ import annotations

import base64
import binascii
import re

from ..models import Finding
from ..rules import secrets as rules
from .base import Context, make_finding
from .dedup import merge as merge_duplicates
from .dedup import tag as tag_duplicate

DOWNGRADE = {"critical": "medium", "high": "low", "medium": "info", "low": "info", "info": "info"}
SECOND_DOWNGRADE = {
    "critical": "low",
    "high": "info",
    "medium": "info",
    "low": "info",
    "info": "info",
}
SKIP_SUFFIXES = (".min.js", ".min.css", ".map", ".snap")
ENV_KEEP_SUFFIXES = (".example", ".sample", ".template", ".dist")
BASE64_CANDIDATE = re.compile(r"['\"]([A-Za-z0-9+/]{20,4096}={0,2})['\"]")
MAX_DECODED_CHARS = 8192
MAX_CANDIDATES_PER_LINE = 3


def _is_env_file(name: str) -> bool:
    return name == ".env" or name.startswith(".env.")


def _should_skip(rel: str, name: str) -> bool:
    lowered = rel.lower()
    if lowered.endswith(SKIP_SUFFIXES):
        return True
    if "/vendor/" in lowered or "/third_party/" in lowered:
        return True
    if _is_env_file(name) and not name.lower().endswith(ENV_KEEP_SUFFIXES):
        return True
    return False


def _looks_like_pattern(value: str) -> bool:
    return any(char in value for char in "[({*\\") or "\\d" in value or ".*" in value


def _downgrade(severity: str, steps: int) -> str:
    table = DOWNGRADE if steps <= 1 else SECOND_DOWNGRADE
    return table.get(severity, severity)


def _decode_base64(text: str) -> str:
    padded = text + "=" * (-len(text) % 4)
    try:
        raw = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return ""
    if len(raw) < 8:
        return ""
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        return ""
    if len(decoded) > MAX_DECODED_CHARS:
        return ""
    printable = sum(1 for char in decoded if char.isprintable() or char in "\n\r\t")
    if printable / len(decoded) < 0.9:
        return ""
    return decoded


def _match_decoded(text: str) -> dict | None:
    for rule in rules.SECRET_RULES:
        match = rule["pattern"].search(text)
        if not match:
            continue
        value = match.group(0)
        if _looks_like_pattern(value) or rules.looks_placeholder(value):
            continue
        return {
            "rule_id": str(rule["id"]),
            "name": str(rule["name"]),
            "value": value,
            "severity": str(rule["severity"]),
            "remediation": str(rule["remediation"]),
            "reference": str(rule["reference"]),
            "generic": False,
        }
    generic = rules.GENERIC_ASSIGNMENT.search(text)
    if not generic:
        return None
    value = generic.group("value")
    if rules.looks_placeholder(value) or len(value) < 16:
        return None
    entropy = rules.shannon_entropy(value)
    if entropy < 3.2:
        return None
    return {
        "rule_id": "SEC-017",
        "name": "高熵字符串",
        "value": value,
        "severity": "high" if entropy > 4.1 and len(value) >= 32 else "medium",
        "remediation": "改为从环境变量或密钥管理服务读取；若是测试数据，请换成明显的占位值。",
        "reference": "",
        "generic": True,
    }


def _merge(findings: list[Finding]) -> list[Finding]:
    return merge_duplicates(findings)


def scan(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []

    for info in ctx.scoped_files():
        if not ctx.in_scope(info.rel):
            continue
        name = info.path.name
        if _should_skip(info.rel, name):
            continue
        is_test = info.is_test or "example" in info.rel.lower() or "sample" in info.rel.lower()

        for lineno, line in enumerate(info.lines, start=1):
            if not line or len(line) > 4000:
                continue
            if "re.compile(" in line or "_PATTERNS" in line or "pattern =" in line:
                continue
            matched_specific = False
            for rule in rules.SECRET_RULES:
                pattern = rule["pattern"]
                match = pattern.search(line)
                if not match:
                    continue
                value = match.group(0)
                if _looks_like_pattern(value):
                    continue
                if rules.looks_placeholder(value) and rule["id"] != "SEC-009":
                    continue
                matched_specific = True
                severity = str(rule["severity"])
                if is_test:
                    severity = _downgrade(severity, 1)
                if severity == "info" and not is_test:
                    severity = "low"
                findings.append(
                    tag_duplicate(
                        make_finding(
                            str(rule["id"]),
                            "secrets",
                            severity,
                            f"疑似泄漏：{rule['name']}",
                            f"在 {info.rel} 第 {lineno} 行发现疑似真实凭据。{rule['remediation']}",
                            path=info.rel,
                            line=lineno,
                            column=match.start() + 1,
                            evidence=rules.mask(value),
                            remediation=str(rule["remediation"]),
                            reference=str(rule["reference"]),
                            detail={"pattern": str(rule["name"])},
                        ),
                        str(rule["id"]),
                        value,
                    )
                )
                break

            if not matched_specific:
                finding = _generic_finding(line, info.rel, lineno, is_test)
                if finding is not None:
                    findings.append(finding)

            for index, candidate in enumerate(BASE64_CANDIDATE.finditer(line)):
                if index >= MAX_CANDIDATES_PER_LINE:
                    break
                decoded = _decode_base64(candidate.group(1))
                if not decoded:
                    continue
                hit = _match_decoded(decoded)
                if hit is None:
                    continue
                severity = str(hit["severity"])
                if is_test:
                    severity = _downgrade(severity, 1)
                if severity == "info" and not is_test:
                    severity = "low"
                findings.append(
                    tag_duplicate(
                        make_finding(
                            str(hit["rule_id"]),
                            "secrets",
                            severity,
                            f"疑似泄漏（base64 编码）：{hit['name']}",
                            f"在 {info.rel} 第 {lineno} 行发现 base64 字面量，解码后命中凭据特征，"
                            "说明密钥被刻意编码后写死。",
                            path=info.rel,
                            line=lineno,
                            column=candidate.start() + 1,
                            evidence=rules.mask(str(hit["value"])),
                            remediation=str(hit["remediation"]),
                            reference=str(hit["reference"]),
                            confidence=0.85,
                            detail={"encoding": "base64", "pattern": str(hit["name"])},
                        ),
                        str(hit["rule_id"]),
                        str(hit["value"]),
                    )
                )
                break

    return _merge(findings)


def _generic_finding(line: str, rel: str, lineno: int, is_test: bool) -> Finding | None:
    generic = rules.GENERIC_ASSIGNMENT.search(line)
    if not generic:
        return None
    value = generic.group("value")
    if rules.looks_placeholder(value):
        return None
    if len(value) < 16 or rules.shannon_entropy(value) < 3.2:
        return None
    severity = "medium"
    confidence = 0.5
    if rules.shannon_entropy(value) > 4.1 and len(value) >= 32:
        severity = "high"
        confidence = 0.65
    if is_test:
        severity = _downgrade(severity, 1)
        confidence = min(confidence, 0.4)
    return tag_duplicate(
        make_finding(
            "SEC-017",
            "secrets",
            severity,
            "疑似硬编码密钥（高熵字符串）",
            f"`{generic.group(1)}` 被赋值为一个高熵字符串，看起来像真实密钥而不是配置项。",
            path=rel,
            line=lineno,
            column=generic.start("value") + 1,
            evidence=f"{generic.group(1)} = {rules.mask(value)}",
            remediation="改为从环境变量或密钥管理服务读取；若是测试数据，请换成明显的占位值。",
            confidence=confidence,
            detail={"entropy": round(rules.shannon_entropy(value), 2)},
        ),
        "SEC-017",
        value,
    )
