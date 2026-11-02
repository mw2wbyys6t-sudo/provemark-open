from __future__ import annotations

import hashlib

from ..models import SEVERITY_RANK, Finding

MAX_LOCATIONS = 20


def key(rule_id: str, value: str) -> tuple[str, str]:
    digest = hashlib.sha1(value.encode("utf-8", errors="replace")).hexdigest()[:16]
    return rule_id, digest


def tag(finding: Finding, rule_id: str, value: str) -> Finding:
    setattr(finding, "_dedup", key(rule_id, value))
    return finding


def merge(findings: list[Finding]) -> list[Finding]:
    groups: dict[tuple[str, str], list[Finding]] = {}
    order: list[Finding | tuple[str, str]] = []
    for finding in findings:
        dedup_key = getattr(finding, "_dedup", None)
        if dedup_key is None:
            order.append(finding)
            continue
        if dedup_key not in groups:
            groups[dedup_key] = []
            order.append(dedup_key)
        groups[dedup_key].append(finding)

    merged: list[Finding] = []
    for item in order:
        if isinstance(item, Finding):
            merged.append(item)
            continue
        items = sorted(groups[item], key=lambda finding: (finding.path, finding.line))
        head = items[0]
        if len(items) > 1:
            worst = min(items, key=lambda finding: SEVERITY_RANK[finding.severity])
            head.severity = worst.severity
            head.confidence = max(finding.confidence for finding in items)
            locations = [f"{finding.path}:{finding.line}" for finding in items]
            head.detail = dict(head.detail)
            head.detail["count"] = len(items)
            head.detail["occurrences"] = locations[:MAX_LOCATIONS]
            shown = "、".join(locations[:5])
            head.message = (
                head.message
                + f" 同一取值在另外 {len(items) - 1} 处重复出现（已合并计分）："
                + shown
                + ("…" if len(locations) > 5 else "")
            )
        merged.append(head)
    for finding in merged:
        if hasattr(finding, "_dedup"):
            delattr(finding, "_dedup")
    return merged
