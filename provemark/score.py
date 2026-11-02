from __future__ import annotations

import math

from .models import CATEGORIES, SEVERITIES, Finding, Score

CRITICAL_WEIGHT = 35.0
NON_CRITICAL_WEIGHT = {"high": 8.0, "medium": 2.0, "low": 0.8, "info": 0.1}
NON_CRITICAL_CAP = 25.0
DAMPING = 0.7
MIN_EFFECTIVE_COUNT = 0.05
GRADES = ((90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F"))


def grade_for(total: int) -> str:
    for threshold, grade in GRADES:
        if total >= threshold:
            return grade
    return "F"


def _deduction(weight: float, effective: float) -> float:
    if effective <= 0:
        return 0.0
    factor = 1 + DAMPING * math.log2(max(MIN_EFFECTIVE_COUNT, effective))
    return max(0.0, weight * factor)


def compute(findings: list[Finding], reliable: bool = True) -> Score:
    deductions: dict[str, float] = {}
    by_category: dict[str, float] = {}
    counts: dict[str, int] = {name: 0 for name in SEVERITIES}

    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    for category in CATEGORIES:
        buckets: dict[str, float] = {}
        for finding in findings:
            if finding.category != category:
                continue
            buckets[finding.severity] = buckets.get(finding.severity, 0.0) + max(
                0.0, finding.confidence
            )
        critical = _deduction(CRITICAL_WEIGHT, buckets.get("critical", 0.0))
        others = 0.0
        for severity, weight in NON_CRITICAL_WEIGHT.items():
            effective = buckets.get(severity, 0.0)
            if effective > 0:
                others += _deduction(weight, effective)
        total = critical + min(others, NON_CRITICAL_CAP)
        deductions[category] = total
        by_category[category] = min(100.0, max(0.0, 100.0 - total))

    total_score = max(0, min(100, round(100 - sum(deductions.values()))))
    return Score(
        total=total_score,
        grade=grade_for(total_score),
        by_category=by_category,
        deductions=deductions,
        counts=counts,
        reliable=reliable,
    )
