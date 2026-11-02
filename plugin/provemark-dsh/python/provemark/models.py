from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any

from . import __version__

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITIES)}
SEVERITY_WEIGHT = {"critical": 35.0, "high": 8.0, "medium": 2.0, "low": 0.8, "info": 0.1}
SEVERITY_LABEL = {
    "critical": "致命",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "提示",
}

CATEGORIES = {
    "dependency": "依赖漏洞",
    "license": "许可证",
    "secrets": "凭据泄漏",
    "pii": "敏感数据",
    "security": "代码安全",
    "ai": "AI 代码风险",
    "supply": "供应链",
    "hygiene": "仓库卫生",
}

_WS = re.compile(r"\s+")


def _normalize(text: str, limit: int = 160) -> str:
    return _WS.sub(" ", text.strip())[:limit]


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: str
    title: str
    message: str
    path: str = ""
    line: int = 0
    column: int = 0
    evidence: str = ""
    remediation: str = ""
    reference: str = ""
    source: str = "local"
    confidence: float = 1.0
    detail: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_RANK:
            raise ValueError(f"unknown severity: {self.severity}")
        if self.category not in CATEGORIES:
            raise ValueError(f"unknown category: {self.category}")
        self.confidence = max(0.0, min(1.0, float(self.confidence)))

    @property
    def fingerprint(self) -> str:
        seed = "|".join(
            [self.rule_id, self.path.replace("\\", "/"), _normalize(self.evidence or self.message)]
        )
        return hashlib.sha1(seed.encode("utf-8")).hexdigest()[:16]

    @property
    def severity_index(self) -> int:
        return SEVERITY_RANK[self.severity]

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "category_label": CATEGORIES[self.category],
            "severity": self.severity,
            "severity_label": SEVERITY_LABEL[self.severity],
            "title": self.title,
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "reference": self.reference,
            "source": self.source,
            "confidence": round(self.confidence, 2),
            "fingerprint": self.fingerprint,
            "detail": self.detail,
        }


@dataclass
class Package:
    name: str
    ecosystem: str
    version: str = ""
    declared: str = ""
    scope: str = "runtime"
    manifest: str = ""
    direct: bool = True
    locator: str = ""
    indirect: bool = False
    lookup_name: str = ""
    pinned_by_parent: bool = False

    @property
    def ref(self) -> str:
        return self.lookup_name or self.name

    @property
    def key(self) -> str:
        return f"{self.ecosystem}:{self.ref}@{self.version or self.declared}"

    @property
    def display(self) -> str:
        return f"{self.name} {self.version or self.declared}".strip()

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "name": self.name,
            "ecosystem": self.ecosystem,
            "version": self.version,
            "declared": self.declared,
            "scope": self.scope,
            "manifest": self.manifest,
            "direct": self.direct,
        }
        if self.lookup_name and self.lookup_name != self.name:
            payload["lookup_name"] = self.lookup_name
        return payload


@dataclass
class Score:
    total: int
    grade: str
    by_category: dict[str, float] = field(default_factory=dict)
    deductions: dict[str, float] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)
    reliable: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "grade": self.grade,
            "by_category": {k: round(v, 2) for k, v in self.by_category.items()},
            "counts": self.counts,
            "reliable": self.reliable,
        }


@dataclass
class ScanStats:
    files_scanned: int = 0
    bytes_scanned: int = 0
    packages_total: int = 0
    packages_direct: int = 0
    packages_unverified: int = 0
    duration_s: float = 0.0
    network_used: bool = False
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "files_scanned": self.files_scanned,
            "bytes_scanned": self.bytes_scanned,
            "packages_total": self.packages_total,
            "packages_direct": self.packages_direct,
            "packages_unverified": self.packages_unverified,
            "duration_s": round(self.duration_s, 2),
            "network_used": self.network_used,
            "notes": self.notes,
        }


@dataclass
class ScanResult:
    root: str
    findings: list[Finding] = field(default_factory=list)
    score: Score | None = None
    stats: ScanStats = field(default_factory=ScanStats)
    suppressed: list[Finding] = field(default_factory=list)
    expired_ignores: list[Finding] = field(default_factory=list)
    packages: list[Package] = field(default_factory=list)
    scanned_at: str = ""
    tool_version: str = __version__

    def sorted_findings(self) -> list[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (f.severity_index, f.category, f.path, f.line, f.rule_id),
        )

    def counts_by_severity(self) -> dict[str, int]:
        counts = {name: 0 for name in SEVERITIES}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    def counts_by_category(self) -> dict[str, int]:
        counts = {name: 0 for name in CATEGORIES}
        for finding in self.findings:
            counts[finding.category] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "provemark",
            "version": self.tool_version,
            "root": self.root,
            "scanned_at": self.scanned_at,
            "score": self.score.to_dict() if self.score else None,
            "stats": self.stats.to_dict(),
            "counts": {
                "by_severity": self.counts_by_severity(),
                "by_category": self.counts_by_category(),
            },
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "suppressed": [f.to_dict() for f in self.suppressed],
            "packages": [p.to_dict() for p in self.packages],
        }
