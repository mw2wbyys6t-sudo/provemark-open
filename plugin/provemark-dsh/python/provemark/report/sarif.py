from __future__ import annotations

import json
from typing import Any

from ..models import CATEGORIES, SEVERITY_LABEL, ScanResult

LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _rules(result: ScanResult) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}
    for finding in result.sorted_findings():
        if finding.rule_id in seen:
            continue
        seen[finding.rule_id] = {
            "id": finding.rule_id,
            "name": finding.title.replace(" ", ""),
            "shortDescription": {"text": finding.title},
            "fullDescription": {"text": finding.message},
            "help": {
                "text": finding.remediation or "请参考报告中的修复建议。",
                "markdown": finding.remediation or "请参考报告中的修复建议。",
            },
            "defaultConfiguration": {"level": LEVEL[finding.severity]},
            "properties": {
                "category": finding.category,
                "categoryLabel": CATEGORIES[finding.category],
                "severity": finding.severity,
                "severityLabel": SEVERITY_LABEL[finding.severity],
                "tags": ["security", finding.category]
                + ([str(finding.detail["cwe"])] if finding.detail.get("cwe") else []),
                **({"cwe": finding.detail["cwe"]} if finding.detail.get("cwe") else {}),
                **({"owasp": finding.detail["owasp"]} if finding.detail.get("owasp") else {}),
            },
        }
    return list(seen.values())


def _results(result: ScanResult) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for finding in result.sorted_findings():
        # GitHub Code Scanning rejects results without a physical location
        # ("locationFromSarifResult: expected at least one location"). Repository-
        # level findings (missing LICENSE/CI/lockfile) have no file: they stay in
        # the JSON/HTML reports and rule metadata, but cannot be a SARIF result.
        if not finding.path:
            continue
        entry: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": LEVEL[finding.severity],
            "message": {"text": f"{finding.title}：{finding.message}"},
            "partialFingerprints": {"provemarkFingerprint": finding.fingerprint},
            "properties": {
                "severity": finding.severity,
                "category": finding.category,
                "remediation": finding.remediation,
                "source": finding.source,
                **({"cwe": finding.detail["cwe"]} if finding.detail.get("cwe") else {}),
                **({"owasp": finding.detail["owasp"]} if finding.detail.get("owasp") else {}),
            },
        }
        if finding.path:
            region: dict[str, Any] = {}
            if finding.line:
                region["startLine"] = max(1, finding.line)
            if finding.column:
                region["startColumn"] = max(1, finding.column)
            entry["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.path, "uriBaseId": "%SRCROOT%"},
                        **({"region": region} if region else {}),
                    }
                }
            ]
        items.append(entry)
    return items


def render(result: ScanResult) -> str:
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Provemark",
                        "version": result.tool_version,
                        "informationUri": "https://github.com/",
                        "rules": _rules(result),
                    }
                },
                "results": _results(result),
                "properties": {
                    "score": result.score.total if result.score else None,
                    "grade": result.score.grade if result.score else None,
                    "scannedAt": result.scanned_at,
                    "root": result.root,
                },
            }
        ],
    }
    return json.dumps(document, ensure_ascii=False, indent=2)
