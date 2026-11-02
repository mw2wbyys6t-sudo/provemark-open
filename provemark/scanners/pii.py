from __future__ import annotations

import json
import re
from pathlib import Path

from ..rules import pii as rules
from .base import Context, make_finding
from .dedup import merge as merge_duplicates
from .dedup import tag as tag_duplicate

DOC_SUFFIXES = (".md", ".rst", ".txt", ".adoc")
SKIP_SUFFIXES = (".min.js", ".min.css", ".map", ".snap", ".svg", ".lock", ".pyc")
SKIP_NAMES = (
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "Cargo.lock",
    "go.sum",
    "composer.lock",
    "Gemfile.lock",
    # Manifests carry the author's public contact address; that is package
    # metadata, not personal data found in the code.
    "pyproject.toml",
    "package.json",
    "composer.json",
    "Cargo.toml",
    "setup.py",
    "setup.cfg",
    "PKG-INFO",
)
SNAPSHOT_EMAIL_THRESHOLD = 20
MAX_FINDINGS_PER_FILE = 40
LOG_INTERPOLATED = re.compile(
    r"(?i)(\{[^}]*(email|phone|mobile|nric|nik|mykad|philsys|card|address)[^}]*\}"
    r"|\+\s*[\w.]*(email|phone|mobile|nric|nik|mykad|philsys|card))"
)


def jurisdictions(root: Path) -> tuple[str, ...]:
    path = root / ".pdp-compliance.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ()
    section = data.get("personalDataProtection") or {}
    items = section.get("jurisdictions") or []
    return tuple(str(item) for item in items if item in rules.JURISDICTIONS)


def _skip(info) -> bool:
    name = info.path.name
    if name in SKIP_NAMES:
        return True
    lowered = info.rel.lower()
    return lowered.endswith(SKIP_SUFFIXES)


def _severity(base: str, is_doc: bool, is_test: bool) -> str:
    order = ["critical", "high", "medium", "low", "info"]
    index = order.index(base)
    if is_test:
        index = min(len(order) - 1, index + 1)
    if is_doc:
        index = len(order) - 1
    return order[index]


def _line_findings(
    line: str,
    info,
    lineno: int,
    is_doc: bool,
    is_test: bool,
    active: tuple[str, ...],
) -> list:
    findings: list = []

    for match in rules.EMAIL.finditer(line):
        local, domain = match.group(1), match.group(2)
        if rules.is_placeholder_email(local, domain):
            continue
        severity = _severity("low", is_doc, is_test)
        masked = rules.mask_email(local, domain)
        findings.append(
            tag_duplicate(
                make_finding(
                    "PII-001",
                    "pii",
                    severity,
                    "仓库中出现邮箱地址",
                    f"在 {info.rel} 第 {lineno} 行发现邮箱地址，若对应真实用户，属于个人信息。",
                    path=info.rel,
                    line=lineno,
                    column=match.start() + 1,
                    evidence=masked,
                    remediation="测试数据改用 example.com 等保留域名；真实数据不要入库。",
                    confidence=0.35 if (is_doc or is_test) else 0.6,
                    detail={"kind": "email"},
                ),
                "PII-001",
                f"{local}@{domain}".lower(),
            )
        )

    for match in rules.PHONE_CANDIDATE.finditer(line):
        raw = match.group(0)
        digits = re.sub(r"\D", "", raw)
        if len(set(digits)) <= 2:
            continue
        has_plus = raw.strip().startswith("+")
        context = bool(rules.SENSITIVE_NAME.search(line))
        jurisdiction = rules.phone_jurisdiction(digits, has_plus, context)
        if not jurisdiction:
            continue
        if active and jurisdiction not in active and not has_plus:
            continue
        severity = _severity("medium", is_doc, is_test)
        findings.append(
            tag_duplicate(
                make_finding(
                    "PII-002",
                    "pii",
                    severity,
                    "仓库中出现手机号",
                    f"在 {info.rel} 第 {lineno} 行发现符合 {jurisdiction} 号段规则的手机号。",
                    path=info.rel,
                    line=lineno,
                    column=match.start() + 1,
                    evidence=rules.mask_tail(digits),
                    remediation="改用脱敏样例（如 +65****1234），真实号码移出仓库。",
                    confidence=0.65 if has_plus else 0.45,
                    detail={"kind": "phone", "jurisdiction": jurisdiction},
                ),
                "PII-002",
                digits,
            )
        )

    used_ids: set[str] = set()

    for match in rules.SG_NRIC.finditer(line):
        prefix, digits, check = match.group(1), match.group(2), match.group(3)
        if "sg-pdpa" not in active:
            continue
        if not rules.sg_nric_ok(prefix, digits, check):
            continue
        used_ids.add(f"{prefix}{digits}{check}")
        findings.append(
            tag_duplicate(
                _gov_id(
                    info,
                    lineno,
                    match.start(),
                    f"{prefix}{digits}{check}",
                    "sg-pdpa",
                    0.9,
                    _severity("high", is_doc, is_test),
                ),
                "PII-003",
                f"{prefix}{digits}{check}",
            )
        )

    for match in rules.DIGITS_13.finditer(line):
        value = match.group(1)
        if "th-pdpa" not in active or value in used_ids:
            continue
        if not rules.th_id_ok(value):
            continue
        used_ids.add(value)
        findings.append(
            tag_duplicate(
                _gov_id(
                    info,
                    lineno,
                    match.start(),
                    value,
                    "th-pdpa",
                    0.9,
                    _severity("high", is_doc, is_test),
                ),
                "PII-003",
                value,
            )
        )

    for match in rules.DIGITS_16.finditer(line):
        value = match.group(1)
        if value in used_ids:
            continue
        if "id-pdp" not in active or not rules.nik_ok(value):
            continue
        if rules.card_ok(value) and not rules.NIK_HINT.search(line):
            continue
        used_ids.add(value)
        findings.append(
            tag_duplicate(
                _gov_id(
                    info,
                    lineno,
                    match.start(),
                    value,
                    "id-pdp",
                    0.85,
                    _severity("high", is_doc, is_test),
                ),
                "PII-003",
                value,
            )
        )

    for match in rules.DIGITS_12.finditer(line):
        value = match.group(1)
        if "my-pdpa" in active and rules.mykad_ok(value):
            used_ids.add(value)
            findings.append(
                tag_duplicate(
                    _gov_id(
                        info,
                        lineno,
                        match.start(),
                        value,
                        "my-pdpa",
                        0.8,
                        _severity("high", is_doc, is_test),
                    ),
                    "PII-003",
                    value,
                )
            )
        elif "ph-dpa" in active and rules.PHILSYS_HINT.search(line):
            used_ids.add(value)
            findings.append(
                tag_duplicate(
                    _gov_id(
                        info,
                        lineno,
                        match.start(),
                        value,
                        "ph-dpa",
                        0.65,
                        _severity("high", is_doc, is_test),
                    ),
                    "PII-003",
                    value,
                )
            )

    for match in rules.CARD.finditer(line):
        raw = match.group(1)
        digits = re.sub(r"\D", "", raw)
        if digits in used_ids:
            continue
        if not rules.card_ok(raw):
            continue
        test_card = digits in rules.TEST_CARDS
        findings.append(
            tag_duplicate(
                make_finding(
                    "PII-004",
                    "pii",
                    _severity("low" if test_card else "high", is_doc, is_test),
                    "仓库中出现银行卡号",
                    (
                        "匹配到官方测试卡号，通常无害，但请确认不是真实卡号。"
                        if test_card
                        else f"在 {info.rel} 第 {lineno} 行发现通过 Luhn 校验的卡号。"
                    ),
                    path=info.rel,
                    line=lineno,
                    column=match.start() + 1,
                    evidence=rules.mask_card(digits),
                    remediation="立即移除并轮换支付凭证；测试请使用官方测试卡号。",
                    confidence=0.5 if test_card else 0.9,
                    detail={"kind": "card", "test_card": test_card},
                ),
                "PII-004",
                digits,
            )
        )

    if not is_doc and rules.LOG_CALL.search(line) and LOG_INTERPOLATED.search(line):
        findings.append(
            make_finding(
                "PII-006",
                "pii",
                _severity("high", False, is_test),
                "日志中输出个人信息",
                f"在 {info.rel} 第 {lineno} 行的日志语句里拼接了个人信息字段。",
                path=info.rel,
                line=lineno,
                column=rules.LOG_CALL.search(line).start() + 1,
                evidence="日志语句包含 PII 字段插值",
                remediation="打印前脱敏，或只输出内部 ID。",
                confidence=0.6 if is_test else 0.75,
                detail={"kind": "log"},
            )
        )

    if is_test:
        for finding in findings:
            finding.confidence = min(finding.confidence, 0.4)

    return findings


def _gov_id(
    info,
    lineno: int,
    column: int,
    value: str,
    jurisdiction: str,
    confidence: float,
    severity: str = "high",
):
    return make_finding(
        "PII-003",
        "pii",
        severity,
        "仓库中出现政府证件号",
        f"在 {info.rel} 第 {lineno} 行发现符合 {jurisdiction} 规则的证件号，属于敏感个人信息。",
        path=info.rel,
        line=lineno,
        column=column + 1,
        evidence=rules.mask_tail(value, 3),
        remediation="立即从仓库与历史中移除，改用掩码样例；如属生产数据，按泄露流程评估通知义务。",
        confidence=confidence,
        detail={"kind": "government_id", "jurisdiction": jurisdiction},
    )


def scan(ctx: Context) -> list:
    if not getattr(ctx.config, "pii_enabled", True):
        return []
    active = jurisdictions(ctx.root)
    findings: list = []

    for info in ctx.scoped_files():
        if not ctx.in_scope(info.rel):
            continue
        if _skip(info):
            continue
        is_doc = info.path.suffix.lower() in DOC_SUFFIXES
        is_test = info.is_test
        seen_emails: set[str] = set()
        emitted = 0
        has_emails = False

        for lineno, line in enumerate(info.lines, start=1):
            if not line or len(line) > 4000:
                continue
            if emitted >= MAX_FINDINGS_PER_FILE:
                break
            if "is_placeholder_email" in line or "_PATTERNS" in line:
                continue
            if rules.EMAIL.search(line):
                has_emails = True
                for match in rules.EMAIL.finditer(line):
                    local, domain = match.group(1), match.group(2)
                    if not rules.is_placeholder_email(local, domain):
                        seen_emails.add(f"{local}@{domain}".lower())
            for finding in _line_findings(line, info, lineno, is_doc, is_test, active):
                # Test fixtures legitimately contain fake emails/cards; flagging
                # them on every fixture line drowns the real signals.
                if is_test and finding.rule_id in ("PII-001", "PII-004"):
                    continue
                findings.append(finding)
                emitted += 1

        if (
            has_emails
            and not is_doc
            and len(seen_emails) >= SNAPSHOT_EMAIL_THRESHOLD
        ):
            findings.append(
                make_finding(
                    "PII-005",
                    "pii",
                    _severity("high", False, is_test),
                    "疑似真实用户数据快照",
                    f"{info.rel} 含 {len(seen_emails)} 个不同邮箱，形态更像数据导出而非样例。",
                    path=info.rel,
                    evidence=f"{len(seen_emails)} 个不同邮箱",
                    remediation="确认数据来源；生产数据快照不应提交，改用合成数据。",
                    confidence=0.4 if is_test else 0.7,
                    detail={"kind": "snapshot", "email_count": len(seen_emails)},
                )
            )

    return merge_duplicates(findings)
