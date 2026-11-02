from __future__ import annotations

import re

LICENSE_SIGNATURES: list[tuple[str, tuple[re.Pattern[str], ...]]] = [
    ("AGPL-3.0-only", (re.compile(r"GNU AFFERO GENERAL PUBLIC LICENSE", re.I), re.compile(r"Version 3", re.I))),
    ("LGPL-3.0-only", (re.compile(r"GNU LESSER GENERAL PUBLIC LICENSE", re.I), re.compile(r"Version 3", re.I))),
    ("LGPL-2.1-only", (re.compile(r"GNU LESSER GENERAL PUBLIC LICENSE", re.I), re.compile(r"Version 2\.1", re.I))),
    ("GPL-3.0-only", (re.compile(r"GNU GENERAL PUBLIC LICENSE", re.I), re.compile(r"Version 3", re.I))),
    ("GPL-2.0-only", (re.compile(r"GNU GENERAL PUBLIC LICENSE", re.I), re.compile(r"Version 2", re.I))),
    ("Apache-2.0", (re.compile(r"Apache License", re.I), re.compile(r"Version 2\.0", re.I))),
    ("MPL-2.0", (re.compile(r"Mozilla Public License", re.I), re.compile(r"2\.0", re.I))),
    ("EPL-2.0", (re.compile(r"Eclipse Public License", re.I),)),
    ("CDDL-1.0", (re.compile(r"COMMON DEVELOPMENT AND DISTRIBUTION LICENSE", re.I),)),
    ("BSD-3-Clause", (
        re.compile(r"Redistribution and use in source and binary forms", re.I),
        re.compile(r"Neither the name", re.I),
    )),
    ("BSD-2-Clause", (re.compile(r"Redistribution and use in source and binary forms", re.I),)),
    ("MIT", (re.compile(r"Permission is hereby granted, free of charge", re.I),)),
    ("MIT", (re.compile(r"^\s*MIT License", re.I | re.M),)),
    ("ISC", (re.compile(r"Permission to use, copy, modify, and(/or)? distribute", re.I),)),
    ("ISC", (re.compile(r"^\s*ISC License", re.I | re.M),)),
    ("Unlicense", (re.compile(r"free and unencumbered software released into the public domain", re.I),)),
    ("CC0-1.0", (re.compile(r"CC0 1\.0 Universal", re.I),)),
    ("BSL-1.0", (re.compile(r"Boost Software License", re.I),)),
    ("Zlib", (re.compile(r"altered source versions must be plainly marked", re.I),)),
    ("WTFPL", (re.compile(r"DO WHAT THE FUCK YOU WANT", re.I),)),
    ("SSPL-1.0", (re.compile(r"Server Side Public License", re.I),)),
    ("BUSL-1.1", (re.compile(r"Business Source License", re.I),)),
    ("Elastic-2.0", (re.compile(r"Elastic License 2\.0", re.I),)),
]

PERMISSIVE = {
    "0BSD",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSL-1.0",
    "CC0-1.0",
    "ISC",
    "MIT",
    "MIT-0",
    "OFL-1.1",
    "PostgreSQL",
    "PSF-2.0",
    "Python-2.0",
    "Unlicense",
    "WTFPL",
    "Zlib",
}
WEAK_COPYLEFT = {
    "CDDL-1.0",
    "CDDL-1.1",
    "EPL-2.0",
    "LGPL-2.1",
    "LGPL-2.1-only",
    "LGPL-2.1-or-later",
    "LGPL-3.0",
    "LGPL-3.0-only",
    "LGPL-3.0-or-later",
    "MPL-2.0",
}
STRONG_COPYLEFT = {
    "AGPL-3.0",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "GPL-2.0",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
}
SOURCE_AVAILABLE = {"BUSL-1.1", "Elastic-2.0", "SSPL-1.0"}

ALIASES = {
    "apache 2.0": "Apache-2.0",
    "apache-2": "Apache-2.0",
    "apache2": "Apache-2.0",
    "apache-2.0": "Apache-2.0",
    "asl 2.0": "Apache-2.0",
    "mit license": "MIT",
    "mit-license": "MIT",
    "the mit license": "MIT",
    "bsd": "BSD-3-Clause",
    "bsd 3-clause": "BSD-3-Clause",
    "bsd-3": "BSD-3-Clause",
    "new bsd": "BSD-3-Clause",
    "bsd 2-clause": "BSD-2-Clause",
    "gplv3": "GPL-3.0-only",
    "gpl-3": "GPL-3.0-only",
    "gplv2": "GPL-2.0-only",
    "gpl-2": "GPL-2.0-only",
    "lgplv3": "LGPL-3.0-only",
    "agplv3": "AGPL-3.0-only",
    "mpl2": "MPL-2.0",
    "mpl 2.0": "MPL-2.0",
    "isc license": "ISC",
    "unlicense": "Unlicense",
    "the unlicense": "Unlicense",
    "public domain": "Unlicense",
    "psf": "PSF-2.0",
    "python software foundation license": "PSF-2.0",
    "zlib/libpng": "Zlib",
    "wtfpl": "WTFPL",
    "openfont-1.1": "OFL-1.1",
    "openfont license 1.1": "OFL-1.1",
    "the apache software license, version 2.0": "Apache-2.0",
    "apache license, version 2.0": "Apache-2.0",
    "apache software license 2.0": "Apache-2.0",
    "eclipse public license 1.0": "EPL-1.0",
    "eclipse public license 2.0": "EPL-2.0",
    "eclipse public license - v 1.0": "EPL-1.0",
    "eclipse public license - v 2.0": "EPL-2.0",
    "the bsd license": "BSD-3-Clause",
    "bsd 3-clause license": "BSD-3-Clause",
    "common development and distribution license": "CDDL-1.0",
    "cddl + gplv2 with classpath exception": "CDDL-1.0",
    "gpl v2 with classpath exception": "GPL-2.0-only",
    "mozilla public license version 2.0": "MPL-2.0",
    "go license": "BSD-3-Clause",
    "non-standard": "",
    "unknown": "",
    "noassertion": "",
    "none": "",
    "": "",
}

FAMILY_LABEL = {
    "permissive": "宽松",
    "weak-copyleft": "弱传染（文件级）",
    "strong-copyleft": "强传染（项目级）",
    "source-available": "源码可见但受限",
    "unknown": "未知",
}

FAMILY_EXPLAIN = {
    "permissive": "可商用、可闭源分发，保留版权与许可声明即可。",
    "weak-copyleft": "修改该依赖自身的文件需要公开；通常不要求你的整个项目开源，但需要保留声明并提供源码。",
    "strong-copyleft": "一旦分发包含该依赖的作品，整个作品需要以相同许可证开源；闭源分发会违规。",
    "source-available": "可查看源码但使用受限（禁止托管服务/商业竞争等），需要逐条读条款。",
    "unknown": "未能确定许可证，等于没有获得明确授权，商用前必须人工确认。",
}


def normalize_spdx(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return ""
    text = re.sub(r"^\(|\)$", "", text)
    lowered = text.lower()
    if lowered in ALIASES:
        return ALIASES[lowered]
    for prefix in ("License :: OSI Approved :: ", "License :: "):
        if text.startswith(prefix):
            text = text[len(prefix) :]
    text = text.split(" :: ")[0]
    lowered = text.lower()
    if lowered in ALIASES:
        return ALIASES[lowered]
    cleaned = re.sub(r"\s+", "-", text)
    if cleaned.lower() in ALIASES:
        return ALIASES[cleaned.lower()]
    for known in PERMISSIVE | WEAK_COPYLEFT | STRONG_COPYLEFT | SOURCE_AVAILABLE:
        if known.lower() == cleaned.lower():
            return known
    if " " not in text and re.fullmatch(r"[A-Za-z0-9.+-]+", text):
        return cleaned
    return text


def family_of(spdx: str) -> str:
    if spdx in PERMISSIVE:
        return "permissive"
    if spdx in WEAK_COPYLEFT:
        return "weak-copyleft"
    if spdx in STRONG_COPYLEFT:
        return "strong-copyleft"
    if spdx in SOURCE_AVAILABLE:
        return "source-available"
    return "unknown"


def detect_from_text(text: str) -> str:
    if not text:
        return ""
    head = text[:20000]
    for spdx, patterns in LICENSE_SIGNATURES:
        if all(pattern.search(head) for pattern in patterns):
            return spdx
    return ""


SPLIT_OR = re.compile(r"\s+OR\s+|\s*/\s*", re.I)
SPLIT_AND = re.compile(r"\s+AND\s+|\s+WITH\s+", re.I)


def split_expression(expression: str) -> tuple[list[str], list[str]]:
    text = (expression or "").strip()
    if not text:
        return [], []
    if SPLIT_AND.search(text):
        parts = [part for part in SPLIT_AND.split(text) if part.strip()]
        return [normalize_spdx(part) for part in parts], []
    if SPLIT_OR.search(text):
        parts = [part for part in SPLIT_OR.split(text) if part.strip()]
        return [], [normalize_spdx(part) for part in parts]
    return [normalize_spdx(text)], []


def status_of(spdx: str, policy) -> str:
    if not spdx:
        return "unknown"
    if spdx in policy.deny:
        return "deny"
    if spdx in policy.allow:
        return "allow"
    if spdx in policy.warn:
        return "warn"
    family = family_of(spdx)
    if family == "permissive":
        return "allow"
    if family == "weak-copyleft":
        return "warn"
    if family in ("strong-copyleft", "source-available"):
        return "deny"
    return "unknown"


_WORST = {"deny": 3, "unknown": 2, "warn": 1, "allow": 0}


def evaluate(expression: str, policy) -> tuple[str, list[str]]:
    and_parts, or_parts = split_expression(expression)
    if or_parts:
        results = [(part, status_of(part, policy)) for part in or_parts]
        best = min(results, key=lambda item: _WORST[item[1]])
        return best[1], [best[0]]
    if not and_parts:
        return "unknown", []
    results = [(part, status_of(part, policy)) for part in and_parts]
    worst = max(results, key=lambda item: _WORST[item[1]])
    return worst[1], [part for part, _ in results]


def explain(spdx: str) -> str:
    return FAMILY_EXPLAIN[family_of(spdx)]
