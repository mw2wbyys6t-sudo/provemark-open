from __future__ import annotations

from .license_data import split_expression

OK = "ok"
CONDITIONAL = "conditional"
INCOMPATIBLE = "incompatible"
UNKNOWN = "unknown"

_PERMISSIVE = {
    "0BSD",
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
_CLASSES: dict[str, set[str]] = {
    "permissive": _PERMISSIVE,
    "apache": {"Apache-2.0"},
    "mpl": {"MPL-2.0"},
    "epl": {"EPL-1.0", "EPL-2.0", "CDDL-1.0", "CDDL-1.1"},
    "lgpl2": {"LGPL-2.1", "LGPL-2.1-only", "LGPL-2.1-or-later"},
    "lgpl3": {"LGPL-3.0", "LGPL-3.0-only", "LGPL-3.0-or-later"},
    "gpl2": {"GPL-2.0", "GPL-2.0-only"},
    "gpl2plus": {"GPL-2.0-or-later"},
    "gpl3": {"GPL-3.0", "GPL-3.0-only", "GPL-3.0-or-later"},
    "agpl3": {"AGPL-3.0", "AGPL-3.0-only", "AGPL-3.0-or-later"},
    "source-available": {"BUSL-1.1", "Elastic-2.0", "SSPL-1.0"},
}

_O = OK
_C = CONDITIONAL
_X = INCOMPATIBLE
_Q = UNKNOWN

MATRIX: dict[str, dict[str, str]] = {
    "permissive": {
        "permissive": _O, "apache": _O, "mpl": _C, "epl": _C, "lgpl2": _C,
        "lgpl3": _C, "gpl2": _X, "gpl2plus": _X, "gpl3": _X, "agpl3": _X,
        "source-available": _Q,
    },
    "apache": {
        "permissive": _O, "apache": _O, "mpl": _C, "epl": _C, "lgpl2": _C,
        "lgpl3": _C, "gpl2": _X, "gpl2plus": _C, "gpl3": _X, "agpl3": _X,
        "source-available": _Q,
    },
    "mpl": {
        "permissive": _O, "apache": _O, "mpl": _C, "epl": _C, "lgpl2": _C,
        "lgpl3": _C, "gpl2": _C, "gpl2plus": _C, "gpl3": _C, "agpl3": _C,
        "source-available": _Q,
    },
    "epl": {
        "permissive": _O, "apache": _O, "mpl": _C, "epl": _C, "lgpl2": _C,
        "lgpl3": _C, "gpl2": _C, "gpl2plus": _C, "gpl3": _C, "agpl3": _C,
        "source-available": _Q,
    },
    "lgpl2": {
        "permissive": _O, "apache": _O, "mpl": _C, "epl": _C, "lgpl2": _C,
        "lgpl3": _C, "gpl2": _O, "gpl2plus": _O, "gpl3": _C, "agpl3": _C,
        "source-available": _Q,
    },
    "lgpl3": {
        "permissive": _O, "apache": _O, "mpl": _C, "epl": _C, "lgpl2": _C,
        "lgpl3": _O, "gpl2": _X, "gpl2plus": _C, "gpl3": _O, "agpl3": _C,
        "source-available": _Q,
    },
    "gpl2": {
        "permissive": _O, "apache": _X, "mpl": _C, "epl": _X, "lgpl2": _C,
        "lgpl3": _X, "gpl2": _O, "gpl2plus": _O, "gpl3": _X, "agpl3": _X,
        "source-available": _Q,
    },
    "gpl2plus": {
        "permissive": _O, "apache": _O, "mpl": _C, "epl": _C, "lgpl2": _C,
        "lgpl3": _C, "gpl2": _O, "gpl2plus": _O, "gpl3": _O, "agpl3": _C,
        "source-available": _Q,
    },
    "gpl3": {
        "permissive": _O, "apache": _O, "mpl": _O, "epl": _X, "lgpl2": _C,
        "lgpl3": _O, "gpl2": _X, "gpl2plus": _O, "gpl3": _O, "agpl3": _C,
        "source-available": _Q,
    },
    "agpl3": {
        "permissive": _O, "apache": _O, "mpl": _O, "epl": _X, "lgpl2": _C,
        "lgpl3": _O, "gpl2": _X, "gpl2plus": _O, "gpl3": _O, "agpl3": _O,
        "source-available": _Q,
    },
    "source-available": {
        "permissive": _O, "apache": _O, "mpl": _C, "epl": _C, "lgpl2": _C,
        "lgpl3": _C, "gpl2": _X, "gpl2plus": _X, "gpl3": _X, "agpl3": _X,
        "source-available": _Q,
    },
}

REASONS = {
    "apache->gpl2": "Apache-2.0 的专利与赔偿条款与 GPL-2.0-only 不兼容",
    "gpl2->apache": "GPL-2.0-only 项目无法吸收 Apache-2.0 的专利与赔偿条款",
    "gpl2->gpl3": "GPL-2.0-only 代码不能升级到 GPL-3.0",
    "gpl3->gpl2": "GPL-2.0-only 代码不能并入 GPL-3.0 项目",
    "agpl3->gpl2": "GPL-2.0-only 代码不能并入 AGPL-3.0 项目",
    "gpl2->agpl3": "AGPL-3.0 与 GPL-2.0-only 的版本条款不兼容",
    "gpl2->lgpl3": "LGPL-3.0 要求 GPL-3.0 的兼容条款，无法并入 GPL-2.0-only",
    "lgpl3->gpl2": "LGPL-3.0 依赖不能并入 GPL-2.0-only 项目",
    "gpl2->epl": "EPL / CDDL 与 GPL-2.0-only 不兼容",
    "gpl3->epl": "EPL / CDDL 与 GPL-3.0 不兼容",
    "agpl3->epl": "EPL / CDDL 与 AGPL-3.0 不兼容",
    "permissive->gpl2": "强传染许可证会要求整个作品以 GPL 开源",
    "permissive->gpl2plus": "强传染许可证会要求整个作品以 GPL 开源",
    "permissive->gpl3": "强传染许可证会要求整个作品以 GPL 开源",
    "permissive->agpl3": "AGPL 的网络使用条款会覆盖整个作品",
    "apache->gpl3": "强传染许可证会要求整个作品以 GPL 开源",
    "apache->agpl3": "AGPL 的网络使用条款会覆盖整个作品",
    "gpl3->agpl3": "AGPL 的网络使用条款会覆盖整个作品",
    "source-available->gpl2": "源码可见许可证的使用限制与 GPL 分发义务冲突",
    "source-available->gpl2plus": "源码可见许可证的使用限制与 GPL 分发义务冲突",
    "source-available->gpl3": "源码可见许可证的使用限制与 GPL 分发义务冲突",
    "source-available->agpl3": "源码可见许可证的使用限制与 AGPL 分发义务冲突",
}

_GENERIC_INCOMPATIBLE = "两份许可证的分发义务无法同时满足"
_RANK = {OK: 0, CONDITIONAL: 1, UNKNOWN: 2, INCOMPATIBLE: 3}


def compat_class(spdx: str) -> str:
    text = (spdx or "").strip()
    if not text:
        return "unknown"
    for name, members in _CLASSES.items():
        if text in members:
            return name
    return "unknown"


def _single(project: str, dependency: str) -> tuple[str, str]:
    dep = compat_class(dependency)
    if dep == "unknown":
        return UNKNOWN, f"{dependency or '未知许可证'} 不在兼容矩阵内"
    result = MATRIX[project][dep]
    if result == INCOMPATIBLE:
        return result, REASONS.get(f"{project}->{dep}", _GENERIC_INCOMPATIBLE)
    if result == UNKNOWN:
        return result, f"{project} 与 {dep} 的组合需要人工确认"
    return result, ""


def verdict(project_spdx: str, dependency_expression: str) -> tuple[str, str]:
    project = compat_class(project_spdx)
    if project == "unknown":
        return UNKNOWN, f"{project_spdx or '未知许可证'} 不在兼容矩阵内"
    and_parts, or_parts = split_expression(dependency_expression)
    if or_parts:
        outcomes = [_single(project, part) for part in or_parts]
        return min(outcomes, key=lambda item: _RANK[item[0]])
    if not and_parts:
        return UNKNOWN, "依赖许可证无法归类"
    outcomes = [_single(project, part) for part in and_parts]
    return max(outcomes, key=lambda item: _RANK[item[0]])
