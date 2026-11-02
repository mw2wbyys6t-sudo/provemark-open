from __future__ import annotations

import datetime as _dt
import fnmatch
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CONFIG_NAMES = (
    ".provemark.toml",
    "provemark.toml",
    ".provemark.yml",
    ".provemark.yaml",
    # 0.3 及更早的旧名，只读兼容；写入统一用新名
    ".reposentinel.toml",
    "reposentinel.toml",
    ".reposentinel.yml",
    ".reposentinel.yaml",
)

DEFAULT_EXCLUDES = [
    ".git/**",
    ".hg/**",
    ".svn/**",
    "node_modules/**",
    "__pycache__/**",
    "*.pyc",
    ".venv/**",
    "venv/**",
    "env/**",
    ".mypy_cache/**",
    ".pytest_cache/**",
    ".ruff_cache/**",
    ".tox/**",
    "dist/**",
    "build/**",
    "target/**",
    ".next/**",
    "out/**",
    "coverage/**",
    "htmlcov/**",
    ".idea/**",
    ".vscode/**",
    "vendor/**",
    "Pods/**",
    ".gradle/**",
    ".dart_tool/**",
    ".stack-work/**",
    ".nuget/**",
    "obj/**",
    "_build/**",
    "*.lock.bak",
    "package-lock.json.bak",
]


def _matches_any(rel: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        if fnmatch.fnmatch(rel, pattern):
            return True
        # `dir/**` must also cover the directory itself ("dir"), which fnmatch
        # alone does not: "vendor/**" matches "vendor/x" but not "vendor".
        if pattern.endswith("/**") and (rel == pattern[:-3] or rel.startswith(pattern[:-3] + "/")):
            return True
    return False

PERMISSIVE = [
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
    "Python-2.0",
    "PSF-2.0",
    "Unlicense",
    "WTFPL",
    "Zlib",
]
WEAK_COPYLEFT = [
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
]
STRONG_COPYLEFT = [
    "AGPL-3.0",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "GPL-2.0",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "SSPL-1.0",
    "BUSL-1.1",
    "Elastic-2.0",
]


class ConfigError(Exception):
    pass


@dataclass
class IgnoreRule:
    reason: str = ""
    expires: str = ""
    fingerprint: str = ""
    rule: str = ""
    path: str = ""
    created: str = ""

    def is_expired(self, today: _dt.date | None = None) -> bool:
        if not self.expires:
            return False
        today = today or _dt.date.today()
        try:
            return _dt.date.fromisoformat(self.expires) < today
        except ValueError:
            return True

    def matches(self, finding: Any) -> bool:
        if self.fingerprint and self.fingerprint == finding.fingerprint:
            return True
        if self.rule and self.rule != "*" and self.rule != finding.rule_id:
            return False
        if self.path and not fnmatch.fnmatch(finding.path, self.path):
            return False
        return bool(self.rule or self.path)

    def to_toml(self) -> str:
        parts = []
        if self.fingerprint:
            parts.append(f'fingerprint = "{self.fingerprint}"')
        if self.rule:
            parts.append(f'rule = "{self.rule}"')
        if self.path:
            parts.append(f'path = "{self.path}"')
        parts.append(f'reason = "{self.reason}"')
        if self.expires:
            parts.append(f'expires = "{self.expires}"')
        if self.created:
            parts.append(f'created = "{self.created}"')
        return "[[ignore]]\n" + "\n".join(parts) + "\n"


@dataclass
class LicensePolicy:
    allow: list[str] = field(default_factory=lambda: list(PERMISSIVE))
    warn: list[str] = field(default_factory=lambda: list(WEAK_COPYLEFT))
    deny: list[str] = field(default_factory=lambda: list(STRONG_COPYLEFT))
    unknown: str = "medium"
    no_license: str = "high"
    exceptions: dict[str, str] = field(default_factory=dict)


@dataclass
class Config:
    root: Path
    config_path: Path | None = None
    project_kind: str = "library"
    project_license: str = ""
    exclude: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    max_file_bytes: int = 1_500_000
    max_files: int = 40000
    fail_on: str = "high"
    min_confidence: float = 0.5
    severity_floor: str = "info"
    pii_enabled: bool = True
    network_enabled: bool = True
    timeout: float = 20.0
    severity_overrides: dict[str, str] = field(default_factory=dict)
    ignore: list[IgnoreRule] = field(default_factory=list)
    license_policy: LicensePolicy = field(default_factory=LicensePolicy)
    supply_allowed_indexes: list[str] = field(
        default_factory=lambda: [
            "pypi.org",
            "registry.npmjs.org",
            "proxy.golang.org",
            "crates.io",
            "github.com",
            "repo1.maven.org",
            "repo.packagist.org",
            "rubygems.org",
            "api.nuget.org",
            "pub.dev",
            "hex.pm",
        ]
    )
    ai_allow_debug_logs: bool = False
    allowed_licenses_project: list[str] = field(default_factory=lambda: list(PERMISSIVE))

    def is_excluded(self, rel_path: str) -> bool:
        rel = rel_path.replace("\\", "/")
        return _matches_any(rel, self.exclude)

    def user_excludes(self) -> list[str]:
        """Patterns the user added on top of the built-in defaults.

        Content scanning rightly skips `vendor/**`, `dist/**` and friends out of
        the box, but vendored-attribution rules exist *for* those directories.
        "Do not scan its contents" and "this path is out of scope" are different
        statements, so the vendored rules only honour the latter.
        """
        defaults = set(DEFAULT_EXCLUDES)
        return [pattern for pattern in self.exclude if pattern not in defaults]

    def is_excluded_by_user(self, rel_path: str) -> bool:
        rel = rel_path.replace("\\", "/")
        return _matches_any(rel, self.user_excludes())


def _as_list(value: Any, key: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ConfigError(f"`{key}` 必须是字符串数组")
    return list(value)


def _as_bool(value: Any, key: str, default: bool) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ConfigError(f"`{key}` 必须是 true / false")
    return value


SEVERITY_VALUES = ("critical", "high", "medium", "low", "info")
GATE_VALUES = ("none",) + SEVERITY_VALUES
PROJECT_KINDS = ("library", "app", "docs")
RULE_ID_PATTERN = re.compile(r"^[A-Z]{2,3}-\d{3}$")


def _as_positive_int(value: Any, key: str, default: int) -> int:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"`{key}` 必须是整数，不要加引号（当前是 {value!r}）")
    if value <= 0:
        raise ConfigError(f"`{key}` 必须大于 0（当前是 {value}）")
    return value


def _as_positive_float(value: Any, key: str, default: float) -> float:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"`{key}` 必须是数字，不要加引号（当前是 {value!r}）")
    if value <= 0:
        raise ConfigError(f"`{key}` 必须大于 0（当前是 {value}）")
    return float(value)


def _as_enum(value: Any, key: str, allowed: tuple[str, ...], default: str) -> str:
    if value is None:
        return default
    text = str(value)
    if text not in allowed:
        raise ConfigError(f"`{key}` 只能是 {' / '.join(allowed)}，当前是 {text!r}")
    return text


def _as_ratio(value: Any, key: str, default: float) -> float:
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"`{key}` 必须是 0 到 1 之间的数字（当前是 {value!r}）")
    if not 0 <= value <= 1:
        raise ConfigError(f"`{key}` 必须在 0 到 1 之间（当前是 {value}）")
    return float(value)


def _as_bool(value: Any, key: str, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("true", "yes", "1", "on"):
        return True
    if text in ("false", "no", "0", "off"):
        return False
    raise ConfigError(f"`{key}` 只能是 true / false（当前是 {value!r}）")


def _load_yaml(path: Path) -> dict[str, Any]:
    try:
        import yaml
    except ModuleNotFoundError as exc:
        raise ConfigError(
            f"检测到 {path.name}，但当前环境没有 PyYAML。"
            "请改用 .provemark.toml（零依赖），或执行 pip install pyyaml。"
        ) from exc
    with path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ConfigError(f"{path.name} 顶层必须是映射结构")
    return data


def find_config_file(root: Path) -> Path | None:
    for name in CONFIG_NAMES:
        candidate = root / name
        if candidate.is_file():
            return candidate
    return None


def load_config(root: Path, config_path: Path | None = None) -> Config:
    root = root.resolve()
    path = config_path or find_config_file(root)
    config = Config(root=root)
    if path is None:
        return config
    if not path.is_file():
        raise ConfigError(f"配置文件不存在：{path}")

    if path.suffix in (".yml", ".yaml"):
        raw = _load_yaml(path)
    else:
        try:
            with path.open("rb") as handle:
                raw = tomllib.load(handle)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"{path.name} 解析失败：{exc}") from exc

    config.config_path = path
    project = raw.get("project") or {}
    config.project_kind = _as_enum(project.get("kind"), "project.kind", PROJECT_KINDS, "library")
    config.project_license = str(project.get("license") or "")
    config.allowed_licenses_project = _as_list(
        project.get("allowed_licenses"), "project.allowed_licenses"
    ) or list(PERMISSIVE)

    scan = raw.get("scan") or {}
    if scan.get("exclude") is not None:
        config.exclude = _as_list(scan.get("exclude"), "scan.exclude")
    config.max_file_bytes = _as_positive_int(
        scan.get("max_file_bytes"), "scan.max_file_bytes", config.max_file_bytes
    )
    config.max_files = _as_positive_int(scan.get("max_files"), "scan.max_files", config.max_files)
    config.severity_floor = _as_enum(
        scan.get("severity_floor"), "scan.severity_floor", SEVERITY_VALUES, config.severity_floor
    )

    gate = raw.get("gate") or {}
    config.fail_on = _as_enum(gate.get("fail_on"), "gate.fail_on", GATE_VALUES, config.fail_on)
    config.min_confidence = _as_ratio(
        gate.get("min_confidence"), "gate.min_confidence", config.min_confidence
    )
    pii_section = raw.get("pii") or {}
    config.pii_enabled = _as_bool(pii_section.get("enabled"), "pii.enabled", config.pii_enabled)

    network = raw.get("network") or {}
    config.network_enabled = _as_bool(network.get("enabled"), "network.enabled", True)
    config.timeout = _as_positive_float(network.get("timeout"), "network.timeout", config.timeout)

    severity = raw.get("severity") or {}
    if severity:
        if not isinstance(severity, dict):
            raise ConfigError("`[severity]` 必须是 `规则ID = 级别` 的映射")
        overrides: dict[str, str] = {}
        for rule_id, level in severity.items():
            key = str(rule_id).upper()
            if not RULE_ID_PATTERN.match(key):
                raise ConfigError(f"`[severity]` 的键应为规则 ID（如 AI-004），当前是 {rule_id!r}")
            overrides[key] = _as_enum(level, f"severity.{key}", SEVERITY_VALUES, "medium")
        config.severity_overrides = overrides

    ai = raw.get("ai") or {}
    config.ai_allow_debug_logs = _as_bool(ai.get("allow_debug_logs"), "ai.allow_debug_logs", False)

    supply = raw.get("supply") or {}
    if supply.get("allowed_indexes") is not None:
        config.supply_allowed_indexes = _as_list(
            supply.get("allowed_indexes"), "supply.allowed_indexes"
        )

    license_raw = raw.get("license") or {}
    policy = LicensePolicy()
    if license_raw.get("allow") is not None:
        policy.allow = _as_list(license_raw.get("allow"), "license.allow")
    if license_raw.get("warn") is not None:
        policy.warn = _as_list(license_raw.get("warn"), "license.warn")
    if license_raw.get("deny") is not None:
        policy.deny = _as_list(license_raw.get("deny"), "license.deny")
    policy.unknown = _as_enum(
        license_raw.get("unknown"), "license.unknown", SEVERITY_VALUES, policy.unknown
    )
    policy.no_license = _as_enum(
        license_raw.get("no_license"), "license.no_license", SEVERITY_VALUES, policy.no_license
    )
    exceptions = license_raw.get("exceptions") or {}
    if not isinstance(exceptions, dict):
        raise ConfigError("`license.exceptions` 必须是 `包名 = 原因` 的映射")
    policy.exceptions = {str(k): str(v) for k, v in exceptions.items()}
    config.license_policy = policy

    ignores_raw = raw.get("ignore") or []
    if not isinstance(ignores_raw, list):
        raise ConfigError("`ignore` 必须是数组")
    for item in ignores_raw:
        if not isinstance(item, dict):
            raise ConfigError("每个 `[[ignore]]` 必须是表")
        rule = IgnoreRule(
            reason=str(item.get("reason") or ""),
            expires=str(item.get("expires") or ""),
            fingerprint=str(item.get("fingerprint") or ""),
            rule=str(item.get("rule") or ""),
            path=str(item.get("path") or ""),
            created=str(item.get("created") or ""),
        )
        if not rule.reason:
            raise ConfigError("每条 ignore 都必须写 reason（为什么要接受这个风险）")
        if not (rule.fingerprint or rule.rule or rule.path):
            raise ConfigError("每条 ignore 至少需要 fingerprint / rule / path 之一")
        config.ignore.append(rule)

    return config


DEFAULT_CONFIG_TEMPLATE = """# Provemark 策略文件
# 文档：README.md

[project]
# library | app | docs   —— 文档型仓库不强制要求许可证
kind = "library"
# 留空则自动从 LICENSE 文件推断
license = ""

[scan]
# 额外排除的路径（glob）
# exclude = ["node_modules/**", "vendor/**"]
max_file_bytes = 1500000

[gate]
# none | low | medium | high | critical
fail_on = "high"
# 低于该置信度的问题不参与门禁（0 = 全部参与，0.5 = 只拦较确定的问题）
min_confidence = 0.5

[license]
# 允许 / 需关注 / 禁止 的 SPDX 标识
# allow = ["MIT", "Apache-2.0"]
# deny  = ["GPL-3.0-only", "AGPL-3.0-only"]
unknown = "medium"

[license.exceptions]
# "pkg-name" = "仅内部工具使用，不分发"

[pii]
# 扫描仓库中的邮箱、手机号、证件号、银行卡号
# 适用辖区在 .pdp-compliance.json 里声明；未声明时只做通用格式识别
enabled = true

[ai]
# 生产代码里是否允许 console.log / print 调试输出
allow_debug_logs = false

[supply]
# allowed_indexes = ["pypi.org", "registry.npmjs.org"]

# [[ignore]]
# fingerprint = "0123456789abcdef"
# reason = "该告警已被上游确认误报，等 3.2 版本升级后移除"
# expires = "2027-01-31"
"""
