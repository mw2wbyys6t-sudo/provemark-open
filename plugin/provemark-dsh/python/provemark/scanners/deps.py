from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import Config
from ..models import Package
from .. import ecosystems
from . import manifests

PY_NORMALIZE = re.compile(r"[-_.]+")
REQ_NAME = re.compile(r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)\s*(?P<extras>\[[^\]]*\])?\s*(?P<spec>.*)$")
PIN_PATTERNS = (
    re.compile(r"^==\s*(?P<v>[0-9][^,\s*]*)$"),
    re.compile(r"^===\s*(?P<v>[0-9][^,\s*]*)$"),
)
SKIP_REQ_PREFIXES = ("-e ", "--editable", "-c ", "--constraint", "--find-links", "--trusted-host")


@dataclass
class DepsResult:
    packages: list[Package] = field(default_factory=list)
    manifests: list[Path] = field(default_factory=list)
    lockfiles: list[Path] = field(default_factory=list)
    declared: dict[str, set[str]] = field(default_factory=dict)
    indexes: list[dict[str, Any]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    lock_optional: set[str] = field(default_factory=set)

    def declare(self, ecosystem: str, name: str) -> None:
        self.declared.setdefault(ecosystem, set()).add(name.lower())

    def is_declared(self, ecosystem: str, name: str) -> bool:
        return name.lower() in self.declared.get(ecosystem, set())


def norm_python(name: str) -> str:
    return PY_NORMALIZE.sub("-", name.strip()).lower()


def _pin_version(spec: str) -> str:
    text = (spec or "").strip().rstrip(";").strip()
    for pattern in PIN_PATTERNS:
        match = pattern.match(text)
        if match:
            return match.group("v")
    return ""


def _split_requirement(text: str) -> tuple[str, str, str] | None:
    text = text.strip()
    if not text or text.startswith("#") or text.startswith(SKIP_REQ_PREFIXES):
        return None
    if " @ " in text:
        name_part, url = text.split(" @ ", 1)
        match = REQ_NAME.match(name_part.strip())
        if match:
            return match.group("name"), "", f"url:{url.strip()}"
    match = REQ_NAME.match(text)
    if not match:
        return None
    name = match.group("name")
    spec = (match.group("spec") or "").split(";")[0].strip()
    return name, spec, ""


def parse_requirements_txt(path: Path, root: Path, result: DepsResult, depth: int = 0) -> None:
    if depth > 8:
        return
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return
    buffer = ""
    for raw_line in lines:
        line = raw_line.split(" #")[0].rstrip() if " #" in raw_line else raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue
        full = (buffer + stripped).strip()
        buffer = ""
        if full.startswith(("-r ", "--requirement", "-c ", "--constraint")):
            target = full.split(maxsplit=1)[1].strip() if " " in full else ""
            child = (path.parent / target).resolve()
            # `-r ../../.ssh/id_rsa` must not turn a scan into an arbitrary file
            # reader outside the repository being scanned.
            if root.resolve() not in child.parents:
                continue
            if child.is_file():
                parse_requirements_txt(child, root, result, depth + 1)
            continue
        if full.startswith(("--index-url", "-i ", "--extra-index-url")):
            url = full.split("=", 1)[-1].strip() if "=" in full else full.split(maxsplit=1)[-1].strip()
            result.indexes.append(
                {"manifest": _rel(path, root), "line": 0, "url": url, "kind": "index"}
            )
            continue
        if full.startswith("--"):
            continue
        if full.startswith(("git+", "http://", "https://", "file:")):
            match = re.search(r"#egg=([A-Za-z0-9._-]+)", full)
            if match:
                name = match.group(1)
                result.declare("PyPI", norm_python(name))
                result.packages.append(
                    Package(
                        name=norm_python(name),
                        ecosystem="PyPI",
                        declared=full,
                        manifest=_rel(path, root),
                        direct=True,
                        scope=_py_scope(path),
                    )
                )
            continue
        parsed = _split_requirement(full)
        if not parsed:
            continue
        name, spec, locator = parsed
        version = _pin_version(spec)
        result.declare("PyPI", norm_python(name))
        result.packages.append(
            Package(
                name=norm_python(name),
                ecosystem="PyPI",
                version=version,
                declared=spec or locator,
                manifest=_rel(path, root),
                direct=True,
                scope=_py_scope(path),
                locator=locator,
            )
        )


def _py_scope(path: Path) -> str:
    name = path.name.lower()
    if any(token in name for token in ("dev", "test", "lint", "doc", "ci")):
        return "dev"
    return "runtime"


def parse_pyproject_toml(path: Path, root: Path, result: DepsResult) -> None:
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        result.notes.append(f"{_rel(path, root)} 解析失败，已跳过")
        return

    def add(name: str, spec: str, scope: str) -> None:
        clean = name.strip()
        if not clean or clean.lower() == "python":
            return
        version = _pin_version(spec) if spec else ""
        if not version and spec.startswith("=="):
            version = spec[2:].strip().strip("'\"")
        result.declare("PyPI", norm_python(clean))
        result.packages.append(
            Package(
                name=norm_python(clean),
                ecosystem="PyPI",
                version=version,
                declared=spec,
                manifest=_rel(path, root),
                direct=True,
                scope=scope,
            )
        )

    project = data.get("project") or {}
    for item in project.get("dependencies") or []:
        parsed = _split_requirement(str(item))
        if parsed:
            add(parsed[0], parsed[1], "runtime")
    for group, items in (project.get("optional-dependencies") or {}).items():
        for item in items or []:
            parsed = _split_requirement(str(item))
            if parsed:
                add(parsed[0], parsed[1], "dev" if group != "main" else "runtime")
    for group, items in (data.get("dependency-groups") or {}).items():
        for item in items or []:
            parsed = _split_requirement(str(item))
            if parsed:
                add(parsed[0], parsed[1], "dev")

    poetry = ((data.get("tool") or {}).get("poetry") or {})
    for group, deps in (
        ("runtime", poetry.get("dependencies") or {}),
        ("dev", poetry.get("dev-dependencies") or {}),
    ):
        for name, spec in deps.items():
            add(name, _poetry_spec(spec), group)
    for group_name, group in ((poetry.get("group") or {}).items()):
        for name, spec in (group.get("dependencies") or {}).items():
            add(name, _poetry_spec(spec), "dev" if group_name != "main" else "runtime")


def _poetry_spec(spec: Any) -> str:
    if isinstance(spec, str):
        return spec
    if isinstance(spec, dict):
        return str(spec.get("version") or "")
    if isinstance(spec, list):
        return "; ".join(_poetry_spec(item) for item in spec)
    return ""


def parse_pipfile(path: Path, root: Path, result: DepsResult) -> None:
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return
    for section, scope in (("packages", "runtime"), ("dev-packages", "dev")):
        for name, spec in (data.get(section) or {}).items():
            version = ""
            declared = "*"
            if isinstance(spec, str):
                declared = spec
                version = _pin_version(spec)
            elif isinstance(spec, dict):
                declared = str(spec.get("version") or "*")
                version = _pin_version(declared)
            result.declare("PyPI", norm_python(name))
            result.packages.append(
                Package(
                    name=norm_python(name),
                    ecosystem="PyPI",
                    version=version,
                    declared=declared,
                    manifest=_rel(path, root),
                    scope=scope,
                )
            )


def parse_package_json(path: Path, root: Path, result: DepsResult) -> None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        result.notes.append(f"{_rel(path, root)} 解析失败，已跳过")
        return
    manifest = _rel(path, root)
    for section, scope in (
        ("dependencies", "runtime"),
        ("devDependencies", "dev"),
        ("peerDependencies", "peer"),
        ("optionalDependencies", "optional"),
    ):
        for name, spec in (data.get(section) or {}).items():
            result.declare("npm", name)
            result.packages.append(
                Package(
                    name=name,
                    ecosystem="npm",
                    version=_pin_version(str(spec).lstrip("=")),
                    declared=str(spec),
                    manifest=manifest,
                    scope=scope,
                )
            )


def parse_package_lock(path: Path, root: Path, result: DepsResult) -> dict[str, str]:
    versions: dict[str, str] = {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return versions
    manifest = _rel(path, root)
    packages = data.get("packages")
    seen: set[str] = set()
    if isinstance(packages, dict):
        for key, meta in packages.items():
            if not isinstance(meta, dict) or not key:
                continue
            name = meta.get("name") or key.rsplit("node_modules/", 1)[-1]
            version = str(meta.get("version") or "")
            if not name or not version or name in seen:
                continue
            seen.add(name)
            versions[name] = version
            result.packages.append(
                Package(
                    name=name,
                    ecosystem="npm",
                    version=version,
                    declared=str(meta.get("version") or ""),
                    manifest=manifest,
                    direct=not meta.get("dev", False),
                    scope="dev" if meta.get("dev") else "runtime",
                )
            )
    else:
        for name, meta in (data.get("dependencies") or {}).items():
            if isinstance(meta, dict) and meta.get("version"):
                versions[name] = str(meta["version"])
    return versions


def parse_yarn_lock(path: Path, root: Path, result: DepsResult) -> dict[str, str]:
    versions: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return versions
    current: list[str] = []
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw.startswith((" ", "\t")):
            header = raw.rstrip(":").strip().strip('"')
            current = []
            for part in header.split(","):
                spec = part.strip().strip('"')
                name = spec.rsplit("@", 1)[0] if "@" in spec[1:] else spec
                if name.startswith("@"):
                    name = "@" + spec[1:].rsplit("@", 1)[0] if spec.count("@") > 1 else spec
                current.append(name)
            continue
        stripped = raw.strip()
        match = re.match(r'^version\s+"?([^"\s]+)"?$', stripped)
        if match and current:
            version = match.group(1)
            for name in current:
                if name:
                    versions.setdefault(name, version)
                    result.packages.append(
                        Package(
                            name=name,
                            ecosystem="npm",
                            version=version,
                            declared=version,
                            manifest=_rel(path, root),
                        )
                    )
    return versions


def parse_pnpm_lock(path: Path, root: Path, result: DepsResult) -> dict[str, str]:
    versions: dict[str, str] = {}
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return versions
    pattern = re.compile(r"^\s{2,}/?(@?[^/\s:]+(?:/[^/\s:]+)?)/([0-9][^:\s(]*)")
    pattern_v9 = re.compile(r"^\s{2,}(@?[^/\s:]+(?:/[^/\s:]+)?)@([0-9][^:\s(]*)")
    for raw in text.splitlines():
        match = pattern.match(raw) or pattern_v9.match(raw)
        if not match:
            continue
        name, version = match.group(1), match.group(2)
        if name.startswith("@"):
            versions.setdefault(name, version)
            result.packages.append(
                Package(
                    name=name,
                    ecosystem="npm",
                    version=version,
                    declared=version,
                    manifest=_rel(path, root),
                )
            )
        else:
            versions.setdefault(name, version)
            result.packages.append(
                Package(
                    name=name,
                    ecosystem="npm",
                    version=version,
                    declared=version,
                    manifest=_rel(path, root),
                )
            )
    return versions


def parse_go_mod(path: Path, root: Path, result: DepsResult) -> None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    manifest = _rel(path, root)
    in_block = False
    for raw in text.splitlines():
        line = raw.split("//")[0].strip()
        indirect = "// indirect" in raw
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        if line.startswith("require "):
            line = line[len("require ") :].strip()
        elif not in_block:
            continue
        parts = line.split()
        if len(parts) != 2:
            continue
        name, version = parts
        version = version.lstrip("v")
        if "-" in version and re.search(r"-\d{14}-[0-9a-f]{12}$", version):
            version = version.split("-")[0]
        result.declare("Go", name)
        result.packages.append(
            Package(
                name=name,
                ecosystem="Go",
                version=version,
                declared=parts[1],
                manifest=manifest,
                direct=not indirect,
                indirect=indirect,
                scope="runtime",
            )
        )


def parse_cargo_toml(path: Path, root: Path, result: DepsResult) -> None:
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        result.notes.append(f"{_rel(path, root)} 解析失败，已跳过")
        return
    manifest = _rel(path, root)
    sections = (
        ("dependencies", "runtime"),
        ("dev-dependencies", "dev"),
        ("build-dependencies", "dev"),
    )
    for section, scope in sections:
        for name, spec in (data.get(section) or {}).items():
            result.declare("crates.io", name)
            result.packages.append(
                Package(
                    name=name,
                    ecosystem="crates.io",
                    version=_cargo_version(spec),
                    declared=_cargo_declared(spec),
                    manifest=manifest,
                    scope=scope,
                )
            )
    workspace = data.get("workspace") or {}
    for name, spec in (workspace.get("dependencies") or {}).items():
        result.declare("crates.io", name)
        result.packages.append(
            Package(
                name=name,
                ecosystem="crates.io",
                version=_cargo_version(spec),
                declared=_cargo_declared(spec),
                manifest=manifest,
                scope="runtime",
            )
        )


def _cargo_declared(spec: Any) -> str:
    if isinstance(spec, str):
        return spec
    if isinstance(spec, dict):
        return str(spec.get("version") or "")
    return ""


def _cargo_version(spec: Any) -> str:
    declared = _cargo_declared(spec)
    match = re.match(r"^=\s*([0-9][^,\s]*)$", declared.strip())
    return match.group(1) if match else ""


def parse_cargo_lock(path: Path, root: Path, result: DepsResult) -> dict[str, str]:
    versions: dict[str, str] = {}
    try:
        with path.open("rb") as handle:
            data = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return versions
    manifest = _rel(path, root)
    for item in data.get("package") or []:
        name = item.get("name")
        version = item.get("version")
        if name and version:
            versions.setdefault(str(name), str(version))
            result.packages.append(
                Package(
                    name=str(name),
                    ecosystem="crates.io",
                    version=str(version),
                    declared=str(version),
                    manifest=manifest,
                )
            )
    return versions


def discover(root: Path, config: Config) -> list[Path]:
    found: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = _rel(path, root)
        if config.is_excluded(rel):
            continue
        if ecosystems.is_known_manifest(path.name):
            found.append(path)
    return found


def _rel(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def collect(root: Path, config: Config) -> DepsResult:
    result = DepsResult()
    manifests.reset_caches()
    paths = discover(root, config)
    manifests.parse_actions(root, config, result)

    added = 0
    for path in paths:
        before = len(result.packages)
        name = path.name
        if name.startswith("requirements") and name.endswith(".txt"):
            result.manifests.append(path)
            parse_requirements_txt(path, root, result)
        elif name == "pyproject.toml":
            result.manifests.append(path)
            parse_pyproject_toml(path, root, result)
        elif name == "Pipfile":
            result.manifests.append(path)
            parse_pipfile(path, root, result)
        elif name == "package.json":
            result.manifests.append(path)
            parse_package_json(path, root, result)
        elif name == "package-lock.json":
            result.lockfiles.append(path)
            parse_package_lock(path, root, result)
        elif name == "yarn.lock":
            result.lockfiles.append(path)
            parse_yarn_lock(path, root, result)
        elif name == "pnpm-lock.yaml":
            result.lockfiles.append(path)
            parse_pnpm_lock(path, root, result)
        elif name == "go.mod":
            result.manifests.append(path)
            parse_go_mod(path, root, result)
        elif name == "Cargo.toml":
            result.manifests.append(path)
            parse_cargo_toml(path, root, result)
        elif name == "Cargo.lock":
            result.lockfiles.append(path)
            parse_cargo_lock(path, root, result)
        else:
            kind = manifests.handle(path, root, result)
            if kind == "lock":
                result.lockfiles.append(path)
            elif kind == "manifest":
                result.manifests.append(path)
            if kind is None:
                continue
        added += len(result.packages) - before
        if added > 20000:
            result.notes.append("依赖数量超过 20000，已停止继续解析")
            break

    result.packages = _dedupe(result.packages)
    for package in result.packages:
        package.direct = result.is_declared(package.ecosystem, package.name) and not package.indirect
    return result


def _dedupe(packages: list[Package]) -> list[Package]:
    merged: dict[tuple[str, str], Package] = {}
    for package in packages:
        key = (package.ecosystem, package.name.lower())
        existing = merged.get(key)
        if existing is None:
            merged[key] = package
            continue
        if not existing.version and package.version:
            existing.version = package.version
        if not existing.direct and package.direct:
            existing.direct = True
        if package.indirect:
            existing.indirect = True
        if existing.scope == "runtime" and package.scope == "dev":
            existing.scope = "dev"
        if package.manifest and package.manifest not in existing.manifest:
            existing.manifest = f"{existing.manifest};{package.manifest}" if existing.manifest else package.manifest
        if len(package.declared) > len(existing.declared):
            existing.declared = package.declared
    return list(merged.values())
