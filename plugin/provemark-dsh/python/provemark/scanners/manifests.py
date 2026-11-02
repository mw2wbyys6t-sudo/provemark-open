from __future__ import annotations

import json
import re
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable

from .. import ecosystems, yaml_lite
from ..models import Package

Handler = Callable[[Path, Path, Any], None]

PLAIN_VERSION = re.compile(r"^v?\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.\-]+)?$")
GRADLE_DEP = re.compile(
    r"\b(implementation|api|compileOnly|runtimeOnly|testImplementation|testRuntimeOnly|"
    r"androidTestImplementation|annotationProcessor|kapt|ksp|compile|classpath)\s*\(?\s*[\"']([^\"']+)[\"']"
)
GRADLE_PLATFORM = re.compile(r"(?:platform|enforcedPlatform)\s*\(\s*[\"']([^\"']+)[\"']")
SBT_DEP = re.compile(r"\"([\w.\-]+)\"\s*(%%?)\s*\"([\w.\-]+)\"\s*(%%?)\s*\"([^\"$]+)\"")
GEM_CALL = re.compile(r"^\s*gem\s+[\"']([^\"']+)[\"']\s*(.*)$")
GEM_LOCK_SPEC = re.compile(r"^ {4}([A-Za-z0-9_.\-]+) \(([^)]+)\)\s*$")
MIX_DEP = re.compile(r"\{:(\w+),\s*(?:\"([^\"]*)\"|\[|\bpath:|\bgit:)")
MIX_LOCK = re.compile(r"\"([A-Za-z0-9_]+)\":\s*\{:[a-z]+,\s*:([A-Za-z0-9_]+),\s*\"([^\"]+)\"")
CABAL_DEP = re.compile(r"([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(?:==\s*([0-9][0-9A-Za-z.\-]*))?")
EDN_DEP = re.compile(r"([\w.\-]+/[\w.\-]+)\s*\{:mvn/version\s+\"([^\"]+)\"")
CLJ_DEP = re.compile(r"\[([\w.\-]+/[\w.\-]+)\s+\"([^\"]+)\"")
CPAN_DEP = re.compile(r"requires\s+[\"']([^\"']+)[\"'](?:\s*,\s*[\"']([^\"']+)[\"'])?")
CONAN_TXT = re.compile(r"^([A-Za-z0-9_.\-]+)/([^\s#\[\]]+)")
CONAN_PY = re.compile(r"self\.requires\(\s*[\"']([A-Za-z0-9_.\-]+)/([^\"'#]+)")
SWIFT_PKG = re.compile(
    r"\.package\(\s*(?:name:\s*\"[^\"]*\"\s*,\s*)?(?:url:\s*\"([^\"]+)\"|path:\s*\"([^\"]+)\")"
    r"(?:\s*,\s*(?:from:\s*\"([^\"]+)\"|exact:\s*\"([^\"]+)\"|\.exact\(\s*\"([^\"]+)\"|branch:\s*\"([^\"]+)\"|revision:\s*\"([^\"]+)\"))?"
)
DENO_NPM = re.compile(r"npm:((?:@[^/@\s]+/)?[^@/\s]+)(?:@([^\"'\s]+))?")


def plain_version(text: str) -> str:
    value = (text or "").strip().strip("'\"").strip()
    value = value.lstrip("=").strip()
    return value if PLAIN_VERSION.match(value) else ""


def _rel(path: Path, root: Path) -> str:
    return ecosystems.rel_path(path, root)


def _add(
    result: Any,
    path: Path,
    root: Path,
    name: str,
    ecosystem: str,
    *,
    version: str = "",
    declared: str = "",
    scope: str = "runtime",
    locator: str = "",
    indirect: bool = False,
    pinned: bool = False,
    lookup: str = "",
) -> None:
    clean = (name or "").strip()
    if not clean:
        return
    result.declare(ecosystem, clean)
    result.packages.append(
        Package(
            name=clean,
            ecosystem=ecosystem,
            version=version,
            declared=declared or version,
            scope=scope,
            manifest=_rel(path, root),
            direct=True,
            locator=locator,
            indirect=indirect,
            lookup_name=lookup,
            pinned_by_parent=pinned,
        )
    )


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _json(path: Path) -> Any:
    try:
        return json.loads(_read(path))
    except json.JSONDecodeError:
        return None


def _toml(path: Path) -> Any:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return None


def _xml(path: Path) -> ET.Element | None:
    try:
        return ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return None


def _local(tag: str) -> str:
    return str(tag).rsplit("}", 1)[-1].lower()


def _kids(elem: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in list(elem) if _local(child.tag) == name]


def _text(elem: ET.Element, name: str) -> str:
    for child in _kids(elem, name):
        return (child.text or "").strip()
    return ""


def _dev_scope(words: str) -> str:
    lowered = words.lower()
    return "dev" if any(token in lowered for token in ("test", "dev", "bench", "lint", "doc")) else "runtime"


def _maven_dep_flag(scope_text: str) -> str:
    return "dev" if scope_text.strip().lower() in ("test", "provided", "system") else "runtime"


def parse_pom(path: Path, root: Path, result: Any) -> None:
    tree = _xml(path)
    if tree is None:
        result.notes.append(f"{_rel(path, root)} 解析失败，已跳过")
        return
    props: dict[str, str] = {}
    for block in _kids(tree, "properties"):
        for child in list(block):
            props[_local(child.tag)] = (child.text or "").strip()
    for key, value in (
        ("project.version", _text(tree, "version")),
        ("project.groupid", _text(tree, "groupid")),
        ("project.artifactid", _text(tree, "artifactid")),
        ("revision", _text(tree, "version")),
    ):
        if value:
            props.setdefault(key, value)

    def resolve(value: str) -> str:
        text = (value or "").strip()
        for _ in range(6):
            match = re.search(r"\$\{([^}]+)\}", text)
            if not match:
                break
            replacement = props.get(match.group(1), props.get(match.group(1).lower(), ""))
            if not replacement:
                return ""
            text = text.replace(match.group(0), replacement)
        return text

    managed: dict[str, str] = {}
    for block in _kids(tree, "dependencymanagement"):
        for group in _kids(block, "dependencies"):
            for dep in _kids(group, "dependency"):
                coord = f"{resolve(_text(dep, 'groupid'))}:{resolve(_text(dep, 'artifactid'))}"
                version = resolve(_text(dep, "version"))
                if coord != ":" and version:
                    managed[coord] = version

    for group in _kids(tree, "dependencies"):
        for dep in _kids(group, "dependency"):
            group_id = resolve(_text(dep, "groupid"))
            artifact = resolve(_text(dep, "artifactid"))
            if not artifact:
                continue
            coord = f"{group_id}:{artifact}" if group_id else artifact
            version = resolve(_text(dep, "version"))
            if not version:
                version = managed.get(coord, "")
            _add(
                result,
                path,
                root,
                coord,
                "Maven",
                version=plain_version(version),
                declared=version,
                scope=_maven_dep_flag(_text(dep, "scope")),
                pinned=not version,
            )


def parse_gradle(path: Path, root: Path, result: Any) -> None:
    text = _read(path)
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*"):
            continue
        scope = "runtime"
        match = GRADLE_DEP.search(line)
        if match:
            scope = _dev_scope(match.group(1)) if match.group(1).startswith(("test", "androidTest")) else "runtime"
            if match.group(1) in ("classpath",):
                scope = "dev"
            coordinate = match.group(2)
        else:
            match = GRADLE_PLATFORM.search(line)
            if not match:
                continue
            coordinate = match.group(1)
        parts = coordinate.split(":")
        if len(parts) < 2:
            continue
        group_id, artifact = parts[0], parts[1]
        version = parts[2] if len(parts) > 2 else ""
        if "$" in coordinate:
            version = ""
        _add(
            result,
            path,
            root,
            f"{group_id}:{artifact}",
            "Maven",
            version=plain_version(version),
            declared=version,
            scope=scope,
            pinned=not version,
        )


def parse_gradle_catalog(path: Path, root: Path, result: Any) -> None:
    data = _toml(path)
    if not isinstance(data, dict):
        return
    versions = data.get("versions") or {}
    libraries = data.get("libraries") or {}
    if not isinstance(libraries, dict):
        return
    for spec in libraries.values():
        module = ""
        declared = ""
        if isinstance(spec, str):
            module = spec
        elif isinstance(spec, dict):
            module = str(spec.get("module") or "")
            if not module and spec.get("group"):
                module = f"{spec['group']}:{spec.get('name') or ''}"
            version = spec.get("version")
            if isinstance(version, dict):
                declared = str(versions.get(str(version.get("ref") or ""), ""))
            elif version:
                declared = str(version)
        parts = module.split(":")
        if len(parts) < 2:
            continue
        if len(parts) > 2 and not declared:
            declared = parts[2]
        _add(
            result,
            path,
            root,
            f"{parts[0]}:{parts[1]}",
            "Maven",
            version=plain_version(declared),
            declared=declared,
            pinned=not declared,
        )


def parse_sbt(path: Path, root: Path, result: Any) -> None:
    for line in _read(path).splitlines():
        if line.strip().startswith("//"):
            continue
        for match in SBT_DEP.finditer(line):
            group_id, artifact, version = match.group(1), match.group(3), match.group(5)
            scope = "dev" if re.search(r"%\s*Test\b", line) else "runtime"
            _add(
                result,
                path,
                root,
                f"{group_id}:{artifact}",
                "Maven",
                version=plain_version(version),
                declared=version,
                scope=scope,
            )


def parse_nuget_project(path: Path, root: Path, result: Any) -> None:
    tree = _xml(path)
    if tree is None:
        return
    props = _msbuild_props(path.parent, root)
    central = _central_versions(path.parent, root)
    for elem in tree.iter():
        name = _local(elem.tag)
        if name not in ("packagereference", "packageversion", "dependency"):
            continue
        include = elem.get("Include") or elem.get("Update") or elem.get("id") or ""
        version = elem.get("Version") or ""
        if not version:
            for child in list(elem):
                if _local(child.tag) == "version":
                    version = (child.text or "").strip()
        if not include:
            continue
        version = _resolve_msbuild(version, props) or central.get(include.lower(), "")
        _add(
            result,
            path,
            root,
            include,
            "NuGet",
            version=plain_version(version),
            declared=version,
            pinned=not version,
        )


_MSBUILD_CACHE: dict[str, dict[str, str]] = {}
_CENTRAL_CACHE: dict[str, dict[str, str]] = {}


def _ancestor_chain(directory: Path, root: Path) -> list[Path]:
    chain: list[Path] = []
    current = directory
    while True:
        chain.append(current)
        if current == root or current.parent == current:
            break
        try:
            current.relative_to(root)
        except ValueError:
            break
        current = current.parent
    return list(reversed(chain))


def _msbuild_props(directory: Path, root: Path) -> dict[str, str]:
    key = str(directory)
    if key in _MSBUILD_CACHE:
        return _MSBUILD_CACHE[key]
    props: dict[str, str] = {}
    for folder in _ancestor_chain(directory, root):
        for name in ("Directory.Build.props", "Directory.Packages.props"):
            target = folder / name
            if not target.is_file():
                continue
            tree = _xml(target)
            if tree is None:
                continue
            for group in tree.iter():
                if _local(group.tag) != "propertygroup":
                    continue
                for child in list(group):
                    props[_local(child.tag)] = (child.text or "").strip()
    _MSBUILD_CACHE[key] = props
    return props


def _central_versions(directory: Path, root: Path) -> dict[str, str]:
    key = str(directory)
    if key in _CENTRAL_CACHE:
        return _CENTRAL_CACHE[key]
    versions: dict[str, str] = {}
    for folder in _ancestor_chain(directory, root):
        target = folder / "Directory.Packages.props"
        if not target.is_file():
            continue
        tree = _xml(target)
        if tree is None:
            continue
        for elem in tree.iter():
            if _local(elem.tag) != "packageversion":
                continue
            name = (elem.get("Include") or "").strip()
            version = (elem.get("Version") or "").strip()
            if name and version:
                versions[name.lower()] = version
    _CENTRAL_CACHE[key] = versions
    return versions


def _resolve_msbuild(value: str, props: dict[str, str]) -> str:
    text = (value or "").strip()
    for _ in range(6):
        match = re.search(r"\$\(([^)]+)\)", text)
        if not match:
            break
        replacement = props.get(match.group(1).lower(), "")
        if not replacement:
            return ""
        text = text.replace(match.group(0), replacement)
    return text


def parse_packages_config(path: Path, root: Path, result: Any) -> None:
    parse_nuget_project(path, root, result)


def parse_gemfile(path: Path, root: Path, result: Any) -> None:
    group_depth = 0
    dev_depth = -1
    gemspec = any(path.parent.glob("*.gemspec"))
    if gemspec:
        result.lock_optional.add("RubyGems")
    for line in _read(path).splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if re.match(r"^group\b.*\bdo\b", stripped):
            group_depth += 1
            if _dev_scope(stripped) == "dev":
                dev_depth = group_depth
            continue
        if stripped == "end":
            if group_depth == dev_depth:
                dev_depth = -1
            group_depth = max(0, group_depth - 1)
            continue
        match = GEM_CALL.match(line)
        if not match:
            continue
        name, rest = match.group(1), match.group(2)
        declared = ""
        version_match = re.search(r"[\"']([^\"']+)[\"']", rest)
        if version_match and not re.search(r"^\s*,\s*(git|path|branch|github|ref):", rest):
            declared = version_match.group(1)
        locator = ""
        if re.search(r"\bgit:", rest):
            locator = "url:git"
        elif re.search(r"\bpath:", rest):
            locator = "file:."
        scope = "dev" if dev_depth >= 0 else "runtime"
        _add(
            result,
            path,
            root,
            name,
            "RubyGems",
            version=plain_version(declared),
            declared=declared,
            scope=scope,
            locator=locator,
            pinned=not declared and gemspec,
        )


def parse_gemfile_lock(path: Path, root: Path, result: Any) -> None:
    section = ""
    for line in _read(path).splitlines():
        if not line.strip():
            continue
        if not line.startswith(" "):
            section = line.strip()
            continue
        if section not in ("GEM", "PATH", "GIT"):
            continue
        match = GEM_LOCK_SPEC.match(line)
        if not match:
            continue
        name, version = match.group(1), match.group(2).split("-")[0].strip()
        _add(result, path, root, name, "RubyGems", version=plain_version(version), declared=version)


def parse_gemspec(path: Path, root: Path, result: Any) -> None:
    for line in _read(path).splitlines():
        match = re.search(
            r"add_(?:runtime_|development_)?dependency\s*[\( ]\s*[\"']([^\"']+)[\"']\s*(?:,\s*[\"']([^\"']+)[\"'])?",
            line,
        )
        if not match:
            continue
        scope = "dev" if "development" in line else "runtime"
        declared = match.group(2) or ""
        _add(
            result,
            path,
            root,
            match.group(1),
            "RubyGems",
            version=plain_version(declared),
            declared=declared,
            scope=scope,
        )


def parse_composer_json(path: Path, root: Path, result: Any) -> None:
    data = _json(path)
    if not isinstance(data, dict):
        result.notes.append(f"{_rel(path, root)} 解析失败，已跳过")
        return
    if str(data.get("type") or "") == "library":
        result.lock_optional.add("Packagist")
    for section, scope in (("require", "runtime"), ("require-dev", "dev")):
        for name, spec in (data.get(section) or {}).items():
            if str(name) == "php" or str(name).startswith("ext-") or str(name).startswith("lib-"):
                continue
            declared = str(spec)
            locator = "url:git" if declared.startswith("dev-") else ""
            _add(
                result,
                path,
                root,
                str(name),
                "Packagist",
                version=plain_version(declared),
                declared=declared,
                scope=scope,
                locator=locator,
            )


def parse_composer_lock(path: Path, root: Path, result: Any) -> None:
    data = _json(path)
    if not isinstance(data, dict):
        return
    for section in ("packages", "packages-dev"):
        for item in data.get(section) or []:
            if not isinstance(item, dict) or not item.get("name"):
                continue
            version = str(item.get("version") or "").lstrip("v")
            _add(result, path, root, str(item["name"]), "Packagist", version=plain_version(version), declared=version)


def parse_pubspec(path: Path, root: Path, result: Any) -> None:
    data = None
    try:
        data = yaml_lite.load(_read(path))
    except Exception:  # noqa: BLE001 - 极简 YAML 解析失败时降级
        data = None
    if not isinstance(data, dict):
        result.notes.append(f"{_rel(path, root)} 解析失败，已跳过")
        return
    for section, scope in (
        ("dependencies", "runtime"),
        ("dev_dependencies", "dev"),
        ("dependency_overrides", "runtime"),
    ):
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            if not isinstance(name, str):
                continue
            declared = ""
            locator = ""
            if isinstance(spec, str):
                declared = spec
            elif isinstance(spec, dict):
                if "sdk" in spec:
                    continue
                declared = str(spec.get("version") or "")
                if spec.get("git"):
                    locator = "url:git"
                elif spec.get("path"):
                    locator = "file:."
            _add(
                result,
                path,
                root,
                name,
                "Pub",
                version=plain_version(declared),
                declared=declared,
                scope=scope,
                locator=locator,
            )


def parse_pubspec_lock(path: Path, root: Path, result: Any) -> None:
    data = None
    try:
        data = yaml_lite.load(_read(path))
    except Exception:  # noqa: BLE001
        data = None
    if not isinstance(data, dict):
        return
    packages = data.get("packages")
    if not isinstance(packages, dict):
        return
    for name, meta in packages.items():
        if not isinstance(name, str) or not isinstance(meta, dict):
            continue
        version = str(meta.get("version") or "")
        dependency = str(meta.get("dependency") or "")
        _add(
            result,
            path,
            root,
            name,
            "Pub",
            version=plain_version(version),
            declared=version,
            scope="dev" if "dev" in dependency else "runtime",
            indirect="transitive" in dependency,
        )


def parse_package_swift(path: Path, root: Path, result: Any) -> None:
    for match in SWIFT_PKG.finditer(_read(path)):
        url, local = match.group(1), match.group(2)
        version = match.group(3) or match.group(4) or match.group(5) or ""
        if local:
            _add(result, path, root, local, "SwiftURL", declared=local, locator="file:.", pinned=True)
            continue
        if not url:
            continue
        name = re.sub(r"^[a-z]+://", "", url).rstrip("/")
        if name.endswith(".git"):
            name = name[:-4]
        _add(
            result,
            path,
            root,
            name,
            "SwiftURL",
            version=plain_version(version),
            declared=version or (match.group(6) or match.group(7) or ""),
            pinned=not version,
        )


def parse_package_resolved(path: Path, root: Path, result: Any) -> None:
    data = _json(path)
    if not isinstance(data, dict):
        return
    pins = data.get("pins") or (data.get("object") or {}).get("pins") or []
    for pin in pins:
        if not isinstance(pin, dict):
            continue
        location = str(pin.get("location") or "")
        name = re.sub(r"^[a-z]+://", "", location).rstrip("/")
        if name.endswith(".git"):
            name = name[:-4]
        state = pin.get("state") or {}
        version = str(state.get("version") or "")
        _add(
            result,
            path,
            root,
            name or str(pin.get("identity") or ""),
            "SwiftURL",
            version=plain_version(version),
            declared=version or str(state.get("branch") or state.get("revision") or ""),
        )


def parse_mix_exs(path: Path, root: Path, result: Any) -> None:
    for line in _read(path).splitlines():
        if line.strip().startswith("#"):
            continue
        for match in MIX_DEP.finditer(line):
            name, declared = match.group(1), match.group(2) or ""
            if declared.startswith("=="):
                version = plain_version(declared[2:].strip())
            else:
                version = plain_version(declared)
            scope = "dev" if re.search(r"only:\s*\[?[^\]]*(test|dev)", line) else "runtime"
            locator = "url:git" if re.search(r"\b(git|github):", line) else ""
            _add(
                result,
                path,
                root,
                name,
                "Hex",
                version=version,
                declared=declared,
                scope=scope,
                locator=locator,
                pinned=not declared,
            )


def parse_mix_lock(path: Path, root: Path, result: Any) -> None:
    for match in MIX_LOCK.finditer(_read(path)):
        _add(result, path, root, match.group(1), "Hex", version=plain_version(match.group(3)), declared=match.group(3))


def parse_description(path: Path, root: Path, result: Any) -> None:
    fields: dict[str, str] = {}
    current = ""
    for line in _read(path).splitlines():
        if not line.strip():
            continue
        if not line.startswith((" ", "\t")) and ":" in line:
            key, value = line.split(":", 1)
            current = key.strip().lower()
            fields[current] = value.strip()
        elif current:
            fields[current] = f"{fields.get(current, '')} {line.strip()}".strip()
    for field, scope in (("depends", "runtime"), ("imports", "runtime"), ("linkingto", "runtime"), ("suggests", "dev")):
        value = fields.get(field, "")
        if not value:
            continue
        for item in value.split(","):
            entry = item.strip()
            if not entry:
                continue
            match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._]*)\s*(?:\(([^)]*)\))?$", entry)
            if not match:
                continue
            name = match.group(1)
            if name.lower() == "r":
                continue
            constraint = (match.group(2) or "").strip()
            declared = constraint or ""
            version = ""
            exact = re.match(r"^==\s*([0-9][0-9A-Za-z.\-]*)$", constraint)
            if exact:
                version = exact.group(1)
            _add(
                result,
                path,
                root,
                name,
                "CRAN",
                version=version,
                declared=declared,
                scope=scope,
                pinned=not version,
            )


def parse_renv_lock(path: Path, root: Path, result: Any) -> None:
    data = _json(path)
    if not isinstance(data, dict):
        return
    for name, meta in (data.get("Packages") or {}).items():
        if not isinstance(meta, dict):
            continue
        version = str(meta.get("Version") or "")
        _add(result, path, root, str(name), "CRAN", version=plain_version(version), declared=version)


def parse_cabal(path: Path, root: Path, result: Any) -> None:
    buffer: list[str] = []
    base_indent = 0
    collecting = False

    def flush() -> None:
        nonlocal buffer
        for item in ",".join(buffer).split(","):
            entry = item.strip()
            if not entry:
                continue
            match = CABAL_DEP.match(entry)
            if not match:
                continue
            declared = match.group(2) or ""
            _add(
                result,
                path,
                root,
                match.group(1),
                "Hackage",
                version=plain_version(declared),
                declared=declared,
                pinned=not declared,
            )
        buffer = []

    for line in _read(path).splitlines():
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))
        if re.match(r"^build-depends\s*:", stripped, re.I):
            if collecting:
                flush()
            collecting = True
            base_indent = indent
            buffer = [stripped.split(":", 1)[1]]
            continue
        if not collecting:
            continue
        if not stripped:
            flush()
            collecting = False
            continue
        if indent > base_indent:
            buffer.append(stripped)
            continue
        flush()
        collecting = False
    if collecting:
        flush()


def parse_deps_edn(path: Path, root: Path, result: Any) -> None:
    for match in EDN_DEP.finditer(_read(path)):
        coord = match.group(1).replace("/", ":")
        version = match.group(2)
        _add(result, path, root, coord, "Maven", version=plain_version(version), declared=version)


def parse_project_clj(path: Path, root: Path, result: Any) -> None:
    for match in CLJ_DEP.finditer(_read(path)):
        coord = match.group(1).replace("/", ":")
        version = match.group(2)
        _add(result, path, root, coord, "Maven", version=plain_version(version), declared=version)


def parse_julia_project(path: Path, root: Path, result: Any) -> None:
    data = _toml(path)
    if not isinstance(data, dict):
        return
    deps = data.get("deps")
    if not isinstance(deps, dict):
        return
    for name in deps:
        _add(result, path, root, str(name), "Julia", pinned=True)


def parse_julia_manifest(path: Path, root: Path, result: Any) -> None:
    data = _toml(path)
    if not isinstance(data, dict):
        return
    deps = data.get("deps")
    if not isinstance(deps, dict):
        return
    for name, meta in deps.items():
        entry = meta
        if isinstance(entry, list):
            entry = entry[0] if entry and isinstance(entry[0], dict) else None
        if not isinstance(entry, dict):
            continue
        version = str(entry.get("version") or "")
        _add(result, path, root, str(name), "Julia", version=plain_version(version), declared=version)


def parse_cpanfile(path: Path, root: Path, result: Any) -> None:
    for line in _read(path).splitlines():
        if line.strip().startswith("#"):
            continue
        for match in CPAN_DEP.finditer(line):
            declared = match.group(2) or ""
            scope = "dev" if re.search(r"on\s+['\"](test|develop)", line) else "runtime"
            _add(
                result,
                path,
                root,
                match.group(1),
                "CPAN",
                version=plain_version(declared),
                declared=declared,
                scope=scope,
            )


def parse_vcpkg_json(path: Path, root: Path, result: Any) -> None:
    data = _json(path)
    if not isinstance(data, dict):
        return
    for item in data.get("dependencies") or []:
        if isinstance(item, str):
            _add(result, path, root, item, "vcpkg", pinned=True)
        elif isinstance(item, dict) and item.get("name"):
            declared = str(item.get("version>=") or item.get("version") or "")
            _add(
                result,
                path,
                root,
                str(item["name"]),
                "vcpkg",
                version=plain_version(declared),
                declared=declared,
                pinned=not declared,
            )


def parse_conanfile_txt(path: Path, root: Path, result: Any) -> None:
    section = ""
    for line in _read(path).splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            section = stripped.strip("[]").lower()
            continue
        if section not in ("requires", "tool_requires", "build_requires") or not stripped:
            continue
        match = CONAN_TXT.match(stripped)
        if not match:
            continue
        _add(
            result,
            path,
            root,
            match.group(1),
            "ConanCenter",
            version=plain_version(match.group(2)),
            declared=match.group(2),
            scope="dev" if section != "requires" else "runtime",
        )


def parse_conanfile_py(path: Path, root: Path, result: Any) -> None:
    for match in CONAN_PY.finditer(_read(path)):
        _add(
            result,
            path,
            root,
            match.group(1),
            "ConanCenter",
            version=plain_version(match.group(2)),
            declared=match.group(2),
        )


def parse_environment_yml(path: Path, root: Path, result: Any) -> None:
    data = None
    try:
        data = yaml_lite.load(_read(path))
    except Exception:  # noqa: BLE001
        data = None
    if not isinstance(data, dict):
        return
    for item in data.get("dependencies") or []:
        if isinstance(item, str):
            match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(?:([=<>!~]+)\s*([0-9][0-9A-Za-z.*\-]*))?", item)
            if not match:
                continue
            version = match.group(3) or ""
            _add(
                result,
                path,
                root,
                match.group(1),
                "Conda",
                version=plain_version(version) if match.group(2) in ("=", "==") else "",
                declared=item,
                pinned=not version,
            )
        elif isinstance(item, dict):
            for channel, entries in item.items():
                if str(channel) != "pip" or not isinstance(entries, list):
                    continue
                for entry in entries:
                    text = str(entry)
                    parsed = re.match(r"^([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(?:==\s*([0-9][^,\s]*))?", text)
                    if not parsed:
                        continue
                    _add(
                        result,
                        path,
                        root,
                        parsed.group(1),
                        "PyPI",
                        version=plain_version(parsed.group(2) or ""),
                        declared=text,
                        pinned=not parsed.group(2),
                    )


def parse_deno_json(path: Path, root: Path, result: Any) -> None:
    text = _read(path)
    if path.suffix == ".jsonc":
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
        text = re.sub(r"^\s*//.*$", "", text, flags=re.M)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return
    if not isinstance(data, dict):
        return
    imports = data.get("imports")
    if not isinstance(imports, dict):
        return
    for spec in imports.values():
        if not isinstance(spec, str):
            continue
        match = DENO_NPM.search(spec)
        if not match:
            continue
        declared = match.group(2) or ""
        _add(
            result,
            path,
            root,
            match.group(1),
            "npm",
            version=plain_version(declared),
            declared=declared,
            pinned=not declared,
        )


def parse_actions(root: Path, config: Any, result: Any) -> None:
    workflows = root / ".github" / "workflows"
    if not workflows.is_dir():
        return
    for path in sorted(workflows.glob("*.y*ml")):
        rel = _rel(path, root)
        if config.is_excluded(rel):
            continue
        for line in _read(path).splitlines():
            match = re.match(r"^\s*-?\s*uses:\s*([^\s#]+)", line)
            if not match:
                continue
            ref = match.group(1)
            if ref.startswith(("./", "docker://")) or "@" not in ref:
                continue
            name, version = ref.rsplit("@", 1)
            _add(result, path, root, name, "GitHub Actions", declared=version, pinned=True)


HANDLERS: tuple[tuple[str, str, Handler], ...] = (
    ("pom.xml", "manifest", parse_pom),
    ("build.gradle", "manifest", parse_gradle),
    ("build.gradle.kts", "manifest", parse_gradle),
    ("libs.versions.toml", "manifest", parse_gradle_catalog),
    ("build.sbt", "manifest", parse_sbt),
    ("deps.edn", "manifest", parse_deps_edn),
    ("project.clj", "manifest", parse_project_clj),
    ("*.csproj", "manifest", parse_nuget_project),
    ("*.fsproj", "manifest", parse_nuget_project),
    ("*.vbproj", "manifest", parse_nuget_project),
    ("packages.config", "manifest", parse_packages_config),
    ("Directory.Packages.props", "manifest", parse_nuget_project),
    ("*.nuspec", "manifest", parse_nuget_project),
    ("Gemfile", "manifest", parse_gemfile),
    ("Gemfile.lock", "lock", parse_gemfile_lock),
    ("*.gemspec", "manifest", parse_gemspec),
    ("composer.json", "manifest", parse_composer_json),
    ("composer.lock", "lock", parse_composer_lock),
    ("pubspec.yaml", "manifest", parse_pubspec),
    ("pubspec.lock", "lock", parse_pubspec_lock),
    ("Package.swift", "manifest", parse_package_swift),
    ("Package.resolved", "lock", parse_package_resolved),
    ("mix.exs", "manifest", parse_mix_exs),
    ("mix.lock", "lock", parse_mix_lock),
    ("DESCRIPTION", "manifest", parse_description),
    ("renv.lock", "lock", parse_renv_lock),
    ("*.cabal", "manifest", parse_cabal),
    ("Project.toml", "manifest", parse_julia_project),
    ("Manifest.toml", "lock", parse_julia_manifest),
    ("cpanfile", "manifest", parse_cpanfile),
    ("vcpkg.json", "manifest", parse_vcpkg_json),
    ("conanfile.txt", "manifest", parse_conanfile_txt),
    ("conanfile.py", "manifest", parse_conanfile_py),
    ("environment.yml", "manifest", parse_environment_yml),
    ("environment.yaml", "manifest", parse_environment_yml),
    ("deno.json", "manifest", parse_deno_json),
    ("deno.jsonc", "manifest", parse_deno_json),
)


def _matches(pattern: str, filename: str) -> bool:
    if pattern == filename:
        return True
    if "*" in pattern or "?" in pattern:
        from fnmatch import fnmatch

        return fnmatch(filename, pattern) or fnmatch(filename.lower(), pattern.lower())
    return filename.lower() == pattern.lower()


def reset_caches() -> None:
    _MSBUILD_CACHE.clear()
    _CENTRAL_CACHE.clear()


def handle(path: Path, root: Path, result: Any) -> str | None:
    filename = path.name
    for pattern, kind, parser in HANDLERS:
        if _matches(pattern, filename):
            try:
                parser(path, root, result)
            except Exception as exc:  # noqa: BLE001 - 单个清单解析失败不应中断扫描
                result.notes.append(f"{_rel(path, root)} 解析失败（{type(exc).__name__}），已跳过")
            return kind
    return None
