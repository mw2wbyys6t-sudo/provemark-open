from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path


@dataclass(frozen=True)
class Ecosystem:
    id: str
    label: str
    language: str
    depsdev: str = ""
    registry: str = ""
    lockfiles: tuple[str, ...] = ()
    pins: tuple[str, ...] = ()
    osv: bool = True
    license_lookup: bool = True
    note: str = ""


ECOSYSTEMS: dict[str, Ecosystem] = {
    "PyPI": Ecosystem(
        "PyPI",
        "Python",
        "Python",
        depsdev="pypi",
        registry="pypi",
        lockfiles=("uv.lock", "poetry.lock", "Pipfile.lock", "pdm.lock", "requirements.lock"),
    ),
    "npm": Ecosystem(
        "npm",
        "Node.js",
        "JavaScript / TypeScript",
        depsdev="npm",
        registry="npm",
        lockfiles=("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock"),
    ),
    "Go": Ecosystem("Go", "Go Modules", "Go", depsdev="go", lockfiles=("go.sum",)),
    "crates.io": Ecosystem(
        "crates.io", "Cargo", "Rust", depsdev="cargo", registry="crates", lockfiles=("Cargo.lock",)
    ),
    "Maven": Ecosystem(
        "Maven",
        "Maven / Gradle",
        "Java / Kotlin / Scala / Clojure",
        depsdev="maven",
        registry="maven",
    ),
    "NuGet": Ecosystem(
        "NuGet",
        "NuGet",
        "C# / F# / .NET",
        depsdev="nuget",
        registry="nuget",
        lockfiles=("packages.lock.json",),
        pins=("Directory.Packages.props",),
    ),
    "RubyGems": Ecosystem("RubyGems", "RubyGems", "Ruby", depsdev="rubygems", registry="rubygems", lockfiles=("Gemfile.lock",)),
    "Packagist": Ecosystem("Packagist", "Composer", "PHP", registry="packagist", lockfiles=("composer.lock",)),
    "Pub": Ecosystem(
        "Pub",
        "pub.dev",
        "Dart / Flutter",
        lockfiles=("pubspec.lock",),
        license_lookup=False,
        note="pub.dev 不提供许可证 API",
    ),
    "SwiftURL": Ecosystem(
        "SwiftURL",
        "Swift Package Manager",
        "Swift",
        lockfiles=("Package.resolved",),
        license_lookup=False,
        note="Swift 包没有统一的许可证接口",
    ),
    "Hex": Ecosystem("Hex", "Hex", "Elixir / Erlang", registry="hex", lockfiles=("mix.lock",)),
    "CRAN": Ecosystem("CRAN", "CRAN", "R", registry="cran", lockfiles=("renv.lock",)),
    "Hackage": Ecosystem("Hackage", "Hackage", "Haskell", registry="hackage"),
    "Julia": Ecosystem("Julia", "Julia General", "Julia", lockfiles=("Manifest.toml",), license_lookup=False),
    "CPAN": Ecosystem("CPAN", "CPAN", "Perl", osv=False, license_lookup=False),
    "ConanCenter": Ecosystem(
        "ConanCenter", "Conan", "C / C++", license_lookup=False, note="Conan 中心索引暂无许可证 API"
    ),
    "vcpkg": Ecosystem("vcpkg", "vcpkg", "C / C++", license_lookup=False),
    "Conda": Ecosystem("Conda", "Conda", "Python / C / R", osv=False, license_lookup=False),
    "GitHub Actions": Ecosystem(
        "GitHub Actions", "GitHub Actions", "CI 工作流", license_lookup=False
    ),
}

MANIFESTS: tuple[tuple[str, str], ...] = (
    ("requirements*.txt", "PyPI"),
    ("pyproject.toml", "PyPI"),
    ("Pipfile", "PyPI"),
    ("package.json", "npm"),
    ("deno.json", "npm"),
    ("deno.jsonc", "npm"),
    ("go.mod", "Go"),
    ("Cargo.toml", "crates.io"),
    ("pom.xml", "Maven"),
    ("build.gradle", "Maven"),
    ("build.gradle.kts", "Maven"),
    ("libs.versions.toml", "Maven"),
    ("build.sbt", "Maven"),
    ("deps.edn", "Maven"),
    ("project.clj", "Maven"),
    ("*.csproj", "NuGet"),
    ("*.fsproj", "NuGet"),
    ("*.vbproj", "NuGet"),
    ("packages.config", "NuGet"),
    ("Directory.Packages.props", "NuGet"),
    ("*.nuspec", "NuGet"),
    ("Gemfile", "RubyGems"),
    ("*.gemspec", "RubyGems"),
    ("composer.json", "Packagist"),
    ("pubspec.yaml", "Pub"),
    ("Package.swift", "SwiftURL"),
    ("mix.exs", "Hex"),
    ("DESCRIPTION", "CRAN"),
    ("*.cabal", "Hackage"),
    ("Project.toml", "Julia"),
    ("Manifest.toml", "Julia"),
    ("cpanfile", "CPAN"),
    ("vcpkg.json", "vcpkg"),
    ("conanfile.txt", "ConanCenter"),
    ("conanfile.py", "ConanCenter"),
    ("environment.yml", "Conda"),
    ("environment.yaml", "Conda"),
)

LOCKFILES: tuple[tuple[str, str], ...] = tuple(
    (name, eco) for eco, item in ECOSYSTEMS.items() for name in item.lockfiles
)

ACTIONS_WORKFLOW_GLOB = ".github/workflows/*.yml"


def get(ecosystem: str) -> Ecosystem:
    item = ECOSYSTEMS.get(ecosystem)
    if item is not None:
        return item
    return Ecosystem(ecosystem, ecosystem, ecosystem)


def label_of(ecosystem: str) -> str:
    return get(ecosystem).label


def language_of(ecosystem: str) -> str:
    return get(ecosystem).language


def osv_supported(ecosystem: str) -> bool:
    return get(ecosystem).osv


def depsdev_system(ecosystem: str) -> str:
    return get(ecosystem).depsdev


def registry_kind(ecosystem: str) -> str:
    return get(ecosystem).registry


def license_lookup_supported(ecosystem: str) -> bool:
    return get(ecosystem).license_lookup


def lockfiles_of(ecosystem: str) -> tuple[str, ...]:
    item = get(ecosystem)
    return item.lockfiles + item.pins


def _match(pattern: str, filename: str) -> bool:
    if pattern == filename:
        return True
    if fnmatch(filename, pattern):
        return True
    return fnmatch(filename.lower(), pattern.lower())


def ecosystem_of_manifest(filename: str) -> str | None:
    for pattern, ecosystem in MANIFESTS:
        if _match(pattern, filename):
            return ecosystem
    return None


def ecosystem_of_lockfile(filename: str) -> str | None:
    for pattern, ecosystem in LOCKFILES:
        if _match(pattern, filename):
            return ecosystem
    return None


def is_known_manifest(filename: str) -> bool:
    return ecosystem_of_manifest(filename) is not None or ecosystem_of_lockfile(filename) is not None


def manifest_patterns() -> tuple[tuple[str, str], ...]:
    return MANIFESTS


def action_name_options(ecosystem: str) -> tuple[str, ...]:
    item = get(ecosystem)
    return tuple(text for text in (item.label, item.language) if text)


def rel_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()
