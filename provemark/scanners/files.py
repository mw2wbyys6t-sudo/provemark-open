from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Config
from .. import ecosystems

TEXT_SUFFIXES = {
    ".py",
    ".pyi",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".vue",
    ".svelte",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".kts",
    ".scala",
    ".rb",
    ".php",
    ".cs",
    ".fs",
    ".vb",
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".hpp",
    ".swift",
    ".dart",
    ".ex",
    ".exs",
    ".erl",
    ".hrl",
    ".jl",
    ".lua",
    ".pl",
    ".pm",
    ".r",
    ".nim",
    ".cr",
    ".hs",
    ".clj",
    ".cljs",
    ".edn",
    ".sh",
    ".bash",
    ".zsh",
    ".ps1",
    ".bat",
    ".cmd",
    ".sql",
    ".html",
    ".htm",
    ".css",
    ".scss",
    ".json",
    ".jsonc",
    ".toml",
    ".yaml",
    ".yml",
    ".xml",
    ".gradle",
    ".sbt",
    ".cabal",
    ".gemspec",
    ".csproj",
    ".fsproj",
    ".vbproj",
    ".props",
    ".targets",
    ".nuspec",
    ".ini",
    ".cfg",
    ".conf",
    ".env",
    ".md",
    ".txt",
    ".lock",
    ".dockerfile",
    "",
}

BINARY_SUFFIXES = {
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".bmp",
    ".tif",
    ".tiff",
    ".pdf",
    ".zip",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
    ".7z",
    ".rar",
    ".whl",
    ".jar",
    ".exe",
    ".dll",
    ".so",
    ".dylib",
    ".node",
    ".onnx",
    ".pt",
    ".pth",
    ".bin",
    ".mp3",
    ".mp4",
    ".mov",
    ".wav",
    ".woff",
    ".woff2",
    ".ttf",
    ".otf",
    ".eot",
    ".moc3",
    ".psd",
    ".sqlite",
    ".db",
}

CODE_SUFFIXES = {
    ".py",
    ".pyi",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".go",
    ".rs",
    ".java",
    ".kt",
    ".kts",
    ".scala",
    ".rb",
    ".php",
    ".cs",
    ".fs",
    ".vb",
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".hpp",
    ".swift",
    ".dart",
    ".ex",
    ".exs",
    ".erl",
    ".jl",
    ".lua",
    ".pl",
    ".pm",
    ".r",
    ".nim",
    ".cr",
    ".hs",
    ".clj",
    ".cljs",
    ".vue",
    ".svelte",
}

TEST_PATH_TOKENS = ("test", "tests", "spec", "__tests__", "fixtures", "examples", "example", "samples", "testdata")
# Per-file test markers across ecosystems: context_test.go, test_app.py,
# app.test.ts, app.spec.js, widget_test.rs. Directory tokens alone miss all of
# these — that is how a Go `_test.go` fixture kept a card number at "high".
TEST_FILE_PATTERN = re.compile(r"(?:^test_.*\.py$|_test\.(?:go|py|rs|exs?)$|\.(?:test|spec)\.[cm]?[jt]sx?$)", re.IGNORECASE)

# Build output and VCS internals are not the repository's source: `pip install .`
# materialises build/lib/**, and scanning that copy produced a false AI-005 high
# in CI while the working tree was clean.
DEFAULT_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".hgcheck",
        ".venv",
        "venv",
        "env",
        "build",
        "dist",
        ".eggs",
        "htmlcov",
        "node_modules",
        "bower_components",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        ".next",
        ".nuxt",
        "site-packages",
    }
)


def _is_skip_dir(name: str) -> bool:
    lowered = name.lower()
    if lowered in DEFAULT_SKIP_DIRS:
        return True
    return lowered.endswith((".egg-info", ".dist-info"))


@dataclass
class FileInfo:
    path: Path
    rel: str
    size: int
    suffix: str
    lines: list[str] = field(default_factory=list)
    truncated: bool = False

    @property
    def is_code(self) -> bool:
        return self.suffix in CODE_SUFFIXES

    @property
    def is_test(self) -> bool:
        lowered = self.rel.lower()
        if any(token in lowered.split("/") for token in TEST_PATH_TOKENS) or "/fixtures/" in lowered:
            return True
        return bool(TEST_FILE_PATTERN.search(self.path.name))

    def text(self) -> str:
        return "\n".join(self.lines)


def _looks_binary(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            chunk = handle.read(4096)
    except OSError:
        return True
    if b"\x00" in chunk:
        return True
    return False


def collect_files(root: Path, config: Config) -> tuple[list[FileInfo], list[str]]:
    files: list[FileInfo] = []
    notes: list[str] = []
    skipped_large = 0
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        current = Path(dirpath)
        rel_dir = current.relative_to(root).as_posix()
        prefix = "" if rel_dir == "." else rel_dir + "/"
        dirnames[:] = [
            name
            for name in dirnames
            if not _is_skip_dir(name) and not config.is_excluded((prefix + name + "/").lstrip("/"))
        ]
        for filename in filenames:
            rel = (prefix + filename).lstrip("/")
            if config.is_excluded(rel):
                continue
            path = current / filename
            try:
                stat = path.stat()
            except OSError:
                continue
            if not path.is_file():
                continue
            suffix = path.suffix.lower()
            if suffix in BINARY_SUFFIXES:
                continue
            if stat.st_size > config.max_file_bytes:
                skipped_large += 1
                continue
            if suffix not in TEXT_SUFFIXES and filename not in (".env", "Dockerfile", "Makefile"):
                continue
            if suffix == "" and filename not in (".env", "Dockerfile", "Makefile", "LICENSE", "NOTICE", "COPYING"):
                if not ecosystems.is_known_manifest(filename):
                    continue
            count += 1
            if count > config.max_files:
                notes.append(f"文件数超过上限 {config.max_files}，其余文件未扫描")
                return files, notes
            if _looks_binary(path):
                continue
            try:
                raw = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            lines = raw.splitlines()
            truncated = len(lines) > 20000
            if truncated:
                lines = lines[:20000]
            files.append(
                FileInfo(path=path, rel=rel, size=stat.st_size, suffix=suffix, lines=lines, truncated=truncated)
            )
    if skipped_large:
        notes.append(f"{skipped_large} 个超过体积上限的文件未扫描")
    return files, notes


def parseable_files(files: list[FileInfo]) -> list[FileInfo]:
    return [f for f in files if f.is_code and not f.is_test]
