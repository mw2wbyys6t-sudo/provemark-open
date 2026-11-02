from __future__ import annotations

import subprocess
from pathlib import Path


def _run_git(root: Path, args: list[str]) -> str | None:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout


def is_git_repo(root: Path) -> bool:
    if not (root / ".git").exists():
        return False
    output = _run_git(root, ["rev-parse", "--is-inside-work-tree"])
    return bool(output and output.strip() == "true")


def tracked_files(root: Path) -> list[str] | None:
    output = _run_git(root, ["ls-files", "-z"])
    if output is None:
        return None
    return [item for item in output.split("\0") if item]


def staged_files(root: Path) -> list[str] | None:
    output = _run_git(root, ["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"])
    if output is None:
        return None
    return [item for item in output.split("\0") if item]


def file_size_in_git(root: Path, rel: str) -> int:
    path = root / rel
    try:
        return path.stat().st_size
    except OSError:
        return 0
