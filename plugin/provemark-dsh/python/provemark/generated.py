from __future__ import annotations

from pathlib import Path


def find_root_file(root: Path, name: str) -> str:
    if (root / name).is_file():
        return name
    try:
        entries = list(root.iterdir())
    except OSError:
        return ""
    for item in entries:
        if item.is_file() and item.name.lower() == name.lower():
            return item.name
    return ""


def write(content: str, target: Path, *, marker: str, force: bool = False) -> tuple[Path, bool]:
    target = target.expanduser()
    redirected = False
    if target.exists():
        try:
            existing = target.read_text(encoding="utf-8", errors="replace")
        except OSError:
            existing = ""
        if marker not in existing and not force:
            target = target.with_name(f"{target.stem}.provemark{target.suffix}")
            redirected = True
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return target, redirected
