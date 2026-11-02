from __future__ import annotations

import json

from ..models import ScanResult
from . import ai_prompt, console, html, markdown, sarif

FORMATS = ("table", "json", "markdown", "sarif", "html")
EXTENSIONS = {
    ".html": "html",
    ".htm": "html",
    ".json": "json",
    ".sarif": "sarif",
    ".md": "markdown",
    ".markdown": "markdown",
    ".txt": "markdown",
}


def format_for_output(path: str, requested: str | None) -> str:
    if requested and requested != "auto":
        return requested
    for suffix, fmt in EXTENSIONS.items():
        if path.lower().endswith(suffix):
            return fmt
    return "table"


def render(result: ScanResult, fmt: str, *, verbose: bool = False) -> str:
    if fmt == "json":
        return json.dumps(result.to_dict(), ensure_ascii=False, indent=2)
    if fmt == "markdown":
        return markdown.render(result)
    if fmt == "sarif":
        return sarif.render(result)
    if fmt == "html":
        return html.render(result)
    return console.render(result, verbose=verbose)


def dump(result: ScanResult, fmt: str, path: str, *, verbose: bool = False) -> None:
    content = render(result, fmt, verbose=verbose)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content if content.endswith("\n") else content + "\n")


def ai_fix_prompt(result: ScanResult, *, test_command: str = "") -> str:
    return ai_prompt.render(result, test_command=test_command)


__all__ = ["FORMATS", "render", "dump", "format_for_output", "ai_fix_prompt"]
