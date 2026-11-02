"""Line-level "is this real code" mask shared by the pattern scanners.

Comments and docstrings are prose: an `eval(` quoted in a documentation example
is not a vulnerability, and an `import` inside a docstring is not a dependency.
Both the AI-code scanner and the vulnerability scanner need the same answer, so
the masking lives here instead of being duplicated (and drifting).
"""
from __future__ import annotations


def code_mask(lines: list[str], lang: str) -> list[bool]:
    """True for lines that are real code, not comments or docstring payload."""
    mask = [True] * len(lines)
    if lang in ("py",):
        delimiter = None
        for index, line in enumerate(lines):
            if delimiter is not None:
                mask[index] = False
                if delimiter in line:
                    delimiter = None
                continue
            if line.lstrip().startswith("#"):
                mask[index] = False
                continue
            opened = None
            position = -1
            for candidate in ('"""', "'''"):
                found = line.find(candidate)
                if found != -1 and (position == -1 or found < position):
                    position, opened = found, candidate
            if opened is None:
                continue
            if opened in line[position + 3 :]:
                continue  # opened and closed on the same line
            mask[index] = False
            delimiter = opened
        return mask

    in_block_comment = False
    for index, line in enumerate(lines):
        stripped = line.strip()
        if in_block_comment:
            mask[index] = False
            if "*/" in line:
                in_block_comment = False
            continue
        if stripped.startswith("//"):
            mask[index] = False
            continue
        if stripped.startswith("/*"):
            mask[index] = False
            if "*/" not in line:
                in_block_comment = True
            continue
        # continuation lines of a /* ... */ block start with `*`
        if stripped.startswith("*") and not stripped.startswith("*/"):
            mask[index] = False
    return mask
