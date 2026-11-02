from __future__ import annotations

import json
import re
from typing import Any


def load(text: str) -> Any:
    lines = _tokenize(text)
    value, _ = _parse(lines, 0, 0)
    if value is None:
        return {}
    return value


def _strip_comment(line: str) -> str:
    quote = ""
    for index, char in enumerate(line):
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in ("'", '"'):
            quote = char
            continue
        if char == "#" and (index == 0 or line[index - 1] in (" ", "\t")):
            return line[:index]
    return line


def _tokenize(text: str) -> list[tuple[int, str]]:
    tokens: list[tuple[int, str]] = []
    for raw in text.replace("\t", "  ").splitlines():
        line = _strip_comment(raw).rstrip()
        if not line.strip():
            continue
        stripped = line.strip()
        if stripped in ("---", "...") or stripped.startswith("%YAML"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        tokens.append((indent, stripped))
    return tokens


def _split_entry(text: str) -> tuple[str, str] | None:
    if not text or text.startswith("-"):
        return None
    quote = ""
    for index, char in enumerate(text):
        if quote:
            if char == quote:
                quote = ""
            continue
        if char in ("'", '"'):
            quote = char
            continue
        if char == ":" and (index + 1 == len(text) or text[index + 1] == " "):
            key = text[:index].strip().strip("'\"")
            return key, text[index + 1 :].strip()
    return None


def _parse(lines: list[tuple[int, str]], index: int, depth: int) -> tuple[Any, int]:
    if depth > 40 or index >= len(lines):
        return None, index
    indent, text = lines[index]
    if text.startswith("-"):
        return _parse_seq(lines, index, indent, depth)
    return _parse_map(lines, index, indent, depth)


def _parse_seq(lines: list[tuple[int, str]], index: int, indent: int, depth: int) -> tuple[Any, int]:
    items: list[Any] = []
    while index < len(lines) and lines[index][0] == indent and lines[index][1].startswith("-"):
        rest = lines[index][1][1:].strip()
        index += 1
        if not rest:
            child, index = _parse(lines, index, depth + 1)
            items.append(child)
            continue
        entry = _split_entry(rest)
        if entry is None:
            items.append(_scalar(rest))
            continue
        key, value = entry
        item: dict[str, Any] = {}
        if value:
            item[key] = _scalar(value)
        elif index < len(lines) and lines[index][0] > indent:
            child, index = _parse(lines, index, depth + 1)
            item[key] = child
        else:
            item[key] = None
        while index < len(lines) and lines[index][0] > indent:
            sub_indent = lines[index][0]
            entry = _split_entry(lines[index][1])
            if entry is None:
                break
            before = index
            sub, index = _parse_map(lines, index, sub_indent, depth + 1)
            if isinstance(sub, dict):
                item.update(sub)
            if index == before:
                break
        items.append(item)
    return items, index


def _parse_map(lines: list[tuple[int, str]], index: int, indent: int, depth: int) -> tuple[Any, int]:
    result: dict[str, Any] = {}
    while index < len(lines) and lines[index][0] == indent:
        text = lines[index][1]
        entry = _split_entry(text)
        if entry is None:
            break
        key, value = entry
        index += 1
        if value in ("|", ">", "|-", ">-", "|+", ">+"):
            block: list[str] = []
            while index < len(lines) and lines[index][0] > indent:
                block.append(lines[index][1])
                index += 1
            result[key] = ("\n" if value.startswith("|") else " ").join(block)
            continue
        if value:
            result[key] = _scalar(value)
            continue
        if index < len(lines) and lines[index][0] > indent:
            child, index = _parse(lines, index, depth + 1)
            result[key] = child
        else:
            result[key] = None
    return result, index


_INLINE = re.compile(r"^\[(.*)\]$|^\{(.*)\}$")


def _scalar(text: str) -> Any:
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("'", '"'):
        return text[1:-1]
    match = _INLINE.match(text)
    if match:
        inner = match.group(1) if match.group(1) is not None else match.group(2)
        parts = [part.strip() for part in inner.split(",") if part.strip()]
        if match.group(1) is not None:
            return [_scalar(part) for part in parts]
        mapping: dict[str, Any] = {}
        for part in parts:
            entry = _split_entry(part)
            if entry:
                mapping[entry[0]] = _scalar(entry[1]) if entry[1] else None
        return mapping
    lowered = text.lower()
    if lowered in ("true", "yes", "on"):
        return True
    if lowered in ("false", "no", "off"):
        return False
    if lowered in ("null", "~", ""):
        return None
    if re.fullmatch(r"-?\d+", text):
        return int(text)
    if re.fullmatch(r"-?\d+\.\d+", text):
        return float(text)
    return text


def dump_value(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)
