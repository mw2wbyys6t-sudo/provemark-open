"""Python 3.11 兼容性守卫。

CI 的矩阵会在 3.11 上跑全量测试；这个测试的作用是让本地（例如只有 3.12/3.14 的机器）
也能在提交前发现最常见的 3.12+ 专属语法：

- f-string 表达式里出现反斜杠（3.12 才允许，3.11 直接 SyntaxError）；
- PEP 695 的 `type X = ...` 与 `def f[T]()` / `class C[T]` 泛型语法（3.12+）。

它用 AST 判断真正的 f-string（而不是源码里“字符串里写着 f-string”的样例），
因此不会误报测试夹具。真正的保证仍来自 CI matrix；这里只守住已经踩过坑的类别。
"""
from __future__ import annotations

import ast
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCES = [ROOT / "provemark", ROOT / "tests"]


def python_files() -> list[Path]:
    files: list[Path] = []
    for base in SOURCES:
        files.extend(path for path in base.rglob("*.py") if "__pycache__" not in path.parts)
    return sorted(files)


def fstring_with_backslash(path: Path) -> list[str]:
    """返回 `文件:行` 列表：真正的 f-string 表达式里含反斜杠。"""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError:
        return []  # 语法本身有问题时交给编译/测试去报，这里不重复
    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.JoinedStr):
            continue
        for value in node.values:
            if not isinstance(value, ast.FormattedValue):
                continue
            try:
                rendered = ast.unparse(value.value)
            except Exception:  # noqa: BLE001 - unparse 失败不是兼容性问题
                continue
            if "\\" in rendered:
                offenders.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    return offenders


class Python311SyntaxTests(unittest.TestCase):
    def test_no_fstring_backslash_expressions(self) -> None:
        offenders: list[str] = []
        for path in python_files():
            offenders.extend(fstring_with_backslash(path))
        self.assertEqual(offenders, [], "f-string 表达式里不能用反斜杠（Python 3.11 会 SyntaxError）")

    def test_no_pep695_syntax(self) -> None:
        patterns = [
            re.compile(r"(?m)^\s*type\s+[A-Za-z_]\w*\s*="),  # type Alias = ...
            re.compile(r"(?m)^\s*def\s+\w+\s*\["),  # def f[T](...)
            re.compile(r"(?m)^\s*class\s+\w+\s*\["),  # class C[T]
        ]
        offenders = []
        for path in python_files():
            text = path.read_text(encoding="utf-8")
            for pattern in patterns:
                if pattern.search(text):
                    offenders.append(f"{path.relative_to(ROOT)}: {pattern.pattern}")
        self.assertEqual(offenders, [], "PEP 695 语法在 Python 3.11 上不可用")


if __name__ == "__main__":
    unittest.main()
