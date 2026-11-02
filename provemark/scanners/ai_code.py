from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

from .. import ai_usage
from ..generated import find_root_file
from ..models import Finding
from ..rules import ai_patterns as rules
from .base import Context, make_finding
from .codemask import code_mask as _code_mask

LANG_BY_SUFFIX = {
    ".py": "py",
    ".pyi": "py",
    ".js": "js",
    ".jsx": "js",
    ".mjs": "js",
    ".cjs": "js",
    ".vue": "js",
    ".svelte": "js",
    ".ts": "ts",
    ".tsx": "ts",
    ".go": "go",
    ".rs": "rs",
}

PY_DIST_ALIASES = {
    "pil": "pillow",
    "cv2": "opencv-python",
    "sklearn": "scikit-learn",
    "skimage": "scikit-image",
    "yaml": "pyyaml",
    "dotenv": "python-dotenv",
    "bs4": "beautifulsoup4",
    "jwt": "pyjwt",
    "psd_tools": "psd-tools",
    "dateutil": "python-dateutil",
    "attr": "attrs",
    "openssl": "pyopenssl",
    "crypto": "pycryptodome",
    "pkg_resources": "setuptools",
    "fitz": "pymupdf",
    "docx": "python-docx",
    "pptx": "python-pptx",
    "mysqldb": "mysqlclient",
    "psycopg2": "psycopg2-binary",
    "mpl_toolkits": "matplotlib",
    "google": "google-cloud-storage",
    "jose": "python-jose",
    "multipart": "python-multipart",
    "rest_framework": "djangorestframework",
    "dns": "dnspython",
    "win32api": "pywin32",
    "win32con": "pywin32",
    "serial": "pyserial",
    "usb": "pyusb",
    "gi": "pygobject",
    "wx": "wxpython",
    "zmq": "pyzmq",
}

DOWNGRADE = {"critical": "high", "high": "medium", "medium": "low", "low": "info", "info": "info"}
SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
GENERATED_TOKENS = (
    "_pb2.py",
    ".d.ts",
    ".min.js",
    ".min.css",
    ".g.dart",
    "_generated",
    ".pb.go",
    ".pb.gw.go",
    ".gen.go",
    "zz_generated",
)
AGGREGATE_RULES = {"AI-002", "AI-003", "AI-004", "AI-008", "AI-020", "AI-025", "AI-026"}
SCRIPT_DIRS = ("scripts/", "tools/", "examples/", "training/", "benchmarks/", "docs/", "doc/")
TEST_ONLY_PACKAGES = {"pytest", "hypothesis", "faker", "coverage", "tox", "nox", "mock"}
# Code-quality rules do not apply to test code: tests legitimately use pickle for
# fixtures, ignore exceptions, loop over checks and print diagnostics. Security
# scanners (secrets/PII) still cover tests; this set is only the AI-quality layer.
TEST_SKIP_RULES = {"AI-003", "AI-004", "AI-005", "AI-016", "AI-017", "AI-020", "AI-022", "AI-025", "AI-026"}
# Third-party code shipped inside the repo (jQuery, select2, bundled SDKs).
VENDORED_DIRS = ("vendor", "vendors", "third_party", "third-party", "node_modules", "bower_components", "external")
LOOP_START = re.compile(r"^\s*(?:async\s+)?for\s*(?:\(|[\w, ]+\s+in\s)")
# `await import(...)` is module resolution (inherently sequential, not a
# network/db call); a quoted "await" in scanner code must not count either.
AWAIT_CALL = re.compile(r"\bawait\s+(?!import\b)(?:[A-Za-z_$]|\()")
QUERY_CALL = re.compile(
    r"(?:\.objects\.|\.query\s*\(|\.execute\s*\(|"
    r"\b[A-Z][A-Za-z0-9_]*\.find(?:One|All|ById|ByIdAndUpdate)?\s*\()"
)
# 循环体里的其他复杂度反模式（见 rules.ai_patterns.ENGINEERING_LOOP_RULES）
BODY_SIGNALS = {
    "io": re.compile(
        r"(?:\brequests\.(?:get|post|put|patch|delete)\s*\(|\bfetch\s*\(|"
        r"\baxios\.(?:get|post|put|patch|delete)\s*\(|\bhttp\.(?:Get|Post)\s*\()"
    ),
    # `total += n`（数值累加）是正常写法；只有拼**字符串**才是 O(n²)
    "concat": re.compile(r"^\s*[A-Za-z_$][\w$]*\s*\+=\s*(?:f?[\"'`])"),
    "frame": re.compile(r"(?:\bpd\.concat\s*\(|\bpandas\.concat\s*\()"),
}


def _matches_signal(signal: str, line: str) -> bool:
    if signal == "await":
        return bool(AWAIT_CALL.search(line))
    if signal == "query":
        return bool(QUERY_CALL.search(line)) and not AWAIT_CALL.search(line)
    if signal == "io":
        # 异步循环已由 AI-016 覆盖，避免同一行报两条
        return bool(BODY_SIGNALS["io"].search(line)) and not AWAIT_CALL.search(line)
    pattern = BODY_SIGNALS.get(signal)
    return bool(pattern and pattern.search(line))


def _lang(path: Path) -> str:
    return LANG_BY_SUFFIX.get(path.suffix.lower(), "generic")


def _skip_file(rel: str) -> bool:
    lowered = rel.lower()
    if any(token in lowered for token in GENERATED_TOKENS):
        return True
    if lowered.endswith((".lock", ".map")):
        return True
    # Vendored third-party bundles are not the repository author's code: flagging
    # jQuery's catch blocks or select2's loops is pure noise for the user.
    # (No backslash inside the f-string expression: Python 3.11 rejects it.)
    slashed = lowered.replace("\\", "/")
    normalized = f"/{slashed}"
    if any(f"/{segment}/" in normalized for segment in VENDORED_DIRS):
        return True
    return False


def _worse(left: str, right: str) -> str:
    return left if SEVERITY_ORDER.index(left) <= SEVERITY_ORDER.index(right) else right


def _local_names(ctx: Context) -> set[str]:
    names: set[str] = set()
    for info in ctx.files:
        parts = info.rel.split("/")
        if not parts:
            continue
        for part in parts[:-1]:
            if part not in ("", ".", "src", "lib"):
                names.add(part.lower().replace("-", "_"))
        names.add(parts[0].rsplit(".", 1)[0].lower().replace("-", "_"))
        names.add(info.path.stem.lower().replace("-", "_"))
    return names


def _go_module(ctx: Context) -> str:
    for manifest in ctx.deps.manifests:
        if manifest.name != "go.mod":
            continue
        try:
            for line in manifest.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.strip().startswith("module "):
                    return line.strip().split(None, 1)[1].strip()
        except OSError:
            continue
    return ""


def _py_import_index(declared: set[str]) -> set[str]:
    index: set[str] = set()
    for dist in declared:
        base = dist.strip().lower()
        if not base:
            continue
        dashed = base.replace("_", "-")
        index.add(dashed)
        index.add(dashed.replace("-", "_"))
        for prefix in ("python-", "py-"):
            if dashed.startswith(prefix) and len(dashed) > len(prefix):
                index.add(dashed[len(prefix) :])
        for suffix in ("-python", "-py"):
            if dashed.endswith(suffix) and len(dashed) > len(suffix):
                index.add(dashed[: -len(suffix)])
        parts = dashed.split("-")
        for length in range(1, min(3, len(parts)) + 1):
            index.add("-".join(parts[:length]))
    for module, dist in PY_DIST_ALIASES.items():
        normalized = dist.lower().replace("_", "-")
        if normalized in index or normalized.replace("-", "_") in index:
            key = module.lower()
            index.add(key)
            index.add(key.replace("_", "-"))
    return index


def _py_module_ok(module: str, index: set[str], local: set[str], stdlib: frozenset[str]) -> bool:
    root = module.split(".")[0]
    if not root:
        return True
    if root in stdlib or root in local:
        return True
    normalized = root.lower().replace("_", "-")
    if normalized in index:
        return True
    dotted = module.lower().replace("_", "-").replace(".", "-")
    if dotted in index:
        return True
    for part in dotted.split("-")[1:]:
        if part in index:
            return True
    return False


def _js_package_name(spec: str) -> str:
    if spec.startswith("@"):
        parts = spec.split("/")
        return "/".join(parts[:2]) if len(parts) >= 2 else spec
    return spec.split("/")[0]


def _js_module_ok(spec: str, declared: set[str], local: set[str]) -> bool:
    if spec.startswith(("http:", "https:", "data:", "node:")):
        return True
    if spec.startswith((".", "/", "~", "#")) or spec.startswith("@" + "/"):
        return True
    if spec.startswith(("@/", "~/")):
        return True
    package = _js_package_name(spec).lower()
    if package in declared or package.replace("-", "_") in declared:
        return True
    head = package.split("/")[0]
    if head in rules.JS_BUILTIN_PREFIXES or head in local:
        return True
    return False


def _is_guarded_optional(lines: list[str], index: int, lang: str) -> bool:
    if lang != "py":
        return False
    line = lines[index]
    indent = len(line) - len(line.lstrip())
    for back in range(index - 1, max(-1, index - 8), -1):
        previous = lines[back]
        if not previous.strip():
            continue
        previous_indent = len(previous) - len(previous.lstrip())
        if previous_indent < indent:
            stripped = previous.strip()
            return bool(
                stripped.startswith("try:")
                # `if TYPE_CHECKING:` and `if t.TYPE_CHECKING:` / `if typing.TYPE_CHECKING:`
                or re.match(r"if\s+(?:\w+\.)?TYPE_CHECKING\b", stripped)
            )
    return False


def _declaration_findings(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    artifacts = ai_usage.detect_artifacts(ctx.root)
    ai_file = find_root_file(ctx.root, ai_usage.DEFAULT_NAME)
    if artifacts and not ai_file:
        findings.append(
            make_finding(
                "AI-013",
                "ai",
                "info",
                "检测到 AI 助手配置，但没有 AI 使用声明",
                f"仓库里有 {('、'.join(artifacts[:4]))} 等 AI 助手痕迹，但没有 AI_USAGE.md；"
                "「哪些代码由 AI 参与」目前无法自证。",
                remediation="运行 `provemark ai-usage` 生成声明骨架，补充工具、范围与人工复核。",
                detail={"artifacts": artifacts[:10]},
            )
        )
    elif ai_file:
        try:
            text = (ctx.root / ai_file).read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        missing = ai_usage.missing_sections(text)
        unfilled = ai_usage.unfilled_placeholders(text)
        if missing:
            findings.append(
                make_finding(
                    "AI-014",
                    "ai",
                    "info",
                    f"AI 使用声明缺少 {len(missing)} 个必需小节",
                    f"AI_USAGE.md 缺少：{'、'.join(missing)}；尽调时无法回答「AI 用在哪、谁复核」。",
                    path=ai_file,
                    remediation="补齐小节，或重新生成：`provemark ai-usage --force`。",
                    detail={"missing_sections": missing},
                )
            )
        elif unfilled:
            findings.append(
                make_finding(
                    "AI-014",
                    "ai",
                    "info",
                    f"AI 使用声明还有 {unfilled} 处「待填写」",
                    "声明骨架已存在，但关键信息仍为空，无法作为原创性证据。",
                    path=ai_file,
                    remediation="把「待填写」替换成实际工具、范围与复核人。",
                    detail={"unfilled": unfilled},
                )
            )
    return findings


def scan(ctx: Context) -> list[Finding]:
    findings: list[Finding] = _declaration_findings(ctx)
    declared_npm = set(ctx.deps.declared.get("npm", set()))
    declared_py = set(ctx.deps.declared.get("PyPI", set()))
    py_index = _py_import_index(declared_py)
    declared_go = set(ctx.deps.declared.get("Go", set()))
    local = _local_names(ctx)
    stdlib = frozenset(getattr(sys, "stdlib_module_names", frozenset()))
    go_module = _go_module(ctx)
    fake_py = getattr(rules, "PY_FAKE_MODULES", set())
    import_issues: dict[str, dict[str, Any]] = {}

    for info in ctx.scoped_files():
        if not ctx.in_scope(info.rel) or not info.is_code or _skip_file(info.rel):
            continue
        lang = _lang(info.path)
        is_test = info.is_test
        is_script = any(token in info.rel.lower() for token in SCRIPT_DIRS)
        aggregates: dict[str, list[tuple[int, str, dict]]] = {}

        for lineno, line in enumerate(info.lines, start=1):
            if not line or len(line) > 2000:
                continue
            if "re.compile(" in line or "pattern =" in line:
                continue
            for rule in rules.AI_PATTERNS:
                languages = rule["languages"]  # type: ignore[assignment]
                if lang not in languages and "generic" not in languages:
                    continue
                if rule["id"] in ("AI-007",) and is_test:
                    continue
                if rule["id"] in ("AI-008",) and ctx.config.ai_allow_debug_logs:
                    continue
                if is_test and rule["id"] in TEST_SKIP_RULES:
                    continue
                if rule["id"] == "AI-020" and _is_cli_file(info.rel):
                    continue
                match = rule["pattern"].search(line)  # type: ignore[union-attr]
                if not match:
                    continue
                severity = str(rule["severity"])
                if is_test:
                    severity = DOWNGRADE.get(severity, severity)
                if is_script and severity in ("high", "medium"):
                    severity = DOWNGRADE.get(severity, severity)
                entry = {
                    "severity": severity,
                    "line": lineno,
                    "column": match.start() + 1,
                    "snippet": line.strip()[:200],
                    "rule": rule,
                }
                if str(rule["id"]) in AGGREGATE_RULES:
                    aggregates.setdefault(str(rule["id"]), []).append((lineno, line.strip(), entry))
                else:
                    findings.append(_build(info.rel, entry))
                break

        for rule_id, items in aggregates.items():
            first_line, first_snippet, first_entry = items[0]
            rule = first_entry["rule"]
            extra = f"（本文件共 {len(items)} 处）" if len(items) > 1 else ""
            findings.append(
                make_finding(
                    rule_id,
                    "ai",
                    first_entry["severity"],
                    f"{rule['title']}{extra}",
                    str(rule["message"]),
                    path=info.rel,
                    line=first_line,
                    column=first_entry["column"],
                    evidence=first_snippet,
                    remediation=str(rule["remediation"]),
                    detail={"count": len(items), "lines": [item[0] for item in items[:20]]},
                )
            )

        if lang == "py":
            findings.extend(_silent_excepts(info.rel, info.lines, is_test, is_script))

        for record in _check_imports(
            rel=info.rel,
            lang=lang,
            lines=info.lines,
            declared_npm=declared_npm,
            py_index=py_index,
            declared_go=declared_go,
            local=local,
            stdlib=stdlib,
            go_module=go_module,
            is_test=is_test,
            is_script=is_script,
            fake_py=fake_py,
            has_manifests=bool(ctx.deps.packages),
        ):
            key = f"{record['ecosystem']}:{record['module']}"
            record_confidence = float(record.get("confidence", 0.8))
            bucket = import_issues.setdefault(
                key,
                {
                    "module": record["module"],
                    "ecosystem": record["ecosystem"],
                    "severity": record["severity"],
                    "confidence": record_confidence,
                    "message": record["message"],
                    "remediation": record["remediation"],
                    "paths": [],
                    "first_path": record["path"],
                    "first_line": record["line"],
                    "evidence": record["evidence"],
                    "test_only": True,
                },
            )
            bucket["severity"] = _worse(bucket["severity"], record["severity"])
            bucket["confidence"] = min(bucket["confidence"], record_confidence)
            bucket["test_only"] = bool(bucket["test_only"] and record["is_test"])
            if len(bucket["paths"]) < 6:
                bucket["paths"].append(f"{record['path']}:{record['line']}")

    findings.extend(_import_findings(import_issues))
    findings.extend(_loop_findings(ctx))
    return findings


def _silent_excepts(rel: str, lines: list[str], is_test: bool, is_script: bool) -> list[Finding]:
    findings: list[Finding] = []
    for index, line in enumerate(lines):
        match = re.match(r"^\s*except(?:\s+([^:]+))?:\s*$", line)
        if not match:
            continue
        exception = (match.group(1) or "").strip()
        if "ImportError" in exception or "ModuleNotFoundError" in exception:
            continue
        severity = "medium"
        if exception and "Exception" not in exception and exception != "":
            severity = "low"
        if is_test or is_script:
            severity = DOWNGRADE[severity]
        indent = len(line) - len(line.lstrip())
        for inner in range(index + 1, min(len(lines), index + 4)):
            body = lines[inner]
            if not body.strip():
                continue
            body_indent = len(body) - len(body.lstrip())
            if body_indent <= indent:
                break
            if body.strip() in ("pass", "...") or body.strip().startswith("pass  #"):
                findings.append(
                    make_finding(
                        "AI-004",
                        "ai",
                        severity,
                        "异常被静默吞掉",
                        f"`except {exception or '(裸 except)'}` 分支里只有 pass，出错时没有任何信号，排查成本极高。",
                        path=rel,
                        line=inner + 1,
                        evidence=f"{line.strip()} / {body.strip()}",
                        remediation="至少记录日志并保留上下文；确实要忽略时，写明为什么可以忽略。",
                    )
                )
            break
    return findings


def _import_findings(issues: dict[str, dict[str, Any]]) -> list[Finding]:
    findings: list[Finding] = []
    for bucket in issues.values():
        count = len(bucket["paths"])
        severity = bucket["severity"]
        if bucket["test_only"]:
            severity = "low"
        elif bucket["module"].lower() in TEST_ONLY_PACKAGES:
            severity = _worse(severity, "medium")
        extra = f"（{count} 处）" if count > 1 else ""
        findings.append(
            make_finding(
                "AI-012",
                "ai",
                severity,
                f"`{bucket['module']}` 未在依赖清单中声明{extra}",
                bucket["message"] + " 出现位置：" + "、".join(bucket["paths"]) + ("…" if count > 1 else ""),
                path=bucket["first_path"],
                line=bucket["first_line"],
                evidence=bucket["evidence"],
                confidence=bucket["confidence"],
                remediation=bucket["remediation"],
                detail={"module": bucket["module"], "count": count, "paths": bucket["paths"]},
            )
        )
    return findings


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" \t"))


def _is_cli_file(rel: str) -> bool:
    lowered = f"/{rel.lower()}"
    tokens = ("/cli.py", "/cli.js", "/cli.ts", "/__main__.py", "/cmd/", "manage.py", "/main.py", "/main.js", "/main.ts")
    return any(token in lowered for token in tokens)


def _loop_findings(ctx: Context) -> list[Finding]:
    """Loop-body checks: sequential `await` in a loop, and N+1 queries.

    Both are the engineering mistakes AI writes most often on the backend: the
    code works on three rows and collapses at three thousand. They need the
    loop body (a line window), so they cannot be expressed as a single-line
    regex and live here instead of AI_PATTERNS.
    """
    findings: list[Finding] = []
    for info in ctx.scoped_files():
        if not ctx.in_scope(info.rel) or not info.is_code or _skip_file(info.rel):
            continue
        lang = _lang(info.path)
        if lang not in ("py", "js", "ts"):
            continue
        is_test = info.is_test
        is_script = any(token in info.rel.lower() for token in SCRIPT_DIRS)
        emitted: set[str] = set()
        lines = info.lines
        for index, line in enumerate(lines):
            if not LOOP_START.match(line):
                continue
            base = _indent_of(line)
            for cursor in range(index + 1, min(index + 9, len(lines))):
                body = lines[cursor]
                stripped = body.strip()
                if not stripped:
                    continue
                indent = _indent_of(body)
                if indent <= base:
                    break
                for rule in rules.ENGINEERING_LOOP_RULES:
                    rule_id = str(rule["id"])
                    if is_test and rule_id in TEST_SKIP_RULES:
                        continue
                    if rule_id in emitted or lang not in rule["languages"]:  # type: ignore[operator]
                        continue
                    signal = str(rule["signal"])
                    if not _matches_signal(signal, stripped):
                        continue
                    severity = str(rule["severity"])
                    if is_test:
                        severity = DOWNGRADE.get(severity, severity)
                    if is_script and severity in ("high", "medium"):
                        severity = DOWNGRADE.get(severity, severity)
                    findings.append(
                        _build(
                            info.rel,
                            {
                                "severity": severity,
                                "line": index + 1,
                                "column": 1,
                                "snippet": line.strip()[:200],
                                "rule": rule,
                            },
                        )
                    )
                    emitted.add(rule_id)
    return findings


def _build(rel: str, entry: dict) -> Finding:
    rule = entry["rule"]
    return make_finding(
        str(rule["id"]),
        "ai",
        entry["severity"],
        str(rule["title"]),
        str(rule["message"]),
        path=rel,
        line=entry["line"],
        column=entry["column"],
        evidence=entry["snippet"],
        remediation=str(rule["remediation"]),
    )


def _check_imports(
    *,
    rel: str,
    lang: str,
    lines: list[str],
    declared_npm: set[str],
    py_index: set[str],
    declared_go: set[str],
    local: set[str],
    stdlib: frozenset[str],
    go_module: str,
    is_test: bool,
    is_script: bool,
    fake_py: set[str],
    has_manifests: bool,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    patterns = rules.IMPORT_PATTERNS.get(lang)
    if not patterns:
        return records
    seen: set[str] = set()
    in_go_block = False
    code_lines = _code_mask(lines, lang)

    for lineno, line in enumerate(lines, start=1):
        if not code_lines[lineno - 1]:
            continue
        if lang == "go":
            stripped = line.strip()
            if stripped.startswith("import ("):
                in_go_block = True
                continue
            if in_go_block and stripped == ")":
                in_go_block = False
                continue
            if not in_go_block and not stripped.startswith("import"):
                continue
        for pattern in patterns:
            match = pattern.search(line)
            if not match:
                continue
            spec = match.group(1).strip()
            if not spec:
                continue
            is_local_import = len(line) - len(line.lstrip()) > 0

            if lang == "py":
                if spec.startswith(("_", "tests", "test_")):
                    break
                if _is_guarded_optional(lines, lineno - 1, "py"):
                    break
                if _py_module_ok(spec, py_index, local, stdlib):
                    break
                module = spec.split(".")[0]
                normalized = module.lower().replace("_", "-")
                if normalized in seen:
                    break
                seen.add(normalized)
                severity = "high"
                if is_test or is_script or is_local_import:
                    severity = "medium"
                if normalized in fake_py and not has_manifests:
                    severity = "medium"
                confidence = 0.8
                if is_test:
                    confidence = 0.5
                elif is_script:
                    confidence = 0.6
                if normalized in fake_py and not has_manifests:
                    confidence = 0.4
                records.append(
                    {
                        "ecosystem": "PyPI",
                        "module": module,
                        "severity": severity,
                        "confidence": confidence,
                        "is_test": is_test,
                        "path": rel,
                        "line": lineno,
                        "evidence": f"import {spec}",
                        "message": (
                            f"`{spec}` 不在任何依赖清单里。AI 生成代码时经常“顺手 import 一个看似存在的包”，"
                            "本地装过依赖时不会报错，换台机器或进 CI 就会 ModuleNotFoundError。"
                        ),
                        "remediation": f"在依赖清单中显式声明 `{normalized}`（并确认它真实存在），或删掉未使用的导入。",
                    }
                )
            elif lang in ("js", "ts"):
                package = _js_package_name(spec)
                if _js_module_ok(spec, declared_npm, local):
                    break
                lowered = package.lower()
                if lowered in seen:
                    break
                seen.add(lowered)
                severity = "high"
                confidence = 0.8
                if is_test or is_script or is_local_import:
                    severity = "medium"
                    confidence = 0.5 if is_test else 0.6
                records.append(
                    {
                        "ecosystem": "npm",
                        "module": package,
                        "severity": severity,
                        "confidence": confidence,
                        "is_test": is_test,
                        "path": rel,
                        "line": lineno,
                        "evidence": f"import {spec}",
                        "message": (
                            f"`{package}` 不在 package.json 的依赖里。可能是 AI 编造的包名（幻觉依赖），"
                            "也可能是漏装，两者都会在干净环境里直接失败。"
                        ),
                        "remediation": f"确认 `{package}` 是否为真实包并加入依赖；若只是本地遗留，删除该导入。",
                    }
                )
            else:
                if "." not in spec.split("/")[0]:
                    break
                if go_module and spec.startswith(go_module):
                    break
                # go.mod declares MODULE paths; an import is usually a package
                # inside that module (`golang.org/x/net` covers
                # `golang.org/x/net/http2`). Comparing the full import path
                # against the module list flagged every third-party subpackage.
                if any(spec == module or spec.startswith(module + "/") for module in declared_go):
                    break
                if spec in seen:
                    break
                seen.add(spec)
                severity = "medium" if (is_test or is_script) else "high"
                confidence = 0.5 if is_test else (0.6 if is_script else 0.8)
                records.append(
                    {
                        "ecosystem": "Go",
                        "module": spec,
                        "severity": severity,
                        "confidence": confidence,
                        "is_test": is_test,
                        "path": rel,
                        "line": lineno,
                        "evidence": f'import "{spec}"',
                        "message": f"`{spec}` 不在 go.mod 的 require 列表中，`go mod tidy` 之后构建会失败。",
                        "remediation": "执行 `go mod tidy` 并提交更新后的 go.mod / go.sum。",
                    }
                )
            break
    return records
