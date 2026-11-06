from __future__ import annotations

import json
import re
from pathlib import Path

from ..models import Finding
from .. import ecosystems
from .base import Context, make_finding
from . import vcs

CREDENTIAL_SUFFIXES = (
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".jks",
    ".keystore",
    ".ppk",
    ".ovpn",
)
# 私钥文件名本身就说明问题，不需要看内容。
CREDENTIAL_NAMES = (
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
)
# 这些是「存放凭据的配置文件」，但仓库里更常见的是没写凭据的普通配置
# （例如只写了 package-lock=false 的 .npmrc），必须看内容再判断。
CREDENTIAL_CONFIG_NAMES = (
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".htpasswd",
    "credentials.json",
    "secrets.json",
    "service-account.json",
)
MAX_CREDENTIAL_FILE_BYTES = 256 * 1024
# 测试目录里的私钥多半是测试夹具（例如过期的测试证书），但仍要报出来让人判断，
# 只是不该按「真实泄漏」的最高级别计分——否则一个测试目录就能把整个仓库打成 F。
TEST_CREDENTIAL_CONFIDENCE = 0.4
TEST_PATH_TOKENS = ("tests", "test", "spec", "fixtures", "__tests__")


def _is_test_path(rel: str) -> bool:
    lowered = rel.lower()
    parts = lowered.split("/")
    if any(token in parts for token in TEST_PATH_TOKENS):
        return True
    return "/fixtures/" in lowered or bool(re.search(r"(^test_|_test\.|\.test\.|\.spec\.)", Path(lowered).name))


def _credential_severity(rel: str) -> str:
    return "high" if _is_test_path(rel) else "critical"


def _credential_confidence(rel: str) -> dict[str, float]:
    return {"confidence": TEST_CREDENTIAL_CONFIDENCE} if _is_test_path(rel) else {}


NPMRC_CREDENTIAL = re.compile(
    r"(?i)(?:^|[\s:/])(?:_authtoken|_auth|_password|password|auth)[ \t]*=[ \t]*(?P<value>\S+)"
)
PYPIRC_CREDENTIAL = re.compile(
    r"(?im)^[ \t]*(?:password|passwd|_password|api_?key|apikey|token|secret|passphrase)"
    r"[ \t]*[=:][ \t]*(?P<value>\S+)"
)
NETRC_CREDENTIAL = re.compile(
    r"(?im)^[ \t]*(?:machine\b[^\n]*?\bpassword\b[ \t]+|password\b[ \t]+)(?P<value>\S+)"
)
HTPASSWD_CREDENTIAL = re.compile(r"(?m)^(?!#)[^:\s]+:(?P<value>[^\s:]+)[ \t]*$")
JSON_SECRET_KEY = re.compile(
    r"(?i)token|password|passwd|secret|api_?key|private_?key|access_?key|credential|passphrase"
)
JSON_SECRET_ASSIGN = re.compile(
    r"(?i)\"[^\"]*(?:token|password|passwd|secret|api_?key|private_?key|access_?key|credential|passphrase)"
    r"[^\"]*\"[ \t]*:[ \t]*\"(?P<value>[^\"]+)\""
)
VENDOR_DIRS = (
    "node_modules/",
    "__pycache__/",
    ".venv/",
    "venv/",
    "site-packages/",
    ".gradle/",
    ".dart_tool/",
    "obj/",
    "target/",
)
JUNK_NAMES = (".DS_Store", "Thumbs.db", "desktop.ini")
CI_PATHS = (
    ".github/workflows",
    ".gitlab-ci.yml",
    ".circleci/config.yml",
    "azure-pipelines.yml",
    ".travis.yml",
    "Jenkinsfile",
)
IGNORE_MUST_HAVE = {
    ".env": ("env", "high", "提交 .env 会把密钥直接推到远端，且历史记录无法简单删除。"),
    "node_modules/": ("node_modules", "medium", "依赖目录体积巨大且不可复现，应通过 lockfile 安装。"),
    "__pycache__/": ("__pycache__", "low", "编译缓存会不断制造无意义 diff。"),
    "*.pyc": ("pyc", "low", "Python 字节码不应进入版本库。"),
    "dist/": ("dist", "low", "构建产物应由 CI 重新生成。"),
    ".DS_Store": ("DS_Store", "low", "macOS 系统文件，属于噪音。"),
}
LICENSE_NAMES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "COPYING.md", "LICENCE")
README_NAMES = ("README", "README.md", "README.rst", "README.txt", "readme.md")
NOTICES_NAMES = (
    "THIRD_PARTY_NOTICES.md",
    "THIRD_PARTY_NOTICES",
    "THIRD_PARTY_NOTICES.txt",
    "NOTICE",
    "NOTICE.md",
    "NOTICES.md",
)
BUILD_ONLY = {"GitHub Actions"}


def _root_names(root: Path) -> set[str]:
    try:
        return {item.name for item in root.iterdir()}
    except OSError:
        return set()


def _find_first(ctx: Context, names: tuple[str, ...]) -> str:
    root_names = _root_names(ctx.root)
    for name in names:
        if name in root_names:
            return name
    for name in root_names:
        lowered = name.lower()
        for candidate in names:
            if lowered == candidate.lower():
                return name
    return ""


# Ecosystem conventions differ: Rust crates ship LICENSE-MIT / LICENSE-APACHE,
# some projects use LICENSE.rst, COPYING.LESSER, LICENCE.md. Requiring an exact
# name reported "no license" for repos that plainly have one.
LICENSE_PREFIXES = ("license", "licence", "copying")


def _find_license_file(ctx: Context) -> str:
    exact = _find_first(ctx, LICENSE_NAMES)
    if exact:
        return exact
    for name in sorted(_root_names(ctx.root)):
        lowered = name.lower()
        if not lowered.startswith(LICENSE_PREFIXES):
            continue
        try:
            if (ctx.root / name).is_file():
                return name
        except OSError:
            continue
    return ""


# 安全披露文件不一定叫 SECURITY.md：大小写不统一（.github/security.md）、
# 放在 .github/ 下、或者用 .txt / .rst 都很常见，按名字找会漏。
SECURITY_NAMES = ("SECURITY.md", "SECURITY.txt", "SECURITY.rst", "SECURITY")
SECURITY_DIRS = (".github",)
SECURITY_NAME_SET = {name.lower() for name in SECURITY_NAMES}


def _find_security_policy(ctx: Context) -> str:
    for base in (ctx.root, *(ctx.root / name for name in SECURITY_DIRS)):
        for name in sorted(_root_names(base)):
            if name.lower() in SECURITY_NAME_SET:
                return name
    return ""


# 测试文件的命名远不止 tests/ 目录：node --test 用的 test.js、test-utils.ts
# 这类「文件名本身是 test-*」的写法以前都算不到，会把有测试的仓库报成没测试。
TEST_BASENAMES = (
    "test.js",
    "test.ts",
    "test.mjs",
    "test.cjs",
    "test.py",
    "test.rb",
    "test.go",
    "test.rs",
    "test.java",
)
TEST_PREFIXED = re.compile(
    r"^test[-.][\w.-]*\.(?:js|jsx|ts|tsx|mjs|cjs|py|rb|go|rs|java)$", re.IGNORECASE
)


def _is_test_file(rel: str) -> bool:
    name = Path(rel).name
    lowered = name.lower()
    if "/tests/" in rel or rel.startswith("tests/") or lowered.startswith("test_"):
        return True
    if ".test." in lowered or ".spec." in lowered:
        return True
    if lowered in TEST_BASENAMES:
        return True
    return bool(TEST_PREFIXED.match(lowered))


def _json_has_credential(text: str) -> bool:
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return bool(JSON_SECRET_ASSIGN.search(text))
    return _json_credential(payload)


def _json_credential(node) -> bool:
    if isinstance(node, dict):
        for key, value in node.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
            if JSON_SECRET_KEY.search(normalized) and _json_value_present(value):
                return True
            if _json_credential(value):
                return True
        return False
    if isinstance(node, list):
        return any(_json_credential(item) for item in node)
    return False


def _json_value_present(value) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (dict, list)):
        return bool(value)
    return True


def _holds_credential(name: str, text: str) -> bool:
    """配置文件里是否真的写了凭据。"""
    if not text.strip():
        return False
    if name == ".npmrc":
        return bool(NPMRC_CREDENTIAL.search(text))
    if name == ".pypirc":
        return bool(PYPIRC_CREDENTIAL.search(text))
    if name == ".netrc":
        return bool(NETRC_CREDENTIAL.search(text))
    if name == ".htpasswd":
        return bool(HTPASSWD_CREDENTIAL.search(text))
    return _json_has_credential(text)


def _credential_material(root: Path, rel: str) -> bool | None:
    """读取凭据配置文件内容；读不到时返回 None（无法判断，按泄漏处理）。"""
    path = root / rel
    try:
        if path.stat().st_size > MAX_CREDENTIAL_FILE_BYTES:
            return None
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return _holds_credential(Path(rel).name, text)


def scan(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    root_names = _root_names(ctx.root)
    tracked = vcs.tracked_files(ctx.root)
    if tracked is not None:
        tracked = [rel for rel in tracked if not ctx.config.is_excluded(rel)]
    is_repo = vcs.is_git_repo(ctx.root)
    if not is_repo:
        ctx.note("当前目录不是 Git 仓库，跳过「已提交文件」相关检查")
    if tracked is None and is_repo:
        ctx.note("无法读取 Git 索引，跳过「已提交文件」相关检查")

    kind = ctx.config.project_kind
    license_file = _find_license_file(ctx)
    if not license_file and kind != "docs":
        findings.append(
            make_finding(
                "HYG-001",
                "hygiene",
                ctx.config.license_policy.no_license,
                "仓库没有许可证文件",
                "没有 LICENSE 意味着默认保留所有权利，别人（包括未来的雇主或客户）无法合法使用你的代码。",
                remediation="运行 `provemark fix --apply` 生成与策略一致的 LICENSE，或手动添加。",
                reference="https://choosealicense.com/",
            )
        )

    if not _find_first(ctx, README_NAMES):
        findings.append(
            make_finding(
                "HYG-002",
                "hygiene",
                "medium",
                "缺少 README",
                "README 是别人判断“这个项目能不能用”的第一入口，也是 AI 代理理解项目边界的主要上下文。",
                remediation="补一份 README：它解决什么问题、怎么跑起来、已知限制、许可证。",
            )
        )

    if not _find_security_policy(ctx) and kind != "docs":
        findings.append(
            make_finding(
                "HYG-003",
                "hygiene",
                "medium",
                "缺少 SECURITY.md",
                "没有安全披露渠道时，研究者只能公开提 issue，漏洞会被动公开。",
                remediation="添加 SECURITY.md 写明报告方式与响应预期（`provemark fix --apply` 可生成模板）。",
            )
        )

    gitignore = ctx.root / ".gitignore"
    has_gitignore = gitignore.is_file()
    if not has_gitignore:
        findings.append(
            make_finding(
                "HYG-004",
                "hygiene",
                "medium",
                "缺少 .gitignore",
                "没有忽略规则时，.env、依赖目录、构建产物很容易被误提交。",
                remediation="运行 `provemark fix --apply` 生成覆盖 .env / 依赖 / 产物的 .gitignore。",
            )
        )
    else:
        try:
            content = gitignore.read_text(encoding="utf-8", errors="replace")
        except OSError:
            content = ""
        lines = {line.strip().lstrip("/") for line in content.splitlines() if line.strip()}
        if not any(line in (".env", "*.env", ".env*", ".env.*") for line in lines):
            candidates = list(tracked) if tracked is not None else [item.rel for item in ctx.files]
            env_present = any(
                Path(rel).name == ".env" or Path(rel).name.startswith(".env.")
                for rel in candidates
            )
            findings.append(
                make_finding(
                    "HYG-005",
                    "hygiene",
                    "high" if env_present else "low",
                    ".gitignore 没有忽略 .env",
                    "仓库里确实存在 .env 文件，却没有忽略规则，一次 `git add .` 就会把它推上去。"
                    if env_present
                    else "当前仓库还没有 .env，但缺少忽略规则；等第一次本地配置出现时很容易被误提交。",
                    path=".gitignore",
                    remediation="在 .gitignore 中加入 `.env` 与 `.env.*`（保留 `.env.example`）。",
                )
            )

    if tracked is not None:
        for rel in tracked:
            lowered = rel.lower()
            name = Path(rel).name
            if lowered.endswith((".env", ".env.local", ".env.production", ".env.development")) or name == ".env":
                if not lowered.endswith((".example", ".sample", ".template")):
                    findings.append(
                        make_finding(
                            "HYG-006",
                            "secrets",
                            "critical",
                            "环境变量文件已被提交",
                            "该文件通常包含真实密钥，且已进入 Git 历史。",
                            path=rel,
                            remediation="删除文件、轮换其中所有密钥，并用 git filter-repo 清理历史。",
                        )
                    )
            if lowered.endswith(CREDENTIAL_SUFFIXES) or name in CREDENTIAL_NAMES:
                findings.append(
                    make_finding(
                        "HYG-007",
                        "secrets",
                        _credential_severity(rel),
                        "凭据或私钥文件已被提交",
                        "私钥类文件一旦进入版本库就应视为泄漏，即使后续删除也仍在历史中。",
                        path=rel,
                        remediation="吊销对应凭据、从版本库移除并清理历史。",
                        **_credential_confidence(rel),
                    )
                )
            elif name in CREDENTIAL_CONFIG_NAMES:
                holds = _credential_material(ctx.root, rel)
                if holds is not False:
                    findings.append(
                        make_finding(
                            "HYG-007",
                            "secrets",
                            _credential_severity(rel),
                            "凭据或私钥文件已被提交",
                            "该配置文件里确实写了认证凭据，一旦进入版本库就应视为泄漏。",
                            path=rel,
                            remediation="吊销对应凭据、从版本库移除并清理历史。",
                            **_credential_confidence(rel),
                        )
                    )
            if lowered.startswith(VENDOR_DIRS) or "/node_modules/" in lowered or "/__pycache__/" in lowered:
                findings.append(
                    make_finding(
                        "HYG-008",
                        "hygiene",
                        "high",
                        "依赖 / 缓存目录被提交",
                        "这些目录使仓库体积膨胀、diff 失真，而且无法复现。",
                        path=rel,
                        remediation="从索引中移除（git rm -r --cached）并加入 .gitignore。",
                    )
                )
                break
            if name in JUNK_NAMES:
                findings.append(
                    make_finding(
                        "HYG-012",
                        "hygiene",
                        "low",
                        "系统垃圾文件被提交",
                        "这类文件与代码无关，会制造噪音。",
                        path=rel,
                        remediation="从索引移除并加入 .gitignore。",
                    )
                )
            size = vcs.file_size_in_git(ctx.root, rel)
            if size > 5 * 1024 * 1024:
                findings.append(
                    make_finding(
                        "HYG-009",
                        "hygiene",
                        "medium",
                        "仓库中有较大的二进制文件",
                        f"该文件 {size / 1024 / 1024:.1f} MB，会让克隆越来越慢且无法 diff。",
                        path=rel,
                        remediation="改用 Git LFS，或把产物放到 Release / 对象存储。",
                        detail={"size_bytes": size},
                    )
                )

    if not any((ctx.root / path).exists() for path in CI_PATHS):
        findings.append(
            make_finding(
                "HYG-010",
                "hygiene",
                "low",
                "没有 CI 配置",
                "没有 CI 时，测试与扫描只能靠人记得跑；AI 提交更容易漏验证。",
                remediation="运行 `provemark init` 生成 GitHub Actions 工作流。",
            )
        )

    test_like = [
        f
        for f in (tracked if tracked is not None else [item.rel for item in ctx.files])
        if _is_test_file(f)
    ]
    if not test_like:
        findings.append(
            make_finding(
                "HYG-011",
                "hygiene",
                "info",
                "没有找到测试文件",
                "没有测试时，任何自动修改都无法验证是否破坏了行为。",
                remediation="至少为核心路径补一个可运行的测试。",
            )
        )

    lock_by_ecosystem: dict[str, set[str]] = {}
    for name in set(root_names) | {path.name for path in ctx.deps.lockfiles}:
        ecosystem = ecosystems.ecosystem_of_lockfile(name)
        if ecosystem:
            lock_by_ecosystem.setdefault(ecosystem, set()).add(name)
    for ecosystem, names in sorted(lock_by_ecosystem.items()):
        if len(names) < 2:
            continue
        findings.append(
            make_finding(
                "HYG-013",
                "hygiene",
                "low",
                f"{ecosystems.label_of(ecosystem)} 同时存在多个锁文件",
                f"检测到 {', '.join(sorted(names))}，不同包管理器会各自安装出不同依赖树。",
                remediation="保留团队实际使用的那一个，删除其余。",
            )
        )

    runtimes = [
        package
        for package in ctx.deps.packages
        if package.scope != "dev" and package.ecosystem not in BUILD_ONLY
    ]
    notices_file = _find_first(ctx, NOTICES_NAMES)
    if runtimes and not notices_file and kind != "docs":
        findings.append(
            make_finding(
                "HYG-014",
                "hygiene",
                "low",
                "缺少 THIRD_PARTY_NOTICES",
                f"仓库引用了 {len(runtimes)} 个运行时依赖，但没有归因文件；对外分发时无法说明第三方组件与许可证。",
                remediation="运行 `provemark notices` 生成 THIRD_PARTY_NOTICES.md。",
            )
        )
    elif notices_file:
        try:
            content = (ctx.root / notices_file).read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            content = ""
        missing = [package for package in runtimes if package.name.lower() not in content]
        if missing:
            sample = "、".join(package.display for package in missing[:5])
            findings.append(
                make_finding(
                    "HYG-015",
                    "hygiene",
                    "info",
                    f"THIRD_PARTY_NOTICES 缺少 {len(missing)} 个依赖",
                    f"归因文件没有覆盖当前依赖：{sample}" + ("…" if len(missing) > 5 else "") + "。",
                    path=notices_file,
                    remediation="重新生成：`provemark notices --force`。",
                    detail={
                        "count": len(missing),
                        "missing": [package.display for package in missing[:20]],
                    },
                )
            )

    return _artifact_adjusted(ctx, findings)


# Files that a published artifact never carries: a source distribution, a crate
# tarball or an `egg-info` tree is built from the repo, not shipped with it. Rules
# that only ask "does this file exist at the root" are therefore unanswerable
# there — keep them visible but advisory, and say why.
MISSING_FILE_RULES = {"HYG-003", "HYG-004", "HYG-010", "HYG-014"}


def _looks_like_release_artifact(root: Path) -> bool:
    names = {name.lower() for name in _root_names(root)}
    if "pkg-info" in names or ".cargo_vcs_info.json" in names:
        return True
    return any(name.endswith((".egg-info", ".dist-info")) for name in names)


def _artifact_adjusted(ctx: Context, findings: list[Finding]) -> list[Finding]:
    if not _looks_like_release_artifact(ctx.root):
        return findings
    adjusted: list[Finding] = []
    touched = False
    for finding in findings:
        if finding.rule_id in MISSING_FILE_RULES and finding.severity != "info":
            finding.severity = "info"
            touched = True
        adjusted.append(finding)
    if touched:
        ctx.note(
            "根目录看起来是发布包（sdist / crate / dist-info）：.gitignore、SECURITY.md、"
            "CI、归因文件通常不随包发布，相关 HYG 结论已降为提示，请以源码仓库为准。"
        )
    return adjusted

