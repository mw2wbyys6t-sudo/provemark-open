from __future__ import annotations

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
CREDENTIAL_NAMES = (
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".htpasswd",
    "credentials.json",
    "secrets.json",
    "service-account.json",
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

    if "SECURITY.md" not in root_names and kind != "docs":
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
                        "critical",
                        "凭据或私钥文件已被提交",
                        "私钥类文件一旦进入版本库就应视为泄漏，即使后续删除也仍在历史中。",
                        path=rel,
                        remediation="吊销对应凭据、从版本库移除并清理历史。",
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
        if "/tests/" in f or f.startswith("tests/") or Path(f).name.startswith("test_") or ".test." in f or ".spec." in f
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

