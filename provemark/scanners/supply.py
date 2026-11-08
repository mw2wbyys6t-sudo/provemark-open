from __future__ import annotations

import json
import re

from ..models import Finding
from ..rules.popular import KNOWN_MALICIOUS, POPULAR
from .. import ecosystems, vendored
from ..generated import find_root_file
from .base import Context, make_finding

FLOAT_SPECS = {"", "*", "latest", "x", "any"}
CURL_PIPE = re.compile(r"(?:curl|wget)[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba)?sh\b")
ACTIONS_USE = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)")
DOCKER_FROM = re.compile(r"^\s*FROM\s+([^\s]+)", re.I)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
PR_TARGET = re.compile(
    r"^\s*(?:on\s*:\s*(?:\[[^\]]*)?|-\s*)?pull_request_target\b", re.M
)
PR_HEAD_REF = re.compile(
    r"github\.(?:event\.pull_request\.head\.(?:sha|ref)|head_ref)\b"
)
WRITE_ALL = re.compile(r"^\s*permissions\s*:\s*write-all\s*$", re.M)


def levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for i, char_left in enumerate(left, start=1):
        current = [i]
        for j, char_right in enumerate(right, start=1):
            insert = current[j - 1] + 1
            delete = previous[j] + 1
            substitute = previous[j - 1] + (char_left != char_right)
            current.append(min(insert, delete, substitute))
        previous = current
    return previous[-1]


def _scan_typosquat(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    for package in ctx.deps.packages:
        if package.scope in ("dev", "peer") or not package.direct:
            continue
        ecosystem = package.ecosystem
        name = package.name
        if not name or name.startswith("@") or "/" in name or ":" in name or ecosystem == "Go":
            continue
        malicious = KNOWN_MALICIOUS.get(ecosystem, set())
        if name in malicious:
            findings.append(
                make_finding(
                    "SCP-003",
                    "supply",
                    "critical",
                    f"{name} 是已知的恶意 / 抢注包名",
                    "该包名出现在公开的恶意包清单中，安装即可能执行任意代码。",
                    path=package.manifest.split(";")[0] if package.manifest else "",
                    evidence=name,
                    remediation="立即移除该依赖，检查是否已被安装过（node_modules / site-packages），并轮换环境中所有凭据。",
                )
            )
            continue
        popular = POPULAR.get(ecosystem, [])
        if name in popular or len(name) < 5:
            continue
        for candidate in popular:
            if candidate.startswith("@") or abs(len(candidate) - len(name)) > 2:
                continue
            distance = levenshtein(name.lower(), candidate.lower())
            threshold = 1 if len(candidate) < 6 else 2
            same_prefix = name[:3].lower() == candidate[:3].lower()
            same_initial = name[:1].lower() == candidate[:1].lower()
            if (
                0 < distance <= threshold
                and same_initial
                and (distance == 1 or same_prefix)
            ):
                findings.append(
                    make_finding(
                        "SCP-004",
                        "supply",
                        "high",
                        f"{name} 与流行包 {candidate} 只差 {distance} 个字符",
                        "这是典型的仿冒（typosquatting）特征：名字刻意贴近流行包，用来骗取安装量。"
                        "如果你的本意是使用流行包，这就是拼写错误。",
                        path=package.manifest.split(";")[0] if package.manifest else "",
                        evidence=f"{name} ≈ {candidate}",
                        remediation=f"确认包名；若本意是 {candidate}，改为它并重新安装。",
                        confidence=0.6,
                        detail={"distance": distance, "suspected": candidate},
                    )
                )
                break
    return findings


def _scan_versions(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    for package in ctx.deps.packages:
        if not package.direct or package.pinned_by_parent:
            continue
        declared = (package.declared or "").strip()
        if declared.lower() in FLOAT_SPECS:
            # Dev-only tools (ruff/tox/pytest) float by convention; they are not
            # shipped to users, so this stays an advisory instead of a gate item.
            severity = "info" if package.scope == "dev" else "medium"
            findings.append(
                make_finding(
                    "SCP-002",
                    "supply",
                    severity,
                    f"{package.name} 未指定任何版本约束",
                    "`*` / `latest` / 空声明会让每次安装都可能拿到不同代码，"
                    "一次上游投毒或破坏性升级就会直接影响你。",
                    path=package.manifest.split(";")[0] if package.manifest else "",
                    evidence=f"{package.name} {declared or '(空)'}".strip(),
                    remediation="声明明确版本范围并提交锁文件；CI 按锁文件安装（npm ci / pip install -r 锁文件）。",
                    detail={"package": package.name, "ecosystem": package.ecosystem, "scope": package.scope},
                )
            )
    return findings


def _scan_lockfiles(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    manifests_by_dir: dict[str, set[str]] = {}
    for manifest in ctx.deps.manifests:
        rel = ecosystems.rel_path(manifest, ctx.root)
        directory = rel.rsplit("/", 1)[0] if "/" in rel else "."
        manifests_by_dir.setdefault(directory, set()).add(manifest.name)
    lock_names = {path.name for path in ctx.deps.lockfiles} | {
        path.name for path in ctx.deps.manifests
    }

    for directory, names in manifests_by_dir.items():
        present: list[str] = []
        for name in sorted(names):
            ecosystem = ecosystems.ecosystem_of_manifest(name)
            if ecosystem and ecosystem not in present:
                present.append(ecosystem)
        for ecosystem in present:
            expected = ecosystems.lockfiles_of(ecosystem)
            if not expected or lock_names & set(expected):
                continue
            if ecosystem in ctx.deps.lock_optional:
                continue
            loose = [
                package
                for package in ctx.deps.packages
                if package.ecosystem == ecosystem
                and package.direct
                and not package.version
                and not package.pinned_by_parent
            ]
            # A library is consumed through the resolver of whoever installs it,
            # so not committing a lockfile is the norm (flask, requests, serde all
            # do this). Applications should pin; libraries only get an advisory.
            is_library = str(getattr(ctx.config, "project_kind", "library")) == "library"
            if is_library:
                # Only the default install has to be reproducible for a library:
                # `pip install provemark` resolves zero dependencies. A floating
                # version inside an optional extra or a dev group is opt-in and is
                # decided by the consumer's/CI's resolver — that is not a reason to
                # demand a lockfile the package would never ship.
                loose = [package for package in loose if package.scope == "runtime"]
            if not loose:
                continue
            findings.append(
                make_finding(
                    "SCP-001",
                    "supply",
                    "low" if is_library else "medium",
                    f"{ecosystems.label_of(ecosystem)} 依赖没有锁文件，安装结果不可复现",
                    f"在 {directory}/ 下检测到清单文件，但没有 "
                    f"{' / '.join(expected)}；"
                    f"其中 {len(loose)} 个依赖只声明了范围，实际安装版本取决于当天上游。"
                    + ("（库通常不提交锁文件，由使用方的解析器决定版本；应用应提交。）" if is_library else ""),
                    path=directory if directory != "." else "",
                    evidence=", ".join(package.name for package in loose[:6]),
                    remediation="生成并提交锁文件；CI 使用锁文件安装（npm ci / uv sync / go mod download）。",
                    detail={"ecosystem": ecosystem, "loose": len(loose), "project_kind": "library" if is_library else "app"},
                )
            )
    return findings


def _scan_indexes(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    allowed = {host.lower() for host in ctx.config.supply_allowed_indexes}
    for entry in ctx.deps.indexes:
        url = str(entry.get("url") or "")
        lowered = url.lower()
        manifest = str(entry.get("manifest") or "")
        if lowered.startswith("http://"):
            findings.append(
                make_finding(
                    "SCP-005",
                    "supply",
                    "high",
                    "依赖源使用明文 HTTP",
                    "明文源意味着包内容可能在传输中被替换，等同于把执行权限交给链路上的任何人。",
                    path=manifest,
                    evidence=url,
                    remediation="改用 HTTPS 源，并在 CI 中固定依赖源。",
                )
            )
            continue
        host = re.sub(r"^[a-z]+://", "", lowered).split("/")[0]
        if "extra-index-url" in lowered or (host and host not in allowed):
            findings.append(
                make_finding(
                    "SCP-006",
                    "supply",
                    "medium",
                    "依赖来自非默认源",
                    f"`{host or url}` 不在允许的源列表中。额外源会带来依赖混淆（dependency confusion）"
                    "风险：同名包可能从优先级更高的源被装进来。",
                    path=manifest,
                    evidence=url,
                    remediation="使用单一可信源 + 哈希校验；确需内部源时，在 supply.allowed_indexes 中登记。",
                )
            )
    return findings


def _scan_workflows(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    for info in ctx.scoped_files():
        rel = info.rel
        if not rel.startswith(".github/workflows/") or not rel.endswith((".yml", ".yaml")):
            continue
        for lineno, line in enumerate(info.lines, start=1):
            match = ACTIONS_USE.match(line)
            if not match:
                continue
            ref = match.group(1)
            if "@" not in ref:
                continue
            _, version = ref.rsplit("@", 1)
            if SHA_RE.match(version) or ref.startswith("./") or ref.startswith("docker://"):
                continue
            findings.append(
                make_finding(
                    "SCP-007",
                    "supply",
                    "low",
                    f"Action {ref} 未固定到提交 SHA",
                    "标签（如 v4）可以被作者移动，供应链攻击常通过改写标签指向恶意提交实现。",
                    path=rel,
                    line=lineno,
                    evidence=ref,
                    remediation="固定到完整 commit SHA，并让 Dependabot 负责升级。",
                )
            )
    return findings


def _scan_scripts(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    for info in ctx.scoped_files():
        if info.suffix not in (".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd"):
            continue
        for lineno, line in enumerate(info.lines, start=1):
            if CURL_PIPE.search(line):
                findings.append(
                    make_finding(
                        "SCP-008",
                        "supply",
                        "medium",
                        "脚本中存在「下载即执行」",
                        "`curl | bash` 把远端内容直接交给 shell，脚本一旦被替换就会在你机器上执行任意命令。",
                        path=info.rel,
                        line=lineno,
                        evidence=line.strip()[:160],
                        remediation="改为下载固定版本的产物并校验哈希，再执行本地文件。",
                    )
                )
    return findings


def _scan_docker(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    for info in ctx.scoped_files():
        if not info.path.name.lower().startswith("dockerfile"):
            continue
        for lineno, line in enumerate(info.lines, start=1):
            match = DOCKER_FROM.match(line)
            if not match:
                continue
            image = match.group(1)
            if "@sha256:" in image:
                continue
            tag = image.rsplit(":", 1)[1] if ":" in image.rsplit("/", 1)[-1] else ""
            if tag in ("", "latest"):
                findings.append(
                    make_finding(
                        "SCP-009",
                        "supply",
                        "low",
                        "基础镜像未固定版本",
                        f"`FROM {image}` 会在每次构建时拉取不同内容，构建结果不可复现。",
                        path=info.rel,
                        line=lineno,
                        evidence=line.strip(),
                        remediation="固定到具体版本或 digest（image@sha256:...）。",
                    )
                )
    return findings


def _scan_git_deps(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    for package in ctx.deps.packages:
        locator = package.locator or ""
        if not locator:
            continue
        if locator.startswith(("url:git+", "url:http", "url:file", "file:")):
            findings.append(
                make_finding(
                    "SCP-010",
                    "supply",
                    "low",
                    f"{package.name} 来自 Git / 本地路径依赖",
                    "这类依赖不受注册表校验，也无法用漏洞数据库查询版本。",
                    path=package.manifest.split(";")[0] if package.manifest else "",
                    evidence=locator[:120],
                    remediation="固定到具体 commit，并记录为什么必须走源码依赖。",
                )
            )
    return findings


def _scan_npm_scripts(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    for info in ctx.files:
        if info.path.name != "package.json" or info.rel.count("/") > 0:
            continue
        try:
            payload = json.loads(info.text())
        except json.JSONDecodeError:
            continue
        scripts = payload.get("scripts") or {}
        for name in ("postinstall", "preinstall", "prepare"):
            if name in scripts:
                findings.append(
                    make_finding(
                        "SCP-011",
                        "supply",
                        "info",
                        f"package.json 定义了 {name} 脚本",
                        "安装时自动执行的脚本是 npm 供应链攻击的主要入口；如果这不是你写的，需要特别小心。",
                        path=info.rel,
                        evidence=f'"{name}": "{str(scripts[name])[:120]}"',
                        remediation="确认脚本来源可信；对第三方包可用 `npm ci --ignore-scripts`。",
                    )
                )
    return findings


def _scan_workflow_risk(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    for info in ctx.scoped_files():
        if not info.rel.startswith(".github/workflows/") or not info.rel.endswith((".yml", ".yaml")):
            continue
        text = info.text()
        target = PR_TARGET.search(text)
        head = PR_HEAD_REF.search(text)
        if target and head:
            findings.append(
                make_finding(
                    "SCP-012",
                    "supply",
                    "high",
                    "pull_request_target 里检出了 PR 代码",
                    "`pull_request_target` 在默认分支上下文运行，能拿到仓库 secrets；"
                    "再用它 checkout PR 的 head 代码，等于让外部贡献者的代码带着你的写入权限执行。"
                    "这是 GitHub Actions 上最典型的 pwn request 攻击面。",
                    path=info.rel,
                    line=text[: head.start()].count("\n") + 1,
                    evidence=head.group(0),
                    remediation=(
                        "改用 `pull_request` 触发；确实需要 write 权限时，把检出与执行拆到无 secrets 的 job，"
                        "并对 PR 代码只做只读校验。"
                    ),
                    reference="https://securitylab.github.com/research/github-actions-preventing-pwn-requests/",
                )
            )
        write_all = WRITE_ALL.search(text)
        if write_all:
            findings.append(
                make_finding(
                    "SCP-013",
                    "supply",
                    "medium",
                    "工作流授予了 write-all 权限",
                    "`permissions: write-all` 把 GITHUB_TOKEN 的全部写权限交给该工作流，"
                    "任何一个被污染的动作（含第三方 Action 被投毒）都能改代码、发 Release、推镜像。",
                    path=info.rel,
                    line=text[: write_all.start()].count("\n") + 1,
                    evidence="permissions: write-all",
                    remediation=(
                        "按最小权限显式声明，例如 `permissions:\\n  contents: read`，"
                        "只在确实需要写入的 job 上单独放开。"
                    ),
                )
            )
    return findings


def _vendored_findings(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    items, truncated = vendored.detect(ctx.root, ctx.config)
    record = find_root_file(ctx.root, vendored.DEFAULT_NAME)
    if items and not record:
        findings.append(
            make_finding(
                "SCP-014",
                "supply",
                "medium",
                f"{len(items)} 个 vendored 目录没有来源记录",
                "拷贝进来的第三方代码没有上游地址与版本，既无法回溯漏洞，也无法证明许可证来源。",
                path=items[0].path,
                remediation="运行 `provemark vendored` 生成 VENDORED.md，补齐上游与 Commit。",
                detail={"count": len(items), "paths": [item.path for item in items[:20]]},
            )
        )
    elif record and items:
        try:
            text = (ctx.root / record).read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        missing = vendored.missing_entries(text, items)
        pending = vendored.pending_count(text)
        if missing:
            findings.append(
                make_finding(
                    "SCP-015",
                    "supply",
                    "low",
                    f"VENDORED.md 未覆盖 {len(missing)} 个 vendored 目录",
                    f"来源记录漏了：{'、'.join(item.path for item in missing[:5])}"
                    + ("…" if len(missing) > 5 else ""),
                    path=record,
                    remediation="重新生成：`provemark vendored --force`。",
                    detail={"count": len(missing), "missing": [item.path for item in missing[:20]]},
                )
            )
        elif pending:
            findings.append(
                make_finding(
                    "SCP-015",
                    "supply",
                    "low",
                    f"VENDORED.md 还有 {pending} 处待补齐",
                    "上游地址或版本仍未填写，来源记录目前不能用于审计。",
                    path=record,
                    remediation="补齐上游 URL 与 Commit/Tag；补完再提交。",
                    detail={"pending": pending},
                )
            )
    if truncated:
        ctx.note("vendored 目录数量超过上限，来源记录只覆盖前 200 个")
    return findings


def scan(ctx: Context) -> list[Finding]:
    findings: list[Finding] = []
    findings.extend(_vendored_findings(ctx))
    findings.extend(_scan_typosquat(ctx))
    findings.extend(_scan_versions(ctx))
    findings.extend(_scan_lockfiles(ctx))
    findings.extend(_scan_indexes(ctx))
    findings.extend(_scan_workflows(ctx))
    findings.extend(_scan_workflow_risk(ctx))
    findings.extend(_scan_scripts(ctx))
    findings.extend(_scan_docker(ctx))
    findings.extend(_scan_git_deps(ctx))
    findings.extend(_scan_npm_scripts(ctx))
    return findings
