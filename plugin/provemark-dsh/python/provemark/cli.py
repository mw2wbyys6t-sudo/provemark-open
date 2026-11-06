from __future__ import annotations

import argparse
import datetime as dt
import os
import sys
from pathlib import Path

from . import __version__, ai_usage, fossa_deps, notices, vendored
from .config import DEFAULT_CONFIG_TEMPLATE, ConfigError, find_config_file, load_config
from .engine import gate_failed, run_scan
from .fixers import FIX_TARGETS, apply_action, install_hook, plan, uninstall_hook
from .report import FORMATS, ai_fix_prompt, dump, format_for_output, render
from .report.console import use_color
from .rules.catalog import catalog

SCANNERS = ("repo", "secrets", "pii", "security", "ai", "dependency", "license", "supply", "fossa")
SEVERITY_CHOICES = ("none", "low", "medium", "high", "critical")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="provemark",
        description="源印：本地扫描仓库的原创性与风险——许可证冲突、依赖漏洞、凭据泄漏、敏感数据、AI 代码风险与供应链问题。",
    )
    parser.add_argument("--version", action="version", version=f"provemark {__version__}")
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="扫描仓库")
    scan.add_argument("path", nargs="?", default=".", help="仓库路径（默认当前目录）")
    scan.add_argument("-f", "--format", default="auto", choices=(*FORMATS, "auto"), help="输出格式")
    scan.add_argument("-o", "--output", help="写入文件；不给则打印到终端")
    scan.add_argument("--fail-on", choices=SEVERITY_CHOICES, help="出现该级别及以上问题时返回退出码 1")
    scan.add_argument(
        "--min-confidence",
        type=float,
        default=None,
        dest="min_confidence",
        metavar="0-1",
        help="低于该置信度的问题不参与门禁（默认为策略文件里的值）",
    )
    scan.add_argument("--offline", action="store_true", help="不访问网络（跳过漏洞与依赖许可证查询）")
    scan.add_argument("--staged", action="store_true", help="只扫描 Git 暂存区（用于 pre-commit）")
    scan.add_argument("--only", help="只运行指定扫描器，逗号分隔")
    scan.add_argument("--skip", help="跳过指定扫描器，逗号分隔")
    scan.add_argument("-v", "--verbose", action="store_true", help="终端输出显示全部问题")
    scan.add_argument("--quiet", action="store_true", help="只输出一行摘要")
    scan.add_argument("--no-color", action="store_true", help="关闭颜色")
    scan.add_argument("--config", help="指定策略文件")
    scan.add_argument("--ai-prompt", metavar="FILE", help="生成可交给 AI 代理的修复指令文件")
    scan.add_argument("--test-command", default="", help="写入修复指令的验证命令，如 pytest -q")
    scan.add_argument(
        "--sbom",
        metavar="FILE",
        help="读取 FOSSA / CycloneDX / SPDX 的 JSON SBOM，与本地许可证结论交叉核对",
    )

    init = sub.add_parser("init", help="初始化策略文件与 CI（只创建缺失文件）")
    init.add_argument("path", nargs="?", default=".")
    init.add_argument("--license", default="", help="项目许可证 SPDX 标识（默认 Apache-2.0）")
    init.add_argument("--author", default="", help="版权所有者（默认取 git user.name）")
    init.add_argument("--no-ci", action="store_true", help="不生成 GitHub Actions 工作流")
    init.add_argument("--apply", action="store_true", help="实际写入（默认只预览）")

    fix = sub.add_parser("fix", help="修复不需要判断的问题（默认只预览）")
    fix.add_argument("path", nargs="?", default=".")
    fix.add_argument("--apply", action="store_true", help="实际写入文件")
    fix.add_argument("--force", action="store_true", help="允许覆盖已存在文件")
    fix.add_argument("--license", default="", help="生成 LICENSE 时使用的 SPDX 标识")
    fix.add_argument("--author", default="", help="版权所有者")
    fix.add_argument("--only", help="只处理指定项，逗号分隔（license/gitignore/security/config/ci）")

    ignore = sub.add_parser("ignore", help="登记豁免（必须写原因与到期时间）")
    ignore.add_argument("fingerprint", nargs="?", default="", help="问题指纹（报告里可复制）")
    ignore.add_argument("--rule", default="", help="按规则 ID 豁免，如 SCP-007")
    ignore.add_argument("--path", default="", help="按路径 glob 豁免，如 tools/**")
    ignore.add_argument("--reason", required=True, help="为什么要接受这个风险")
    ignore.add_argument("--expires", default="", help="到期日期 YYYY-MM-DD（默认 90 天后）")
    ignore.add_argument("--config", default="", help="写入哪个策略文件")
    ignore.add_argument("--root", default=".", help="仓库路径（默认当前目录）")

    explain = sub.add_parser("explain", help="解释一条规则的判定逻辑")
    explain.add_argument("rule_id")

    rules = sub.add_parser("rules", help="列出全部规则")
    rules.add_argument("--category", help="按维度过滤")

    hook = sub.add_parser("hook", help="安装 / 移除 pre-commit 钩子")
    hook.add_argument("action", choices=("install", "uninstall"))
    hook.add_argument("path", nargs="?", default=".")
    hook.add_argument("--force", action="store_true")

    deps_export = sub.add_parser(
        "fossa-deps",
        help="生成 fossa-deps.yml，补齐 FOSSA 自己扫不到的依赖",
    )
    deps_export.add_argument("path", nargs="?", default=".", help="仓库路径（默认当前目录）")
    deps_export.add_argument(
        "-o",
        "--output",
        help="输出路径（默认 <repo>/fossa-deps.yml；已有手写文件时自动改名）",
    )
    deps_export.add_argument(
        "--mode",
        choices=("missing", "all"),
        default="missing",
        help="missing：只补 FOSSA 扫不到的部分（vendored 目录）；all：导出全部 FOSSA 支持的依赖",
    )
    deps_export.add_argument("--limit", type=int, default=fossa_deps.DEFAULT_LIMIT, help="all 模式最多导出条数")
    deps_export.add_argument("--force", action="store_true", help="允许覆盖已存在的手写文件")
    deps_export.add_argument("--print", dest="print_only", action="store_true", help="只打印内容，不写文件")

    notices = sub.add_parser(
        "notices",
        help="生成 THIRD_PARTY_NOTICES.md（第三方组件归因）",
    )
    notices.add_argument("path", nargs="?", default=".", help="仓库路径（默认当前目录）")
    notices.add_argument(
        "-o",
        "--output",
        help="输出路径（默认 <repo>/THIRD_PARTY_NOTICES.md；已有手写文件时自动改名）",
    )
    notices.add_argument("--force", action="store_true", help="允许覆盖已存在的手写文件")
    notices.add_argument("--offline", action="store_true", help="不访问网络，只用缓存里的许可证")
    notices.add_argument("--print", dest="print_only", action="store_true", help="只打印内容，不写文件")

    ai_usage_cmd = sub.add_parser(
        "ai-usage",
        help="生成 AI_USAGE.md（AI 使用声明）",
    )
    ai_usage_cmd.add_argument("path", nargs="?", default=".", help="仓库路径（默认当前目录）")
    ai_usage_cmd.add_argument("-o", "--output", help="输出路径（默认 <repo>/AI_USAGE.md）")
    ai_usage_cmd.add_argument("--force", action="store_true", help="允许覆盖已存在的手写文件")
    ai_usage_cmd.add_argument("--print", dest="print_only", action="store_true", help="只打印内容，不写文件")

    vendored_cmd = sub.add_parser(
        "vendored",
        help="生成 VENDORED.md（vendored 代码来源记录）",
    )
    vendored_cmd.add_argument("path", nargs="?", default=".", help="仓库路径（默认当前目录）")
    vendored_cmd.add_argument("-o", "--output", help="输出路径（默认 <repo>/VENDORED.md）")
    vendored_cmd.add_argument("--force", action="store_true", help="允许覆盖已存在的手写文件")
    vendored_cmd.add_argument("--print", dest="print_only", action="store_true", help="只打印内容，不写文件")

    return parser


def _split(value: str | None) -> list[str] | None:
    if not value:
        return None
    return [item.strip() for item in value.split(",") if item.strip()]


def _warn_legacy_config(config) -> None:
    path = getattr(config, "config_path", None)
    if path is not None and "reposentinel" in path.name:
        print(
            f"提示：检测到旧配置文件 {path.name}，建议改名为 .provemark.toml"
            "（旧名仍可读，但不会再被写入）",
            file=sys.stderr,
        )


def _load(path: Path, config_path: str | None):
    explicit = Path(config_path).expanduser() if config_path else None
    config = load_config(path, explicit)
    _warn_legacy_config(config)
    return config


def cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.path).expanduser()
    if not root.exists():
        print(f"路径不存在：{root}", file=sys.stderr)
        return 2
    root = root.resolve()
    unsafe = _reject_unsafe_root(root)
    if unsafe is not None:
        return unsafe
    try:
        config = _load(root, args.config)
    except ConfigError as exc:
        print(f"配置错误：{exc}", file=sys.stderr)
        return 2

    only = _split(args.only)
    skip = _split(args.skip)
    for name in (only or []) + (skip or []):
        if name not in SCANNERS:
            print(f"未知扫描器：{name}（可选：{', '.join(SCANNERS)}）", file=sys.stderr)
            return 2

    if args.sbom:
        sbom_path = Path(args.sbom).expanduser()
        if not sbom_path.is_file():
            print(f"SBOM 文件不存在：{sbom_path}", file=sys.stderr)
            print("提示：用 `fossa report attribution --format cyclonedx-json -o sbom.json` 导出后重试。", file=sys.stderr)
            return 2
        args.sbom = str(sbom_path)

    fail_on = args.fail_on or config.fail_on
    min_confidence = config.min_confidence
    if args.min_confidence is not None:
        if not 0 <= args.min_confidence <= 1:
            print("--min-confidence 必须在 0 到 1 之间", file=sys.stderr)
            return 2
        min_confidence = args.min_confidence
    try:
        result = run_scan(
            root,
            config,
            offline=args.offline,
            staged_only=args.staged,
            only=only,
            skip=skip,
            sbom=args.sbom,
        )
    except (RuntimeError, FileNotFoundError) as exc:
        print(f"扫描失败：{exc}", file=sys.stderr)
        return 2

    fmt = format_for_output(args.output or "", args.format)
    try:
        if args.output:
            if fmt == "table":
                from .report import console

                with open(args.output, "w", encoding="utf-8") as handle:
                    handle.write(console.render(result, verbose=args.verbose, color=False))
            else:
                dump(result, fmt, args.output)
            if not args.quiet:
                print(_summary_line(result), file=sys.stderr)
                print(f"报告已写入 {args.output}", file=sys.stderr)
        elif not args.quiet:
            if fmt == "table":
                from .report import console

                color = False if args.no_color else None
                sys.stdout.write(console.render(result, verbose=args.verbose, color=color))
            else:
                content = render(result, fmt, verbose=args.verbose)
                sys.stdout.write(content if content.endswith("\n") else content + "\n")

        if args.ai_prompt:
            content = ai_fix_prompt(result, test_command=args.test_command)
            Path(args.ai_prompt).write_text(content, encoding="utf-8")
            if not args.quiet:
                print(f"AI 修复指令已写入 {args.ai_prompt}", file=sys.stderr)
    except OSError as exc:
        target = args.output or args.ai_prompt
        print(f"写入失败：{exc}", file=sys.stderr)
        print(f"请确认目标路径可写、父目录存在：{target}", file=sys.stderr)
        return 2

    return 1 if gate_failed(result, fail_on, min_confidence) else 0


def _summary_line(result) -> str:
    score = result.score
    counts = result.counts_by_severity()
    score_text = f"{score.total}/100 ({score.grade})" if score else "-"
    return (
        f"Provemark: {score_text} · 致命 {counts['critical']} · 高危 {counts['high']} "
        f"· 中危 {counts['medium']} · 低危 {counts['low']}"
    )


def _reject_unsafe_root(root: Path) -> int | None:
    """拒绝文件系统根与用户主目录。

    扫描 `C:\\` 或 `~` 会遍历无界目录树：既不是用户想做的事，也会让命令跑上
    几分钟甚至超时。插件侧的 resolveRoot 已经拒绝同样的根，CLI 要保持一致。
    """
    try:
        home = Path.home().resolve()
    except (RuntimeError, OSError):
        home = None
    if root.parent == root:
        print(f"拒绝扫描：{root} 是文件系统根；请指定具体项目目录。", file=sys.stderr)
        return 2
    if home is not None and root == home:
        print(f"拒绝扫描：{root} 是用户主目录；请指定具体项目目录。", file=sys.stderr)
        return 2
    return None


def cmd_init(args: argparse.Namespace) -> int:
    root = Path(args.path).expanduser().resolve()
    unsafe = _reject_unsafe_root(root)
    if unsafe is not None:
        return unsafe
    try:
        config = load_config(root)
    except ConfigError as exc:
        print(f"配置错误：{exc}", file=sys.stderr)
        return 2
    _warn_legacy_config(config)

    actions = plan(
        root,
        config,
        result=None,
        license_id=args.license,
        holder=args.author,
        include_ci=not args.no_ci,
    )
    if not actions:
        print("仓库结构已经完整，没有需要创建的文件。")
        return 0
    print("将要执行：")
    for action in actions:
        print(f"  + {action.summary()}")
    if not args.apply:
        print("\n这是预览。确认后加 --apply 实际写入。")
        return 0
    print("")
    for action in actions:
        print("  " + apply_action(root, action, force=False))
    print("\n下一步：provemark scan")
    return 0


def cmd_fix(args: argparse.Namespace) -> int:
    root = Path(args.path).expanduser().resolve()
    unsafe = _reject_unsafe_root(root)
    if unsafe is not None:
        return unsafe
    try:
        config = load_config(root)
    except ConfigError as exc:
        print(f"配置错误：{exc}", file=sys.stderr)
        return 2
    _warn_legacy_config(config)
    only = _split(args.only)
    for name in only or []:
        if name not in FIX_TARGETS:
            print(
                f"未知修复项：{name}（可选：{', '.join(FIX_TARGETS)}）",
                file=sys.stderr,
            )
            return 2
    actions = plan(
        root,
        config,
        result=None,  # type: ignore[arg-type]
        license_id=args.license,
        holder=args.author,
        include_ci=False,
        only=only,
    )
    if not actions:
        print("没有可自动修复的项。代码层面的问题请用 `provemark scan --ai-prompt fix.md` 交给 AI 代理。")
        return 0
    print("可自动修复：")
    for action in actions:
        print(f"  · {action.summary()}")
    if not args.apply:
        print("\n这是预览（不会改动任何文件）。确认后执行：provemark fix --apply")
        return 0
    print("")
    for action in actions:
        print("  " + apply_action(root, action, force=args.force))
    return 0


def cmd_ignore(args: argparse.Namespace) -> int:
    if not (args.fingerprint or args.rule or args.path):
        print("至少提供指纹、--rule 或 --path 之一", file=sys.stderr)
        return 2
    expires = args.expires or (dt.date.today() + dt.timedelta(days=90)).isoformat()
    try:
        expires_date = dt.date.fromisoformat(expires)
    except ValueError:
        print("--expires 需要 YYYY-MM-DD 格式", file=sys.stderr)
        return 2
    if expires_date <= dt.date.today():
        print("--expires 必须晚于今天", file=sys.stderr)
        return 2

    root = Path(args.root).expanduser().resolve()
    if not root.is_dir():
        print(f"仓库路径不存在：{root}", file=sys.stderr)
        return 2
    target = Path(args.config).expanduser() if args.config else find_config_file(root)
    if target is None:
        target = root / ".provemark.toml"
        target.write_text(DEFAULT_CONFIG_TEMPLATE, encoding="utf-8")
        print(f"已创建策略文件 {target}")

    from .config import IgnoreRule

    rule = IgnoreRule(
        fingerprint=args.fingerprint,
        rule=args.rule,
        path=args.path,
        reason=args.reason,
        expires=expires,
        created=dt.date.today().isoformat(),
    )
    with target.open("a", encoding="utf-8") as handle:
        handle.write("\n" + rule.to_toml())
    print(f"已登记豁免，到期日 {expires}：{args.reason}")
    print("提示：豁免到期后问题会自动重新计分。")
    return 0


def cmd_explain(args: argparse.Namespace) -> int:
    rule_id = args.rule_id.upper()
    entry = catalog().get(rule_id)
    if entry is None:
        print(f"没有找到规则 {rule_id}。可用 `provemark rules` 查看全部规则。", file=sys.stderr)
        return 2
    print(f"{rule_id}  {entry.get('title', '')}")
    print(f"维度：{entry.get('category', '')}    默认级别：{entry.get('severity', '')}")
    if entry.get("cwe"):
        print(f"标准：{entry.get('cwe')} / {entry.get('owasp', '')}")
    print(f"为什么是问题：{entry.get('message', '')}")
    print(f"怎么修：{entry.get('remediation', '')}")
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    entries = catalog()
    category = args.category
    rows = []
    for rule_id, entry in sorted(entries.items()):
        if category and entry.get("category") != category:
            continue
        rows.append(f"  {rule_id:<8} {entry.get('severity', ''):<9} {entry.get('title', '')}")
    if not rows:
        print("没有匹配的规则")
        return 0
    print(f"共 {len(rows)} 条规则：")
    print("\n".join(rows))
    return 0


def cmd_hook(args: argparse.Namespace) -> int:
    root = Path(args.path).expanduser().resolve()
    message = install_hook(root, force=args.force) if args.action == "install" else uninstall_hook(root)
    print(message)
    return 0 if "无法" not in message else 2


def _print_skipped(skipped: dict[str, int]) -> None:
    for reason, count in sorted(skipped.items(), key=lambda item: (-item[1], item[0])):
        print(f"  跳过 {count} 条：{reason}")


def cmd_fossa_deps(args: argparse.Namespace) -> int:
    root = Path(args.path).expanduser().resolve()
    if not root.is_dir():
        print(f"目录不存在：{root}", file=sys.stderr)
        return 2
    try:
        config = _load(root, None)
    except ConfigError as exc:
        print(f"配置错误：{exc}", file=sys.stderr)
        return 2

    declared = fossa_deps.load_declared(root)
    planned = fossa_deps.plan(
        root,
        config,
        mode=args.mode,
        limit=max(1, args.limit),
        declared=declared,
    )
    if planned.empty:
        print("不需要生成：没有 FOSSA 扫不到的依赖需要补充。")
        _print_skipped(planned.skipped)
        return 0

    if args.print_only:
        sys.stdout.write(fossa_deps.render(planned))
        return 0

    target = Path(args.output).expanduser() if args.output else root / "fossa-deps.yml"
    drops_referenced = False
    if target.is_file():
        try:
            previous = target.read_text(encoding="utf-8", errors="replace")
        except OSError:
            previous = ""
        drops_referenced = (
            fossa_deps.MARKER in previous
            and "referenced-dependencies:" in previous
            and not planned.referenced
        )
    written, redirected = fossa_deps.write(planned, target, force=args.force)
    print(f"已生成 {written}（mode={planned.mode}）")
    if planned.referenced:
        note = f"，其中 {planned.unpinned} 条未固定版本" if planned.unpinned else ""
        print(f"  引用依赖 {len(planned.referenced)} 条{note}")
    if planned.vendored:
        names = "、".join(name for name, _ in planned.vendored[:5])
        suffix = "…" if len(planned.vendored) > 5 else ""
        print(f"  vendored 目录 {len(planned.vendored)} 个：{names}{suffix}")
    _print_skipped(planned.skipped)
    if drops_referenced:
        print("\n注意：上次生成的 referenced-dependencies 已被移除（当前是 missing 模式）。")
        print("      需要保留全量声明请重跑：provemark fossa-deps --mode all")
    if redirected:
        print(f"\n仓库里已有手写的 {target.name}，本次写到 {written.name}，没有改动你的文件。")
        print(f"让 FOSSA 读它：fossa analyze --fossa-deps-file {written.name}")
    else:
        print("\n下一步：fossa analyze（会自动读取根目录的 fossa-deps.yml）")
    return 0


def cmd_notices(args: argparse.Namespace) -> int:
    root = Path(args.path).expanduser().resolve()
    if not root.is_dir():
        print(f"目录不存在：{root}", file=sys.stderr)
        return 2
    try:
        config = _load(root, None)
    except ConfigError as exc:
        print(f"配置错误：{exc}", file=sys.stderr)
        return 2

    context = notices.build_context(root, config, offline=args.offline)
    entries, unknown = notices.collect(context)
    if not entries:
        print("没有找到第三方依赖，无需生成归因文件。")
        return 0
    for note in context.notes:
        print(f"  注意：{note}")

    if args.print_only:
        sys.stdout.write(notices.render(entries, unknown))
        return 0

    target = Path(args.output).expanduser() if args.output else root / notices.DEFAULT_NAME
    written, redirected = notices.write(entries, unknown, target, force=args.force)
    print(f"已生成 {written}")
    print(f"  覆盖 {len(entries)} 个组件，其中 {unknown} 个许可证未知")
    if redirected:
        print(f"\n仓库里已有手写的 {target.name}，本次写到 {written.name}，没有改动你的文件。")
    if unknown:
        print("  许可证未知的组件需要人工补齐后再对外分发。")
    return 0


def cmd_ai_usage(args: argparse.Namespace) -> int:
    root = Path(args.path).expanduser().resolve()
    if not root.is_dir():
        print(f"目录不存在：{root}", file=sys.stderr)
        return 2
    artifacts = ai_usage.detect_artifacts(root)
    if args.print_only:
        sys.stdout.write(ai_usage.render(artifacts))
        return 0
    target = Path(args.output).expanduser() if args.output else root / ai_usage.DEFAULT_NAME
    written, redirected = ai_usage.write(target, artifacts, force=args.force)
    print(f"已生成 {written}")
    if artifacts:
        print(f"  检测到 AI 工具痕迹：{'、'.join(artifacts)}")
    else:
        print("  未检测到 AI 工具痕迹；如果确实用过，请手动补充工具与范围")
    if redirected:
        print(f"\n仓库里已有手写的 {target.name}，本次写到 {written.name}，没有改动你的文件。")
    print("  下一步：把「待填写」替换成实际情况，这份声明才能用于尽调。")
    return 0


def cmd_vendored(args: argparse.Namespace) -> int:
    root = Path(args.path).expanduser().resolve()
    if not root.is_dir():
        print(f"目录不存在：{root}", file=sys.stderr)
        return 2
    try:
        config = _load(root, None)
    except ConfigError as exc:
        print(f"配置错误：{exc}", file=sys.stderr)
        return 2
    entries, truncated = vendored.detect(root, config)
    if not entries:
        print("没有检测到 vendored 目录（vendor/、third_party/ 等且含 LICENSE）。")
        return 0
    if args.print_only:
        sys.stdout.write(vendored.render(entries, truncated))
        return 0
    target = Path(args.output).expanduser() if args.output else root / vendored.DEFAULT_NAME
    written, redirected = vendored.write(target, entries, truncated, force=args.force)
    print(f"已生成 {written}")
    print(f"  共 {len(entries)} 个 vendored 目录")
    if redirected:
        print(f"\n仓库里已有手写的 {target.name}，本次写到 {written.name}，没有改动你的文件。")
    print("  下一步：补齐上游地址与版本/Commit，否则无法证明来源。")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0
    handlers = {
        "scan": cmd_scan,
        "init": cmd_init,
        "fix": cmd_fix,
        "ignore": cmd_ignore,
        "explain": cmd_explain,
        "rules": cmd_rules,
        "hook": cmd_hook,
        "fossa-deps": cmd_fossa_deps,
        "notices": cmd_notices,
        "ai-usage": cmd_ai_usage,
        "vendored": cmd_vendored,
    }
    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        return 2
    if args.command == "scan" and not use_color():
        os.environ.setdefault("NO_COLOR", "1")
    return handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
