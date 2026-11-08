---
name: provemark
description: "本地零依赖的仓库原创性、风险与维护守卫（Provemark / 源印）。一次扫描看清任意技术栈仓库：许可证组合冲突、依赖漏洞、凭据泄漏、敏感数据（PII）、代码级安全漏洞（OWASP：SQL/命令/模板注入、路径穿越、SSRF、反序列化、XSS、弱哈希/随机/加密、TLS/JWT 校验关闭、XXE、C 溢出、Actions 注入、容器提权，带 CWE 映射）、AI 代码风险、供应链与仓库卫生，并给出逐条修法、可交给编码代理的修复指令、HTML/Markdown/SARIF 报告与 CI 门禁；维护老项目时用基线与趋势防止 AI 越改越糟（新增问题即阻断）。当用户要求扫描/体检某个仓库、问“这个仓库有什么风险/合规问题/能不能发布”、要做提交前门禁、排查泄漏的密钥或隐私数据、核对 license 与 SBOM（FOSSA/CycloneDX/SPDX）、生成 THIRD_PARTY_NOTICES / AI_USAGE / VENDORED 声明、或要证明“这个项目是不是自己的”时使用；also use for repository audit, security/code vulnerability scan, license compliance, secret leak, PII, supply chain and provenance checks on a local repo."
license: Apache-2.0
metadata:
  version: "0.7.1"
  author: Provemark Contributors
  requires: python>=3.11 or a DSH runtime (auto-detected)
---

# Provemark（源印）

Provemark 是**在提交之前**跑在本地的一次性体检：118 条规则、8 个维度、19 个生态。它把每条问题翻译成「为什么是问题 / 改哪里 / 怎么改」，并且**不猜测**——拿不到许可证就写未知，离线就标注数据不完整。

扫描器源码随本插件一起分发（`<PM>/python/provemark`），不需要 `pip install`，不联网也能跑，不会把代码上传到任何地方。

## 0. 先定位插件根目录 `<PM>`

下文所有命令里的 `<PM>` 都是本插件包（`provemark-dsh`）的根目录；**本技能的参考文档位于 `<PM>/skills/provemark/references/`**（`SKILL.md` 正文里写的参考文档路径都相对于技能目录）。它形如 `<skill 目录>/../..`，也可以用下面任一条命令确认：

```pwsh
(Get-ChildItem "$env:USERPROFILE\.dsh\profiles\*\node_modules\provemark-dsh\package.json" -ErrorAction SilentlyContinue | Select-Object -First 1).DirectoryName
```

```bash
ls -d ~/.dsh/profiles/*/node_modules/provemark-dsh 2>/dev/null | head -1
```

拿到后先跑一次自检，确认能用的 Python 与扫描器副本（输出 JSON，不扫描）：

```pwsh
node "<PM>\bin\provemark.mjs" --pm-info
```

`--pm-info` 里 `python` 为 `null` 就说明这台机器没有 Python 3.11+，不要继续扫，按 §7 处理。

**统一调用方式**（后续示例都省略 `node …`）：

```pwsh
node "<PM>\bin\provemark.mjs" <子命令> [参数]
```

没有 Node 时可用等价形式（PowerShell）：`$env:PYTHONPATH="<PM>\python"; python -P -B -m provemark <子命令> [参数]`

> 示例按 Windows/PowerShell 写。macOS/Linux 上把 `<PM>` 换成 `~/.dsh/profiles/<profile>/node_modules/provemark-dsh`、`"$env:TEMP\provemark"` 换成 `/tmp/provemark`、`New-Item -ItemType Directory -Force X` 换成 `mkdir -p X`。

## 1. 默认动作：扫描

**优先用原生工具**（插件已注册，常驻可用，不需要 shell）：

- `provemark_guard` —— 快速、**默认联网**（OSV 漏洞 + deps.dev 许可证）、带缓存。返回 `verdict`（`clean`/`warn`/`blocking`/`error`）、分数等级、各严重度计数、Top N 条（含 `文件:行`、修法、fingerprint）、以及 `autoFixable`（缺 LICENSE/.gitignore/SECURITY.md/CI 这类可安全补齐的项）。参数：`path`、`only`、`autoFix`（`off|preview|apply`）、`offline`（传 `true` 才跳过网络）、`maxFindings`、`fresh`。
- `provemark_scan` —— 完整形态：出报告（`html`/`markdown`/`sarif`/`json`）、只跑某个维度、`--sbom` 对齐、`--fail-on` 门禁对齐、`--ai-prompt` 生成修复指令。参数：`path`、`format`、`output`、`only`、`skip`、`offline`、`failOn`、`aiPrompt`、`sbom`、`verbose`。
- `provemark_progress` —— 读本地扫描历史：单项目的分数时间线、已修复/仍打开/复发，或 `all: true` 跨项目汇总；`action: "dashboard"` 在工作区内生成单文件 HTML 仪表盘（图表内联、不联网）。参数：`action`（`summary`|`dashboard`）、`path`、`all`、`days`、`output`。**判断"这个项目是变好还是变差"用它**，不要靠记忆里的旧分数。

两个扫描工具都可省略 `path`（默认会话工作目录）。**不要**为了"先看看"就去跑 shell 命令——工具是同一套扫描器，输出更适合你读。插件还会在后台自动扫描（改动后 / 新会话首步），结果以「Provemark 守卫状态」的上下文块出现在你面前；那是**缓存**结果，交付前仍要以一次显式 `provemark_guard` 为准。

**进度账本**：每次**完整**扫描自动写入 `~/.cache/provemark/history.jsonl`（分数、级别计数、文件/依赖数、问题指纹与相对路径；无源码、无证据文本）。`--only` / `--skip` / `--staged` 这类局部扫描**不**入账。历史库有上界（单项目 400 条 / 总计 5000 条 / 400 天），可以用 `PROVEMARK_HISTORY_FILE` 换位置。交付前如果用户问过"现在比之前好还是差"，用 `provemark_progress` 回答，别猜。

没有原生工具时（老版本宿主、工具被禁用）用命令行：

```pwsh
# 人看的摘要（默认 table，写 stdout）
node "<PM>\bin\provemark.mjs" scan <repo>

# 机器读的（推荐：先落盘再挑重点读，不要整段回贴）
New-Item -ItemType Directory -Force "$env:TEMP\provemark" | Out-Null   # -o 不会自动建目录
node "<PM>\bin\provemark.mjs" scan <repo> -f json -o "$env:TEMP\provemark\last.json"

# 进度：单项目 / 跨项目 / HTML 仪表盘
node "<PM>\bin\provemark.mjs" progress <repo>
node "<PM>\bin\provemark.mjs" progress --all
node "<PM>\bin\provemark.mjs" dashboard <repo> -o progress.html
```

- `<repo>` 省略时为当前目录；支持多栈 monorepo（结果自动合并）。
- 默认联网查漏洞与依赖许可证（只发包名+版本）。用户要求快、要隐私、或网络不通时加 `--offline`（此时漏洞与许可证标为未验证，评分会标「仅供参考」）。
- 只关心一类问题时用 `--only` / `--skip`，可选值：`repo, secrets, pii, security, ai, dependency, license, supply, fossa`。例：`--only pii`、`--skip pii,license`。
- 第一次进一个陌生仓库，先跑默认扫描；不要一上来就 `--verbose`（会刷屏）。

## 2. 输出协议（必须遵守）

1. **先落盘再摘要**：`-f json -o <路径>`（父目录必须先存在），然后只读需要的字段。
2. 回复用户时给：分数/等级、数据是否可信、各维度条数、**Top 3–5 条**（`严重度 + 规则ID + 一句话 + 文件:行 + 一句修法`）。
3. 不要把整份 JSON、整段终端报告粘给用户；不要堆 26 条清单，让用户自己翻。需要全集时告诉他报告写到哪。
4. `evidence` 字段是**已掩码**的片段（`sk-p****yHf6`、`******67D`）。不要试图还原、不要拼接上下文猜原文、不要把它写进任何提交或 issue。
5. 终端报告走 stdout（`table` 格式），`-o` 时的那行摘要走 stderr；**`--quiet` 在没有 `-o` 时什么都不打印**——想要一行结论请用 `scan <repo> -f json -o <file>` 再读 `score`。
6. 退出码就是结论：`0` 通过；`1` 命中门禁（`--fail-on`，默认 `high`，且 `confidence ≥ 0.5`）；`2` 用法/运行错误。**不要**在退出码 1 时说“扫描通过”。

## 3. 怎么读结果

`-f json` 的顶层：`tool, version, root, scanned_at, score, stats, counts, findings, suppressed, packages`。

| 字段 | 含义 | 用法 |
| --- | --- | --- |
| `score.total` / `score.grade` | 0–100 与 A/B/C/D/F | 对外只报这两个 + 一句话趋势 |
| `score.reliable` | `false` = 数据不完整（离线或过半依赖版本未知） | 为 false 时必须说「分数仅供参考」，不能说「没有漏洞」 |
| `score.by_category` / `counts.by_category` | 8 个维度的分数与条数 | 指出最差的一两个维度即可 |
| `counts.by_severity` | critical/high/medium/low/info | 先讲 critical 与 high |
| `findings[]` | 逐条问题 | 见下 |
| `suppressed[]` | 被 `.provemark.toml` 豁免、或低置信度未参与门禁的条目 | 有 `IGN-001` 说明豁免已过期，要提醒 |
| `stats.packages_unverified` | 未查到漏洞数据的依赖数 | >0 时说明覆盖面缺口 |
| `stats.notes[]` | 本次降级/局限说明 | 原文照搬给用户（例如「离线模式」） |

单条 `finding`：`rule_id, category, severity, title, message, path, line, column, evidence, remediation, reference, source, confidence, fingerprint, detail`。

- **`confidence` 不是严重度**：`0.4–0.65` 的多是启发式判断（高熵疑似密钥、测试目录命中），报告里标「需人工确认」。低于 `0.6` 不要替用户下结论。
- **`fingerprint`** 是豁免用的稳定指纹；`ignore` 时用它，不要用行号。
- `source` 为 `local` / `osv` / `deps.dev` / `registry`；`local` 的结论不依赖网络。

评分：`扣分 = 权重 × (1 + 0.7·log2(有效次数))`，权重 critical 35 / high 8 / medium 2 / low 0.8 / info 0.1；有效次数按 confidence 加权；critical 不设上限，其余单维度封顶 25；`100 - Σ扣分`，A≥90 / B≥80 / C≥70 / D≥60 / F<60。

## 4. 下一步分诊

| 情况 | 动作 |
| --- | --- |
| 用户问某条规则为什么报 / 怎么算 | `explain <RULE-ID>`，把「为什么是问题 + 怎么修」翻成他的话 |
| 想知道全部规则或被反复追问 | `rules`、`rules --category <维度>` |
| 代码级安全问题（`VUL-*`：注入 / 反序列化 / SSRF / TLS / JWT / XXE / 弱加密…） | 先看 `detail.cwe` 与 `detail.owasp` 分类，再按 `references/security-playbook.md` 的修法逐类处理；只看这一面用 `--only security`。**不要**把"框架内部 eval"和"用户输入进 SQL"混为一类 |
| 想修**不需要判断**的问题（缺 LICENSE / .gitignore / SECURITY.md / CI） | 先 `fix <repo>`（默认只预览），确认后 `fix <repo> --apply`；已存在文件不会被覆盖，除非 `--force` |
| 需要改**业务代码**的问题（幻觉依赖、`except: pass`、硬编码密钥） | 生成修复指令：`scan <repo> --ai-prompt fix.md --test-command "<验证命令>"`，把 fix.md 交给编码代理；**不要自己直接改**，除非用户明确要求 |
| 历史问题暂时接受 | `ignore <fingerprint> --reason "…" --expires YYYY-MM-DD`（原因和到期日必填；critical 不允许豁免）。不要用 ignore「消灭」问题 |
| 要给人看 / 存档 | `-f html -o report.html`（单文件离线可开）、`-f markdown`（贴 PR）、`-f sarif`（GitHub Code Scanning） |
| 想和 FOSSA / SBOM 对齐 | `scan <repo> --sbom sbom.json`，看 `FOS-006/007/008` |
| 要给 FOSSA 补盲区 | `fossa-deps <repo>`（默认只补 vendored；`--print` 预览） |
| 发布前要第三方归因 | `notices <repo>`（生成 THIRD_PARTY_NOTICES.md；已有手写文件会改写 `*.provemark.md`） |
| 要申报 AI 使用 | `ai-usage <repo>`（识别 CLAUDE.md / .cursorrules 等痕迹，未填字段留「待填写」） |
| vendored 代码要来源记录 | `vendored <repo>` |
| 要建立门禁 | `init <repo> --apply` 生成 `.provemark.toml` + CI；`hook install` 装 pre-commit（只扫暂存区） |

## 5. 常用配方

**A. 提交前拦一下**
```pwsh
node "<PM>\bin\provemark.mjs" scan . --staged --fail-on high --min-confidence 0.5 -f sarif -o provemark.sarif
```

**B. 修一轮，再确认分数**
```pwsh
node "<PM>\bin\provemark.mjs" scan . --ai-prompt fix.md --test-command "pytest -q"
# 代理按 fix.md 改完后重新扫描，对比 score.total 与「新增问题=0」
node "<PM>\bin\provemark.mjs" scan . -f json -o "$env:TEMP\provemark\after.json"
```

**C. 只要隐私面（PII 合规复查）**
```pwsh
node "<PM>\bin\provemark.mjs" scan . --only pii -f json -o "$env:TEMP\provemark\pii.json"
```
辖区在 `.pdp-compliance.json` 的 `personalDataProtection.jurisdictions` 里声明（`sg-pdpa/th-pdpa/id-pdp/my-pdpa/ph-dpa`）；未声明时只做通用格式识别，报告会明说「未按辖区校验」。

**D. 许可证收口**
```pwsh
node "<PM>\bin\provemark.mjs" scan . --only license
node "<PM>\bin\provemark.mjs" explain LIC-009
```
`LIC-009` 是「组合冲突」（如 GPL-2.0-only 项目引入 Apache-2.0，或 Apache-2.0 项目引入 GPL）；`LIC-004` 是策略禁止；`LIC-005` 是拿不到许可证。三者含义不同，别混着说。

**E. 发布前归因三件套**
```pwsh
node "<PM>\bin\provemark.mjs" notices .
node "<PM>\bin\provemark.mjs" ai-usage .
node "<PM>\bin\provemark.mjs" vendored .
```
脚本加 `--print` 可先看内容不落盘；手写文件不会被覆盖（会写 `*.provemark.md`）。

**F. 只要结论、不要流程**
```pwsh
node "<PM>\bin\provemark.mjs" scan . -f markdown -o "$env:TEMP\provemark\report.md"
```
读 markdown 的「需要优先处理」段，原文转述即可。

## 6. 红线

- **不擅自写文件**：`fix --apply`、`init --apply`、`hook install`、`notices`、`ai-usage`、`vendored`、`fossa-deps` 都会落盘。用户没明确同意时，一律先不带 `--apply` / 加 `--print` 预览。
- **不擅自改业务代码**：代码层修法只产出 `--ai-prompt` 指令，由用户或编码代理执行。
- **不用 ignore 掩盖问题**：豁免必须写真实原因和到期日；critical（真实密钥、已提交的 `.env`、恶意包名）不允许被豁免。
- **不上传、不外发**：默认只发送包名与版本；不要为了“让它更准”而建议关掉隐私边界或上传源码。
- **不把掩码片段当原文**：PII/凭据只保存掩码与位置；不要日志式回放，也不要写进提交信息。
- **不把工程判断说成法律意见**：许可证兼容性是工程判断，报告页脚也这么写。
- **扫描失败不要伪造结论**：退出码 2 / `stats.notes` 里有降级说明时，如实告诉用户覆盖面不够。

## 7. 故障处理（速查）

| 现象 | 处理 |
| --- | --- |
| `--pm-info` 里 `python: null` | 装 Python 3.11+，或设 `PROVEMARK_PYTHON=<解释器路径>`；DSH 自带运行时会被自动发现 |
| `写入失败：… No such file or directory` | `-o` 不会建父目录，先 `New-Item -ItemType Directory -Force <目录>` |
| 扫描很慢 | 加 `--offline`（跳过 OSV / deps.dev），或用 `--only` 缩小范围 |
| 中文乱码 | 插件已设 `PYTHONUTF8=1`；直接 `python -m provemark` 时请自行设置，或加 `--no-color` |
| 结果里一堆 `confidence < 0.6` | 属启发式命中，标注「需人工确认」，不要当结论 |
| Windows 路径含空格/中文 | 一律给路径加引号；`<PM>` 用完整绝对路径 |

更多细节见 `references/troubleshooting.md`。

## 8. 参考文件（按问题找手册）

| 文件 | 什么时候读 |
| --- | --- |
| `references/tools.md` | 要确认 `provemark_guard` / `provemark_scan` 的参数、返回值、自动扫描与配置项 |
| `references/cli.md` | 需要确认某个子命令/参数的准确语义、退出码、输出格式 |
| `references/rules.md` | 要按维度解释规则、判断某条该不该报、给修法话术 |
| `references/json-output.md` | 要写脚本消费 `-f json`、或需要字段级含义 |
| `references/policy.md` | 要改 `.provemark.toml`（门禁阈值、deny 列表、ignore、exceptions）、写 PII 辖区文件 |
| `references/workflows.md` | 要端到端跑一条流程（首次接入 / 提交前 / AI 修复循环 / 发布归因 / FOSSA 对齐） |
| `references/troubleshooting.md` | 命令报错、结果可疑、跨平台差异 |

### 领域手册（知识层）

| 文件 | 什么时候读 |
| --- | --- |
| `references/maintenance-discipline.md` | 维护老项目 / 大仓库：分批修、基线与趋势、反模式清单 |
| `references/security-playbook.md` | 判 `VUL-*` 严重性、按 CWE/OWASP 分类整改、写修法 |
| `references/fullstack-playbook.md` | 全栈工程：前端/后端/API/数据库/并发/可观测性/测试（`AI-015~020`） |
| `references/algorithms-playbook.md` | 算法与复杂度：规模判据、结构选型、精度陷阱、验证方法（`AI-021~026`） |
| `references/architecture-playbook.md` | 架构：边界与依赖、数据归属、一致性、缓存、伸缩、ADR |
| `references/testing-playbook.md` | 测试：分层策略、该测/不该测、替身、flaky、性质测试、CI |
| `references/data-playbook.md` | 数据：schema/索引/事务/迁移/备份/容量 |
| `references/delivery-playbook.md` | 交付：提交/PR、CI、发布策略、回滚、可观测性门禁、依赖更新 |
| `references/debugging-playbook.md` | 调试：复现→二分→观察→假设，故障签名表，事故复盘 |
| `references/code-review-playbook.md` | 评审：顺序、diff 卫生、AI 代码重点、评论方式、合并清单 |
| `references/ai-collaboration.md` | 与模型协作：任务/上下文怎么给、验证闭环、幻觉形态、提示词模式 |
