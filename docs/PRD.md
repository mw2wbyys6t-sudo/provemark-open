# Provemark（源印）产品需求文档

| 项目 | 内容 |
| --- | --- |
| 产品名 | Provemark / 源印 |
| 版本 | v0.4（原创性 + 敏感数据 + 全技术栈 + FOSSA 协同） |
| 形态 | 本地零依赖 CLI + 自包含 HTML 报告 |
| 目标用户 | 用 AI 辅助写代码的独立开发者、小团队仓库维护者 |
| 文档日期 | 2026-10-27 |

---

## 1. 背景与问题

**观察到的证据。** 用户仓库 `live2d-auto-pipeline` 的 GitHub 检查页显示：`Dependency Quality` 5 项质量问题、`License Compliance` 64 项、`Security Analysis` 4 个漏洞，三项检查全部失败（截图由用户提供）。

**受影响的用户与时刻。** 用户是独立开发者，主要工作方式是「让 AI 写代码 → 合并 → 发布」。托管平台的合规检查是**结果通知**：它出现在提交之后、发布之前，用英文条目列出问题，但：

1. 不告诉用户「这条为什么是问题、在我的项目语境里意味着什么」；
2. 不给「最小改动的修法」，也不给「可以直接喂给 AI 的修改指令」；
3. 需要账号与联网授权，在一个人的小仓库上属于额外负担；
4. 无法在 `git commit` 之前拦住问题。

**产品决策。** 做一个**本地优先、零第三方运行时依赖**的扫描器：在提交前就能跑，给出问题、原因、修法、以及一段可直接粘贴给 AI 编码代理的修复指令；把「合规」翻译成「今天该改哪几行」。

**期望的可观察结果。** 用户在一个仓库里执行一条命令，能在 1 分钟内看到：总分与等级、按严重度排序的问题清单、每条的定位与修法、一份可打开的 HTML 报告，并以退出码形式对 CI 表态。

---

## 2. 目标

| 目标 | 可观察的完成条件 |
| --- | --- |
| G1 一次命令看清全貌 | `provemark scan` 输出总分、等级、各维度计数，无需任何账号或配置 |
| G2 问题可定位可修复 | 每条问题包含文件、行号、证据（脱敏）、修复建议；`fix` 能安全落地不涉及语义的修复 |
| G3 许可证风险可判定 | 输出「项目声明许可证 + 依赖许可证 + 是否与项目策略冲突」，而不是只列许可证名 |
| G4 漏洞可判定 | 输出 CVE/GHSA 编号、受影响版本、修复版本，并区分「无法确定版本」与「无漏洞」 |
| G5 适配 AI 编码节奏 | 提供 `--staged` 提交前扫描、pre-commit 钩子、以及 `--ai-prompt` 生成的修复指令文件 |
| G6 CI 可阻断 | 支持 `--fail-on` 退出码与 SARIF 输出，可直接接入 GitHub Code Scanning |
| G7 结果可信 | 所有外部数据标注来源与时间；离线时明确降级，不猜测、不伪造结论 |
| G8 技术栈无关 | 同一份规则与评分对任意主流技术栈生效；新增生态只需在注册表加一行 + 一个解析函数，不改扫描器与报告 |

---

## 3. 范围

### 3.1 核心旅程（P0）

进入条件：用户在任意仓库根目录执行命令。

1. `provemark scan` — 扫描当前目录，终端输出摘要 + 问题列表。
2. 用户看到「高风险 3 条」，执行 `provemark scan --format html -o report.html` 打开报告逐条看。
3. 用户对无争议问题执行 `provemark fix`（默认只预览），确认后 `--apply` 落地（补 LICENSE / .gitignore / SECURITY.md）。
4. 对需要人判断的问题，执行 `provemark scan --ai-prompt fix.md`，把文件交给 AI 代理修改。
5. 存在历史遗留问题时，用 `provemark ignore <指纹> --reason ... --expires ...` 建立带过期时间的豁免，之后只看新增问题。
6. 完成证据：再次扫描时总分上升、新增问题为 0、`--fail-on high` 退出码为 0。

恢复路径：网络不可用时，漏洞与依赖许可证降级为「未验证」状态并在报告中显著标注，其余本地检查照常完成，退出码不因“未验证”而误报成功。

### 3.2 P1（本期不实现，但接口预留）

- GitHub App / PR 评论回写；
- 依赖升级 PR 生成（含版本兼容性判断）；
- SBOM 导出（CycloneDX / SPDX）；
- 历史趋势数据库与团队看板；
- 容器镜像与 Dockerfile 基础镜像扫描。

### 3.3 明确不做

- 不做 SaaS、不上传代码；除公开元数据查询（OSV / deps.dev / 包注册表）外不发任何请求；
- 不做自动改写业务代码（`fix` 只新增缺失文件与配置，不改动源码语义）；
- 不替代专业法律意见：许可证结论标注为「工程判断」，不构成法律结论。

---

## 4. 核心模型

| 对象 | 定义 |
| --- | --- |
| Finding（问题） | 一条可定位、可解释、可豁免的检查结果，含规则 ID、维度、严重度、位置、证据、修法、指纹 |
| Package（依赖） | 来自某清单文件的一个依赖项：名称、生态、版本（可能未知）、作用域、是否直接依赖 |
| Policy（策略） | 项目的许可证策略、忽略清单、严重度覆盖、门禁阈值，存于 `.provemark.toml` |
| Baseline（基线） | 已确认接受的历史问题集合，每条必须有原因与过期时间 |
| Score（评分） | 0–100 的仓库健康分与 A–F 等级，计算规则见 §6.2 |

**维度（category）**：`security`（代码安全）、`secrets`（凭据泄漏）、`ai`（AI 代码痕迹与幻觉）、`dependency`（依赖漏洞）、`license`（许可证）、`supply`（供应链）、`hygiene`（仓库卫生）。

---

## 5. 功能需求

### FR-01 仓库卫生检查

- **触发**：每次 `scan`。
- **处理规则**：检查根目录是否存在 `LICENSE`、`README`、`SECURITY.md`、`.gitignore`；`.gitignore` 是否覆盖 `.env`、凭据文件、构建产物；仓库内是否已提交 `.env`、私钥文件、`node_modules/`、`__pycache__/`、虚拟环境目录；是否存在超过阈值的二进制大文件；是否存在 CI 配置。
- **结果**：缺失项按 §6.1 定级；已提交的 `.env` 或私钥文件为 critical。
- **例外**：明确声明为「素材仓库 / 文档仓库」时不适用 LICENSE 强制项——由策略文件 `project.kind` 控制（`library` 默认、`app`、`docs`）。

### FR-02 凭据泄漏检测

- **触发**：每次 `scan`，逐文件检查。
- **处理规则**：按内置规则匹配已知凭据格式（OpenAI、Anthropic、AWS、GitHub、Slack、Stripe、Google、私钥块、JWT 等），并对「疑似密钥赋值」做熵值判断。
- **结果**：命中即产出 finding；证据仅显示前 4 位与后 4 位，中间以 `****` 遮蔽，禁止在终端/报告/日志中出现完整凭据。
- **例外**：位于 `tests/`、`docs/`、`*.example`、`*.sample`、`fixtures/` 的命中降级为 low；值中包含 `example`、`dummy`、`placeholder`、`your-`、`xxxx`、`changeme` 时判定为占位符，不报 critical。命中豁免需 `ignore` 记录原因。

### FR-03 AI 代码风险检测

- **触发**：每次 `scan`。
- **处理规则**：识别以下与 AI 生成代码强相关的模式：占位密钥；未完成实现（`NotImplementedError`、空函数体加 TODO）；异常吞没（`except: pass`、`catch {}`）；危险调用（`eval`/`exec`/`pickle.loads`/`yaml.load`/`shell=True` 拼接/`verify=False`/`innerHTML`）；生产代码中的 mock 数据与示例域名；调试残留（`console.log`、`print` 调试、`debugger`）；**幻觉依赖**（代码里 import 了但清单里没有、且不是标准库或本地模块的包）。
- **结果**：按模式定级；幻觉依赖为 high，因为它在运行时才爆炸。
- **例外**：`tests/`、`examples/`、`scripts/` 中的调试残留降级；`print` 在 CLI 入口文件不报。

### FR-04 依赖解析

- **触发**：`scan` 时发现清单文件。
- **处理规则**：以生态注册表（`ecosystems.py`）为唯一事实来源，按「文件名 → 生态 → 解析器」分派。当前覆盖 19 个生态：
  - Python：`requirements*.txt`（含 `-r` 递归、`--extra-index-url`）、`pyproject.toml`（PEP 621 / poetry / uv / dependency-groups）、`Pipfile`、`uv.lock`、`poetry.lock`、`Pipfile.lock`、`pdm.lock`
  - Node.js：`package.json`、`package-lock.json`、`yarn.lock`、`pnpm-lock.yaml`、`bun.lock`、`deno.json(c)`
  - Go：`go.mod`（含 `// indirect`）、`go.sum`；Rust：`Cargo.toml`、`Cargo.lock`
  - JVM：`pom.xml`（properties 展开 + dependencyManagement）、`build.gradle(.kts)`、`gradle/libs.versions.toml`、`build.sbt`、`deps.edn`、`project.clj`
  - .NET：`*.csproj` / `*.fsproj` / `*.vbproj`、`packages.config`、`Directory.Packages.props`、`*.nuspec`（解析 MSBuild `$(Property)` 变量与集中版本管理）
  - Ruby：`Gemfile`、`Gemfile.lock`、`*.gemspec`；PHP：`composer.json`、`composer.lock`
  - Dart：`pubspec.yaml`、`pubspec.lock`；Swift：`Package.swift`、`Package.resolved`
  - Elixir：`mix.exs`、`mix.lock`；R：`DESCRIPTION`、`renv.lock`；Haskell：`*.cabal`；Julia：`Project.toml`、`Manifest.toml`
  - C/C++：`vcpkg.json`、`conanfile.txt`、`conanfile.py`；Perl：`cpanfile`；Conda：`environment.yml`
  - CI：`.github/workflows/*.yml` 中的 `uses:`（映射为 `GitHub Actions` 生态）
- **结果**：产出统一 Package 列表。声明了精确版本或存在锁文件时取锁文件版本；仅声明范围时版本记为未知，并在漏洞检查中标注「无法确定版本」。monorepo 中多个生态的结果会合并，并保留各自清单路径。
- **例外**：本地路径依赖、`file:`、`workspace:`、`git+` 依赖不计入漏洞查询，单独提示其不可验证性；由父 POM / 中央版本文件 / gemspec 管理的版本标记为 `pinned_by_parent`，不判为「未指定版本约束」。

### FR-05 漏洞查询

- **触发**：存在可确定版本的依赖且网络可用。
- **处理规则**：批量查询 OSV.dev；对命中的公告拉取详情以获得严重度与修复版本；结果按公告 ID 缓存（公告内容不可变）。
- **结果**：每个「依赖 × 公告」一条 finding，含当前版本、修复版本、严重度。
- **例外**：网络失败或超时→该依赖标记 `unverified`，报告中单列「未验证依赖数」，不产生假阴性结论；用户可用 `--offline` 强制跳过。

### FR-06 许可证合规

- **触发**：每次 `scan`。
- **处理规则**：识别项目自身声明的许可证（LICENSE 文本特征 + 清单字段），校验两者是否一致；查询依赖许可证；按策略判定 allow / warn / deny；对 `OR` 表达式取最宽松可选项、`AND` 表达式要求全部满足。
- **结果**：项目未声明许可证为 high；deny 类依赖为 high；`unknown` 依赖为 medium 并提示「未能获取许可证」；强 copyleft 依赖出现在宽松许可证项目中时给出「分发即传染」的解释。
- **例外**：策略可显式把某依赖加入 `license.exceptions`（例如「仅在内部工具使用」），需原因。

### FR-07 供应链检查

- **触发**：每次 `scan`。
- **处理规则**：检查是否存在锁文件；生产依赖是否为 `*`/`latest`；包名与流行包名的编辑距离（疑似仿冒）；`requirements.txt` 是否含非 HTTPS 源或 `--extra-index-url`；GitHub Actions 的 `uses:` 是否固定到 SHA；脚本中是否存在 `curl | bash`；Dockerfile 是否使用 `:latest`。
- **结果**：无锁文件为 medium；疑似仿冒为 high；其余为 low / medium。
- **例外**：`dev` 作用域的宽松版本仅提示不加分扣减；私有源可配置 `supply.allowed_indexes`。

### FR-08 评分与门禁

- **触发**：扫描完成后。
- **处理规则**：按 §6.2 计算总分与等级；基线内且未过期的问题不计分。
- **结果**：终端显示 `分数 78 / 等级 C`；`--fail-on` 命中时退出码为 1，否则 0；参数错误为 2。
- **例外**：`unverified` 状态超过依赖总数 50% 时，等级旁标注「数据不完整」，不宣称健康。

### FR-09 报告输出

- **触发**：`--format` 指定或 `-o` 指定文件。
- **处理规则**：支持 `table`（默认）、`json`、`markdown`、`sarif`、`html`。
- **结果**：HTML 为单文件、无外部资源，含总分环、维度分布、按严重度筛选、逐条证据与修法、数据来源与扫描时间；SARIF 符合 2.1.0，可被 GitHub Code Scanning 直接读取。
- **例外**：终端非 TTY 时自动关闭颜色与交互符号。

### FR-10 安全修复

- **触发**：`provemark fix`。
- **处理规则**：默认 dry-run，仅列出将执行的动作；`--apply` 才写入；已存在的文件不覆盖，除非 `--force`。
- **结果**：可新增 `LICENSE`（按策略选择的 SPDX 模板）、`SECURITY.md`、`.gitignore` 补充条目、`.provemark.toml`、CI 工作流。每个动作打印路径与原因。
- **例外**：任何会改动已有业务代码的动作一律不提供，改为输出到 `--ai-prompt` 的指令里。

### FR-11 豁免管理

- **触发**：`provemark ignore <fingerprint|rule-id>`。
- **处理规则**：必须提供 `--reason`；`--expires` 必填（默认 90 天）；写入 `.provemark.toml` 的 `[[ignore]]`。
- **结果**：被豁免项在报告中折叠显示；过期后自动恢复计分，并新增一条 `IGN-001 豁免已过期`。
- **例外**：critical 级问题不允许豁免（策略可放开），必须在本次修复。

### FR-12 AI 修复指令导出

- **触发**：`--ai-prompt <file>`。
- **处理规则**：按「文件 → 问题 → 期望改法 → 验证命令」组织，明确禁止改动的范围与「不得引入新依赖」等约束。
- **结果**：生成可直接投喂给编码代理的 Markdown。
- **例外**：无问题时生成一句话说明，不生成空模板。

### FR-13 FOSSA 协同

- **触发**：`scan` 时发现 `.fossa.yml` / `.fossa.yaml` / `fossa-deps.yml|yaml|json`，或显式传入 `--sbom <file>`（也自动发现根目录的 `sbom.json` / `bom.json` / `*.spdx.json`）。
- **处理规则**：
  - 配置体检：`FOS-001` 多包仓库缺少 `paths.only` / `targets.only`；`FOS-002` vendored / 依赖目录未排除在 `paths.exclude` 之外；`FOS-003` fossa-deps 条目不合规（type 不在 FOSSA 支持列表、缺 name、缺 version、custom 缺 license、vendored 路径不存在、remote 缺 http(s) URL）；`FOS-004` CI 有 `fossa analyze` 但没有 `fossa test`；`FOS-005` 配置版本不是 3 或 YAML 解析失败。
  - 结论对齐：解析 CycloneDX / SPDX JSON，与本地许可证判定逐包比较。`FOS-006` 家族不同（如本地 MIT / SBOM GPL）→ 需人工确认；`FOS-007` 本地 unknown 而 SBOM 有结论 → 生成可粘贴的 `license.exceptions` 片段；`FOS-008` SBOM 有而本地未解析到 → 覆盖率缺口提示。
- **结果**：不依赖 FOSSA 账号与网络，只读本地文件；离线时不比对许可证结论（避免把未知误判为冲突），但仍输出覆盖率缺口。
- **例外**：SBOM 超过 20MB、非 JSON、或无 `bomFormat` / `spdxVersion` 时降级为一条提示，不猜测结构；`fossa test --format json` 的原始输出不在支持范围（结构未公开稳定），请改用标准 SBOM 导出。

### FR-14 fossa-deps 生成器

- **触发**：`provemark fossa-deps [path]`。
- **处理规则**：
  - `--mode missing`（默认）：只声明 FOSSA 自己扫不到的部分——按「含 LICENSE 的最小目录」拆分 vendored 组件，避免把整个 `vendor/` 当成一个包。
  - `--mode all`：把本项目解析到的、FOSSA 支持类型的依赖全部写成 `referenced-dependencies`（`--limit` 控制上限），作为 FOSSA 构建策略失败时的兜底。
  - 生态到 FOSSA 类型的映射集中在 `ECOSYSTEM_TYPES`；无对应类型（Conda / Julia / vcpkg / Conan / GitHub Actions）与 `url:` / `file:` 依赖明确计入跳过统计，不静默丢弃。
  - 版本号一律加引号写入，避免 YAML 把 `1.0` 解析成 `1`。
- **结果**：写出合法 `fossa-deps.yml`，文件头带生成标记与时间；`--print` 只输出内容不落盘。`--mode all` 的文件头必须包含醒目警告——全量声明会与 FOSSA 自动扫描重叠、可能产生「来源不同」的重复条目、且需随依赖升级重新生成，并引导回缺省的 missing 模式。
- **例外**：目标文件已存在且不是本工具生成（无生成标记）时**不覆盖**，改写 `fossa-deps.provemark.yml` 并提示使用 `fossa analyze --fossa-deps-file`；`--force` 才覆盖。重新生成时不会把上一版自己生成的条目误判为「手写声明」。

---

### FR-15 敏感数据（PII）扫描

- **触发**：`scan` 默认启用；`--only pii` 只看这一维度，`--skip pii` 跳过；`[pii] enabled = false` 永久关闭。
- **处理规则**：
  - 通用格式：邮箱、手机号、银行卡号（13–19 位 + Luhn + IIN 前缀）。
  - 辖区格式：`.pdp-compliance.json` 的 `personalDataProtection.jurisdictions` 决定启用哪些——SG NRIC（加权校验位）、泰国身份证（mod 11）、印尼 NIK（省份 + 出生日月）、马来西亚 MyKad（出生日期 + 州代码）、菲律宾 PhilSys（需 `philsys` / `umid` 关键词，无公开校验和）。
  - 未声明辖区时只做通用格式识别，报告标注「未按辖区校验」，不猜测法域。
  - 日志规则：日志调用中出现 PII 字段插值（`{...email...}` / `+ email`）时提示。
  - 快照规则：单文件出现 ≥ 20 个不同邮箱时提示「疑似真实数据快照」。
  - 政府证件号优先于银行卡号判定（16 位 NIK 可能同时通过 Luhn，不能误判为卡号）。
- **隐私不变量**：报告、JSON、SARIF、缓存中**不得出现原始值**，只保存掩码与位置；去重用的哈希只存在于内存，合并后立即丢弃。
- **降噪**：`example.com` / `test.com` / `user@` 等占位值不报；测试目录命中降级并限制置信度 ≤ 0.4，不参与门禁；同一值多处出现合并为一条。
- **例外**：`.pdp-compliance.json` 缺失或格式非法时不报错，退化为通用格式；辖区代码不在支持列表内时忽略该条。

---

### FR-16 许可证组合矩阵

- **触发**：`scan` 的 license 扫描器，在拿到依赖许可证之后自动执行；离线或依赖许可证无法解析时跳过（沿用现有 note）。
- **处理规则**：
  - 把许可证归并为 11 个兼容类（permissive / apache / mpl / epl / lgpl2 / lgpl3 / gpl2 / gpl2plus / gpl3 / agpl3 / source-available），未知归为 `unknown`。
  - 项目许可证取"声明优先、文件兜底"：`[project] license` > 清单字段 > `LICENSE` 内容识别，与 `LIC-002` 的 `declared` 语义一致。
  - `项目类 × 依赖类` 查表得到 `ok` / `conditional` / `incompatible` / `unknown`；依赖表达式 `OR` 取最优、`AND` / `WITH` 取最差。
  - `incompatible` → `LIC-009`（高危，dev 依赖中危），文案给出具体原因（如 Apache-2.0 专利条款与 GPL-2.0-only 不兼容）。
  - `unknown` → `LIC-010`（提示），按"项目许可证 × 依赖许可证"组合聚合，最多 5 组，避免逐包刷屏。
  - `conditional` 不产出 finding：弱传染在保留声明、公开修改文件的前提下可用，逐条提示只会制造噪音。
  - 策略禁止（`LIC-004`）与组合判定分离：若依赖被策略禁止但组合兼容（例如 GPL 项目用 GPL 依赖），`LIC-004` 降为提示并说明是策略选择。
- **边界**：项目许可证缺失或无法归类时**完全跳过**矩阵，不猜测；`WITH` 例外（Classpath / LLVM）不建模，归为 `unknown` 提示人工确认。
- **免责**：兼容性结论是工程判断，不构成法律意见。

---

### FR-17 归因完整性（THIRD_PARTY_NOTICES）

- **触发**：`provemark notices [path]`；扫描时由 repo 扫描器检查归因文件。
- **生成规则**：
  - 只列运行时依赖（`scope != dev`），GitHub Actions 等构建期依赖排除；
  - 许可证复用 license 扫描器的解析结果（含缓存）；拿不到的标为「许可证未知」；
  - 文件头写明生成时间、覆盖组件数、未知数，不宣称完整；
  - 已有手写文件时不覆盖，改写 `THIRD_PARTY_NOTICES.provemark.md`；`--force` 才覆盖；
  - `--offline` 只用缓存，不发起网络请求。
- **检查规则**：
  - `HYG-014`（低）：有运行时依赖但没有任何归因文件（`THIRD_PARTY_NOTICES*` / `NOTICE*`）；
  - `HYG-015`（提示）：归因文件未覆盖部分依赖，按缺失包名聚合，最多列 20 个。
- **边界**：只做"组件是否被提到"的存在性检查，不逐版本比对；归因是工程义务清单，不构成法律意见。

---

### FR-18 AI 使用声明

- **触发**：`provemark ai-usage [path]`；扫描时由 repo 扫描器检查。
- **生成规则**：
  - 自动探测 AI 助手痕迹：`CLAUDE.md`、`AGENTS.md`、`.cursorrules`、`.cursor/`、`.windsurfrules`、`.clinerules`、`.aider.conf.yml`、`.github/copilot-instructions.md`、`.continue/`、`.codeium/` 等；
  - 生成 `AI_USAGE.md`，固定四个小节：使用的工具 / 使用范围 / 人工复核 / 生成内容留存，未填字段留「待填写」；
  - 检测到的痕迹写入独立小节，作为"确实用过 AI"的证据，**不推断未检测到的使用**；
  - 不覆盖手写文件（改写 `AI_USAGE.provemark.md`）。
- **检查规则**：
  - `AI-013`（提示）：有助手痕迹但没有 `AI_USAGE.md`；
  - `AI-014`（提示）：声明缺必需小节，或仍含「待填写」占位。
- **边界**：不做 AI 生成内容识别（不可靠），只检查声明是否存在且可读。

---

### FR-19 vendored 来源记录

- **触发**：`provemark vendored [path]`；扫描时由 repo 扫描器检查。
- **生成规则**：
  - 复用 `fossa-deps` 的 vendored 目录识别（`vendor/`、`third_party/`、`external/` 等）；
  - 排除包管理器目录（`node_modules`、`bower_components`、`Pods`、`Carthage`），它们由锁文件管理；
  - 从目录内 `LICENSE*` 自动判定 SPDX 许可证，判不出写「未识别」；
  - 生成 `VENDORED.md`：目录 / 许可证 / 上游 / 版本或 Commit / 修改说明，上游与版本留「待补齐」标记；
  - 不覆盖手写文件。
- **检查规则**：
  - `SCP-014`（中）：存在 vendored 目录但没有 `VENDORED.md`；
  - `SCP-015`（低）：来源记录漏目录，或上游/版本仍是「待补齐」。
- **边界**：只校验"目录是否被记录、TODO 是否清空"，不校验上游地址可访问；不修改 vendored 代码。

---

## 6. 共享规则

### 6.1 严重度

| 级别 | 判定标准 |
| --- | --- |
| critical | 可直接导致凭据泄漏或远程代码执行；已提交的真实密钥；GPL 依赖进入闭源分发链路 |
| high | 已知高危漏洞；幻觉依赖；项目无许可证；危险调用模式；疑似仿冒包；政府证件号；银行卡号；日志打印 PII |
| medium | 中危漏洞；许可证未知；无锁文件；异常吞没；占位密钥 |
| low | 低危漏洞、调试残留、宽松版本范围、Actions 未固定 SHA |
| info | 建议类，不影响分数趋势 |

### 6.2 评分

对每个维度：`扣分 = Σ_severity 权重(s) × (1 + 0.7 × log2(有效次数))`，其中 `critical=35, high=8, medium=2, low=0.8, info=0.1`；**有效次数 = Σ confidence**（全置信度时等效于条数计数，0.5 记半次，0 不计分，下限 0.05 防止对数发散）；**致命级不设上限**，其余级别单维度扣分上限 25；总分 `100 - Σ维度扣分`，下限 0。等级：A ≥ 90，B ≥ 80，C ≥ 70，D ≥ 60，F < 60。

置信度只影响扣分与门禁，不影响 `counts` 里的条数统计：低置信度问题照样列出，避免"少报"。

- 用对数而非线性，是为了让「1 条」与「5 条」有区别，但不让 60 条同类问题把分数直接打到 0；
- 致命级不设上限：一条真实密钥泄漏就足以把分数拉到 D 以下，这类问题不该被平均数稀释；
- 数据不完整（离线，或超过一半依赖无法确定版本）时，报告标注「分数仅供参考」，不宣称健康。

### 6.3 指纹与稳定性

指纹 = `规则ID + 路径 + 行内容归一化哈希`，不包含行号。代码上下移动不改变指纹，避免基线失效。

### 6.4 数据来源与可信度

| 数据 | 来源 | 缓存 |
| --- | --- | --- |
| 漏洞 | OSV.dev（`/v1/querybatch`、`/v1/vulns/{id}`），覆盖 PyPI、npm、Go、crates.io、Maven、NuGet、RubyGems、Packagist、Pub、SwiftURL、Hex、CRAN、Hackage、ConanCenter、vcpkg、Julia、GitHub Actions 等 | 查询 6 小时，公告 30 天 |
| 依赖许可证 | deps.dev v3（npm / PyPI / Go / Cargo / Maven / NuGet / RubyGems）；回退 PyPI、npm、crates.io、Packagist、RubyGems、Hex、CRAN、Hackage、Maven Central POM、NuGet nuspec | 7 天，仅缓存命中结果 |
| 许可证规则 | 内置 SPDX 元数据 | 随版本 |

所有 finding 的 `source` 字段标注 `local` / `osv` / `deps.dev` / `registry`；报告页脚显示扫描时间、数据新鲜度与降级说明。

### 6.5 隐私

默认不外发任何文件内容或包名之外的元数据；`--offline` 可完全禁止网络；缓存目录位于 `~/.cache/provemark`，可用 `PROVEMARK_CACHE_DIR` 覆盖。

---

## 7. 决策记录与待确认问题

| 编号 | 问题 | 结论 | 影响 |
| --- | --- | --- | --- |
| Q1 | 默认门禁阈值用 `high` 还是 `critical` | **已决（0.3）**：`fail_on=high` + `min_confidence=0.5`。多生态与置信度加权后误报率已降下来，`high` 可安全作为默认；低置信度问题不阻断 CI | 固化在 `Config` 默认值、策略模板、`init` 工作流、Action 四处 |
| Q2 | npm 的 `^` 范围是否算「浮动版本」 | 待确认 | 影响 supply 类噪音量 |
| Q3 | 是否需要拉取 GitHub 三项检查明细并合并进报告 | 待确认（当前已用 `--sbom` 与 FOSSA 对齐，先覆盖合规部分） | 需要 GitHub Token 与额外权限 |
