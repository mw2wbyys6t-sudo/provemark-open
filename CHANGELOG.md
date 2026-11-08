# 更新日志

本文件记录所有版本变更，格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [未发布]

### 新增（端到端演示仓库 + 双语 README）
- `demo/orderdesk/`：48 个文件的三栈演示仓库（Python API / React 面板 / Go 网关），
  刻意写入 SQL 拼接、硬编码密钥、`.env` 入库、过期依赖等，用于在 README 里展示插件的真实效果。
  已加入 `.provemark.toml` 的 `exclude`，不参与本仓库门禁。
- `README.en.md`：完整英文版；两个 README 顶部互加语言切换。

### 修复（跑演示时暴露的三个插件缺陷）
- **`PII-001` 把连接串口令当邮箱**：`postgresql://<user>:<password>@db.internal` 里的口令段
  命中邮箱正则。新增 `rules.email_in_url_credentials()`，只放行 URL **authority** 内的
  `user[:pass]@host`；路径与查询串里的真邮箱照常报（`/search?mail=a@b.com`）。
  新增 5 项回归测试。
- **分数在涨却报「变差、先回退」**：`describeTrend()` 只看 `newCount`，升级依赖换了版本号会产生
  新指纹，于是把 +73 分的一次改动画成退步，还会命令模型回退。现在按 `scoreDelta` 分档：
  涨 → 「+N 分，新增项单独确认」；持平 → 「持平」；只有真的下降才说「变差」并提示回退。
- **仪表盘写死「0 个项目 / 0 次扫描」**：`runProgress()` 的 dashboard 分支直接返回
  `projects: 0, scans: 0`，历史库为空时还会谎报「已生成」。现在从 CLI 真实输出解析计数，
  解析不到（历史库为空）就返回错误而不是伪造路径。
- `selftest.mjs` 为此新增 7 条断言（计数、空账本、趋势措辞三种档位）。测试 394 → 399。


## [0.7.1] - 2026-11-08

### 修复（两条长期挂着的自身误报：SCP-001 / DEP-003）
背景：本仓库自己长期被报 `SCP-001`（Python 依赖没有锁文件）与 `DEP-003`（有依赖无法确定版本）。
逐条核对后，这两条都不是"该补锁文件"，而是规则把**不属于默认安装面**的东西算了进去：
- **SCP-001 范围收紧**：库的默认安装面才是可复现性该管的地方。`pip install provemark` 解析零依赖，
  而 `[project.optional-dependencies] yaml = ["PyYAML>=6"]` 属于使用方按需安装的可选 extra——
  它浮动不是"这个包安装不可复现"。规则现在对 **library** 只统计 `runtime` 作用域的浮动依赖；
  应用（`.provemark.toml` 里 `kind = "app"`）保持原行为，dev/可选依赖浮动同样要求锁文件。
- **DEP-003 拆成"版本未知"与"按 SHA 固定"两类**：GitHub Action 固定到 40 位 commit SHA 是**推荐做法**，
  也是精确可复现的；OSV 只接受版本号、查不了 SHA，所以它不属于"只声明了范围"。
  现在这类只写入报告注释（"N 个 GitHub Action 按 commit SHA 固定…可用 Dependabot 跟踪更新"），不再生成
  "去生成锁文件"的 finding——原来的修法对 Action 根本不成立。
- **可选 extra / dev 依赖的浮动版本同样只进注释**：它们的版本由使用方或 CI 解析，包本身无法行动；
  `DEP-003` 现在只覆盖运行时依赖。未查询的依赖数仍然如实计入 `stats.packages_unverified`
  （所以"数据不完整，分数仅供参考"这条提示保留，不掩盖漏洞维度对这几个依赖是盲的）。
- 规则说明同步更新（`provemark explain SCP-001` / `DEP-003` 会解释这层作用域差异）。
- 扫描器版本 `0.5.0 → 0.5.1`；新增 4 项回归测试：
  库的可选 extra 不触发 SCP-001、应用的可选依赖仍触发、SHA 固定的 Action 不触发 DEP-003 但留 note、
  可选 extra 的浮动版本只留 note。
结果（本仓库）：**100/100 A，致命/高危/中危/低危/提示 全部 0**，仅保留两条说明性注释。

## [0.7.0] - 2026-11-07

### 新增（进度跟踪：单项目 / 跨项目，可视化）
- **历史账本 `provemark/history.py`**：每次**完整**扫描追加一条 JSONL 记录到 `~/.cache/provemark/history.jsonl`
  （`PROVEMARK_HISTORY_FILE` 可覆盖）。记录只含分数、各级别计数、文件/依赖数、扫描耗时与来源，以及每条问题的
  指纹/规则/级别/相对路径——**不含源码、不含证据文本、不含密钥**。
  - 写入策略：1 小时内完全相同的结果折叠成一个点；历史库有上界（单项目 400 / 总计 5000 / 400 天），超限原子重写；
  - 局部扫描（`--only` / `--skip` / `--staged`）**不**入账，否则时间线会混进"只看 PII"的分数；
  - `--no-history` 关闭、`--history-source NAME` 标记来源（插件传 `dsh`，CLI 默认 `cli`）。
- **生命周期**：同一条问题的指纹消失即"已修复"，再次出现即"复发"，首次出现时间即"年龄"。
  完全从账本推导，不需要额外状态文件；文件改名会因指纹变化被识别为新问题（这是有意的，避免掩盖）。
- **`provemark progress`**：单项目进度（当前分数 / 较首次 / 未修复明细 / 累计修掉 / 复发 / 近 7 天修复与新增），
  `--all` 出跨项目总览，`--json` 给工具消费，`--days N` 限定窗口。
- **`provemark dashboard`**：生成**单文件 HTML 仪表盘**——跨项目总览表（分数、等级、未修复、近 7 天修复/新增、
  迷你走势）+ 每个项目的分数时间线（内联 SVG）+ 未修复问题堆叠柱状图 + 未修复清单（级别/规则/位置/首次出现/复发）。
  没有网络请求、没有外部字体或脚本，双击可看，也能当 CI artifact；正文默认不打印到终端（`--print` 可选）。
- **插件工具 `provemark_progress`**：`action="summary"` 读账本（单项目或 `all=true`），
  `action="dashboard"` 在工作区/临时目录内写仪表盘（沿用扫描工具的写盘范围校验）。扫描调用现在带
  `--history-source dsh`，局部扫描带 `--no-history`。
- 扫描器版本 `0.4.0 → 0.5.0`（新增两个子命令与历史模块）。
- 测试：`tests/test_history.py`（记录形状/去重/轮转/损坏行容忍/生命周期/跨项目汇总，12 项）、
  `tests/test_dashboard.py`（空态/总览/转义/无外部资源/生命周期联动，5 项）、`tests/conftest.py`
  把测试期的历史库指向临时目录（不是新增依赖，模块级设置即可）；插件 selftest 新增 9 条断言（含"局部扫描不入账"）。

## [0.6.7] - 2026-11-07

### 图标回退（用回最初那版「源印」）
- 按你的选择，`icon.svg` 回到最开始那版：**深墨瓦片 + 倾斜的印花印章 + 刻出的对勾**，没有任何吉祥物元素。
  理由也说得通：24px 时印章的对比度最高，插件列表里最容易被认出来。
- Q 版「大肥鱼」人物方案没有丢，留在 `docs/assets/icon-alt-mascot.svg`（原创，蓝发 + 荷叶边发箍 + 鲸尾发卡）。
  想切回去：把该文件复制进 `plugin/provemark-dsh/`，再把 `package.json` 的 `"icon"` 改成它的文件名
  （DSH 要求图标必须在包目录内，不能引用包外路径）。
- 0.6.5 的鲸鱼剪影版未保留（已被人物版取代），需要的话我可以按 0.6.5 的描述重建。
- 校验：`icon.svg` 1711 字节、XML 可解析、`validate.mjs` 图标检查全绿；预览图更新到 `docs/assets/`。

## [0.6.6] - 2026-11-07

### 图标改版（换成「大肥鱼」Q 版形象）
- 上一版是鲸鱼剪影，这次按你给的方向换成**蓝发 Q 版角色**：白色荷叶边发箍 + 蓝色蝴蝶结 + 鲸尾发卡 + 大眼睛/腮红/小圆领，
  右下角保留青绿「源印」对勾徽章——形象要像，同时"守卫判定"的产品语义不能丢。
- **版权口径（重要）**：角色是我按"蓝发 Q 版 + 鲸鱼意象"这个**类型**重新画的原创矢量，**不是**你给的那张图、
  也不是任何官方形象或表情包的描摹/截图；包内不含任何第三方素材，可随包分发。如果你要的是"就用那张原图"，
  那需要你提供有授权的 PNG（≤256 KiB），我可以直接接进 `icon.svg` 的位置——`package.json` 的 `icon` 字段换成
  `icon.png` 即可，不用改代码。
- 技术：图形只用了 `rect`/`ellipse`/`circle`/`polygon`/`path(M/L/C/Q/Z)` 与线性渐变；`validate.mjs` 的 SVG
  合法性检查（根元素/命名空间/viewBox/无脚本/无远程引用/已打包）照旧通过；24px 下仍能看出"蓝发头像 + 亮色徽章"。
- 预览图（512px + 24/48px 深色底可读性）更新到 `docs/assets/`。

## [0.6.5] - 2026-11-07

### 图标改版（加入 DeepSeek「大肥鱼」元素）
- **一条胖鲸浮出水面，背上盖着印章**：原来的"印章 + 对勾"太通用，读不出这是 DeepSeek 生态的插件。
  现在图标有了主角——按同色系**原创绘制**的蓝鲸剪影（鼓身体、圆脑袋、扇形尾鳍、喷气水泡、一个笑眼），
  印章压在它背上，两者共用同一套冷色渐变。24px 时仍能看出"蓝色胖鱼 + 亮色徽章"两层结构。
- **版权口径**：鲸鱼是原创矢量（`rect`/`ellipse`/`path` 手绘），**不是** DeepSeek 官方 logo 的描摹或复制，
  不含任何第三方素材，可随包分发；README 里写明了这一点。
- 技术细节：鲸鱼的身体/脑袋/尾鳍共用一个 `gradientUnits="userSpaceOnUse"` 渐变，避免多形状拼接出现接缝；
  图形只用 `rect`/`ellipse`/`circle`/`polygon`/`path`，`validate.mjs` 的 SVG 合法性检查照旧通过。
- 预览图（512px 与 24/48px 深色底可读性检查）更新到 `docs/assets/`。

## [0.6.4] - 2026-11-07

### 安全（第三方红队审计后的输入边界加固）
审计范围：插件 `lib/` 全部模块 + 随包 Python 扫描器的输入/输出路径。下面每条都附了回归断言，
不是"看起来修了"。评分口径不变。
- **写盘越界（高危）**：`provemark_scan` 的 `output` / `aiPrompt` 原先对绝对路径不做限制，而 `path`
  由模型提供——"扫 `~/.dsh` 再把相对报告写进去"就等于往 profile 里写文件（还是绕过 agent 沙箱的宿主写入）。
  现在写盘锚点是**会话工作区**而不是扫描根：相对路径必须留在工作区内，绝对路径只额外允许系统临时目录，
  并且所有路径先经过符号链接解析再校验；扫描根不是锚点，所以"把某个目录当 path 扫一遍"不再附带写权限。
- **提示注入边界（中危）**：扫描输出里的路径/标题/说明来自被扫仓库，原先直接拼进系统提示词段、工具输出和
  收件箱通知，一个恶意仓库可以用换行伪造出一段"系统指令"。现在统一 `oneLine()` 压平 + `<untrusted-scanned-repo>`
  边界包裹 + 剥离伪造边界标签，覆盖动态状态块、`provemark_guard` 渲染、`provemark_scan` 回执与后台通知四条路径。
- **仓库策略豁免不再隐形（中危）**：实测 `[[ignore]] rule = "*"` 可让扫描返回 100 分 / 0 findings / 7 条 suppressed，
  于是守卫会把"被自己的策略压干净"当成"没问题"。现在 `suppressed` 计数进入结论
  （"仓库策略/基线豁免了 N 条问题（未计入分数）"），并有端到端断言。
- **`requirements.txt` 的 `-r` 越界读取（中危）**：`-r ../../../Users/<u>/.dsh/config.json` 会让解析器读仓库外的文件，
  其词元再以依赖名形式出现在结论里。现在解析前校验 include 目标仍在仓库内（绝对路径同理）。
- **`fix --apply` 穿过符号链接写盘（中危）**：仓库里放 `.gitignore -> ~/.bashrc`（或悬空的 `.provemark.toml` 链接）
  时，安全修复器会"只新增文件"却写到仓库外。现在目标或任一父目录是符号链接就跳过，并说明原因。
- **未捕获的 Promise 拒绝（低危）**：工具注册链原先没有 `.catch`，宿主 `defineTool` 漂移时会在现代 Node 上
  直接杀掉宿主进程；现在捕获并降级为"只有提示词守卫"。
- **诊断标记文件（低危）**：`%TEMP%/provemark-dsh-loaded.json` 改为私有目录 `%TEMP%/provemark-dsh/loaded.json`
  （目录 0700、文件 0600），避免多用户机器上的符号链接/截断与信息泄漏；`doctor` 兼容旧路径。
- 新增 `tests/test_input_hardening.py`（6 项）与 4 条 selftest 断言；仓库测试 331 项全过。

### 新增（图标与生态展示）
- **插件图标 `icon.svg`**：原创矢量图标——深墨色圆角瓦片 + 一枚略微倾斜的「印花」印章，印章内是刻出的对勾；
  青绿→天蓝渐变表示"本地校验通过"，倾斜与印章形态对应「源印」。512×512、1.7 KB，`package.json` 顶层 `icon` 声明。
- **本地化 `locale/en.json`、`locale/zh.json`**：`meta.title` / `meta.description`，Plugin Manager 与设置页
  不激活插件也能显示名称与能力说明；`exports` 新增 `./locale/*.json` 与 `./icon`，`files[]` 同步打包。
- `scripts/validate.mjs` 新增展示资源校验：图标存在/大小/SVG 合法性/无脚本与远程引用/被 `files[]` 收录，
  以及两份 locale 的 `meta` 完整性、`dependencies` 为空、`SKILL.md` 版本与 `package.json` 一致。

## [0.6.3] - 2026-11-07

### 适配（DeepSeek Harness 生态元数据与安装路径）
- **声明宿主版本要求**：插件包 `provemark-dsh` 的 `package.json` 新增 `dsh.engines.dsh: ">=0.2.2-rc.1"` 与
  `dsh.compatibility.dshReleases`。之前没有这条声明，插件管理器无法在安装前判断宿主是否兼容；
  现在不满足版本会被拦住，而不是装上一个跑不通半截的包。
- **宿主工具 API 仍是运行时解析**：`@deepseek-ai/dsh-tools` 继续走动态 import（失败即退化为提示词守卫），
  因此 `dependencies` / `optionalDependencies` 保持为空；`scripts/validate.mjs` 新增这条不变量检查，
  防止以后有人把依赖写进来、悄悄破坏「不需要 npm/pip 安装」的前提。
- **补齐包元数据**：`author` / `repository`（含 `directory`）/ `homepage` / `bugs` / `publishConfig.access`，
  供插件市场与 `npm pack` 后的包页展示。
- **`validate.mjs` 增加生态清单与版本一致性检查**：`dsh.engines.dsh`、`dsh.compatibility.dshReleases`、
  `dependencies` 为空、`SKILL.md` 的 `metadata.version` 与 `package.json` 版本一致——后者正是
  `release.mjs` 维护四个版本锚点时最容易漂移的一处。
- **README 安装章节改为双路径**：主路径是 Harness 自带的 `plugin_manager install_bundle`（生态标准做法，
  不改 profile 文件），仓库内 `scripts/install.mjs` 作为 CI / 无界面环境的脚本化路径保留；
  新增「兼容性」表，把宿主版本、工具 API、Node、实测环境一次说清。
- 实测：DSH `0.2.2-rc.1` + Node `24.21.0` + Python `3.14.7` 下 `doctor` 九项全绿，
  插件 `selftest`、`validate`、`sync-vendor --check` 与仓库 `pytest`（325 项 / 38 subtests）全过。

## [0.6.2] - 2026-11-02

### 修复（GitHub CI 红叉 + README 图文示例）
- **CI `scan` 失败根因一**：`pip install .` 生成 `build/lib/**`，扫描器把构建副本当源码，误报 AI-005 high。
  文件收集默认跳过 `build/`、`dist/`、`.venv/`、`venv/`、`node_modules/`、`*.egg-info/`、`.git/` 与缓存目录；
  项目级 `scan.exclude` 仍叠加生效。新增 `tests/test_file_collection.py`。
- **根因二**：GitHub Code Scanning 拒绝没有 location 的 SARIF result（`locationFromSarifResult`）。
  SARIF 现在只包含有文件位置的问题；仓库级问题保留在 JSON/HTML 与规则元数据里。新增回归测试。
- README 新增「30 秒看懂」：架构图、维护工作流图、真实 HTML 报告截图，以及 7 条常见误解校准。
- 实测：模拟 CI（干净副本 + `pip install .`）`--fail-on high` 退出 0，SARIF 全部结果都带 location。

## [0.6.1] - 2026-11-02

### 修复（发布前风险清零：3.11 兼容 / 跨平台 / 冷启动 / 分数校准）
- **Python 3.11 语法兼容**：`ai_code.py` 的 vendored 路径判断里，f-string 表达式含反斜杠（3.12+ 才允许），
  在 3.11 上直接 SyntaxError；改为先计算变量。新增 `tests/test_python311_compat.py`（AST 级守卫，不误报字符串样例）。
- **Linux 实测**（Docker：python:3.11-slim / 3.12-slim / node:22-bookworm）：
  - 3.11 与 3.12 全量测试 311 OK；CLI 边界（`/`、`/root`、中文 + 空格、symlink 环、60 层嵌套）全部通过；
  - Node 22 下 validate / selftest / sync-vendor --check / stress（44 项，Linux 无 junction 测试）全绿。
- **冷启动可判定**：`doctor` 新增 `host version` 检查——运行中宿主版本与插件包版本不一致时直接 FAIL 并提示重启；
  报告末尾给出冷启动步骤。
- **大仓库分数校准**：命中 ≥80 且 AI 质量类占一半时，报告注明“成熟框架写法会被命中，优先看 critical/high 与新增趋势”；
  命中 ≥200 时建议先用 `--only security,dependency`。避免把启发式分数读成判决。
- **开源仓库完善**：新增 `.github/dependabot.yml`（actions / pip 每周更新）、issue 表单（bug / feature）、PR 模板。
- 版本 0.6.0 → **0.6.1**。

## [0.6.0] - 2026-11-02

### 新增（开源准备 + 暴力测试加固）
- **压力测试脚本** `plugin/provemark-dsh/scripts/stress.mjs`（45 项）：持久化上限 / 损坏恢复 / unicode、40 次上下文渲染、
  20 并发工具调用、畸形事件、恶意配置、2MB 文件、二进制、60 层嵌套、junction 环、非 git `--staged`、
  四类报告格式、安装 → 重装 → 卸载生命周期（`npm run stress`）。
- **CLI 拒绝危险根**：`scan` / `init` / `fix` 对文件系统根（`C:\`、`/`）与用户主目录直接 exit 2 并说明原因
  （之前会开始遍历整盘，几分钟后才超时）。新增 3 个回归测试。
- **安装幂等**：重复 `install.mjs --copy` 不再报错，识别已有副本并刷新；`install --check` 输出扫描器 Python 行。
- **大仓库性能与信噪比**（Django 5.1.4，4047 文件实测）：
  - 全量扫描 75.5s → 49–56s；后台 / 工具超时默认 120s / 180s；
  - 测试代码不参与工程规则、vendored 目录跳过、N+1 只认 ORM 调用、PII 测试夹具跳过、AI-003/004 按文件聚合；
  - 同一仓库 findings 847 → 453，AI-005 94 → 16、AI-017 94 → 16。
- **开源准备**：新增 `CODE_OF_CONDUCT.md`；CONTRIBUTING 增加插件开发 / 发布流程；README 增加开发与安全 / 行为准则入口；
  `.gitignore` 补 `*.tgz` / `node_modules` / 插件 dist；CI 的 test job 增加插件 validate / selftest / vendor-sync
  （不新增 Action，避免 `SCP-007` 回归）。

## [0.5.0] - 2026-11-02

### 新增（跨重启棘轮 + 发布流程）
- **基线持久化**：每个工作区的首次基线写入 `~/.dsh/provemark-dsh/baselines.json`（环境变量
  `PROVEMARK_DSH_BASELINE_FILE` 可覆盖，`persistBaseline: false` 关闭），重启宿主后 `trend` 仍与跨会话基线比较，
  文案标注「跨会话基线」；新增 `provemark_guard(resetBaseline: true)` 用于明确接受现状后重置。
  存储按 root 哈希分键、最多 50 个工作区 / 每个最多 500 条指纹，原子写入，损坏时自动重建。
- **发布脚本** `scripts/release.mjs`：先跑 validate / sync --check / selftest 三道门禁，再统一更新
  `package.json`、`lib/index.js VERSION`、SKILL 元数据版本与 CHANGELOG 段落，最后 `npm pack` 到 `dist/`
  并打印 SHA-256；发布动作保持手动（脚本不执行 `npm publish`）。
- 新增 5 个 selftest 断言（持久化写入 / 回读 / 跨会话标记 / 删除 / resetBaseline 文案）；
  `dist/` 自带 `.gitignore`，tarball 不会误提交。
- 首次扫描不再误报「结论可能已过期」：没有结论时只显示「首次扫描进行中…」；
  版本号与扫描器版本解耦（插件 0.5.0 / 随包扫描器 0.4.0），测试改为校验入口 `VERSION` 与随包副本一致。
- 版本 **0.4.0 → 0.5.0**。

### 新增（落地加固：环境自检 / 降级提示 / 多会话根目录 / doctor）
- **Python 缺失不再“静默失效”**：宿主启动时后台探测 Python 与随包扫描器（不阻塞激活，60s 缓存，装好后无需重启即可恢复）；
  状态块直接显示「扫描器不可用：未找到 Python 3.11+」+ 修复方式；工具错误按“缺 Python / 路径 / 未知扫描器 / 超时”分别给处理提示
- **首次扫描可见进度**：首次扫描进行中显示「首次扫描进行中…」，不再误报“尚未扫描”
- **多会话默认根修正**：工具按**调用它的 agent 工作目录**解析默认路径（`exec.agent.session`），不再依赖“最近渲染的会话”；
  显式 `path` 仍优先，且不会污染后续调用
- **`install --check` 增加扫描器健康行**：显示实际使用的 Python 版本与解释器路径，或明确“没有 Python 3.11+”
- **新增 `scripts/doctor.mjs`**：一条命令检查 profile 链接 / 宿主加载 / 工具注册 / Python / 随包扫描器 / 清单 / 随包漂移 / 主机契约自检，
  失败时打印修复命令；支持 `--json`（`npm run doctor`）
- **npm scripts**：`validate` / `selftest` / `sync` / `doctor`；`npm pack --dry-run` 实测 86 files / 240 KB（解包 768 KB）
- 新增 11 条 selftest 断言（Python 健康、缺 Python 横幅、扫描器缺失横幅、首次扫描进度、工具未注册降级、多会话默认根）
- 说明：未在 CI workflow 里新增 job——新增的 Action 未固定 SHA 会被本行自己的 `SCP-007` 判定为新增问题，
  保持“不引入回归”的纪律，改为提供本地 `doctor` 供任意 CI 调用

### 新增（知识层：7 本领域手册 + 技能索引重构）
- 新增领域手册（`skills/provemark/references/`）：
  - `architecture-playbook.md`：边界与依赖方向、数据归属、同步/异步、一致性（outbox/saga/幂等）、缓存、伸缩与隔离、接口演进、何时不拆微服务、ADR 模板
  - `testing-playbook.md`：测试分层与成本、该测/不该测、契约替身、测试数据、flaky 治理、性质测试与对拍、CI 测试矩阵
  - `data-playbook.md`：schema 设计、索引与执行计划、事务与锁、expand-contract 迁移、备份恢复、数据质量、容量
  - `delivery-playbook.md`：提交/PR、CI 流水线、滚动/蓝绿/金丝雀/开关、回滚、可观测性门禁、依赖更新、事故响应
  - `debugging-playbook.md`：复现→二分→观察→假设的流程、故障签名表、并发/时钟/编码排查、postmortem 模板
  - `code-review-playbook.md`：评审顺序、diff 卫生、AI 代码评审重点（幻觉 API/过度抽象/只写 happy path）、评论方式、合并清单
  - `ai-collaboration.md`：任务与上下文怎么给、验证闭环、幻觉形态、停止条件、提示词模式、信任边界
- `SKILL.md` §8 索引重构为「工具与规则参考」+「领域手册」两组，共 11 本手册，按“遇到什么问题读哪本”组织
- 技能描述更新：知识层覆盖安全、全栈、算法、架构、测试、数据、交付、调试、评审、AI 协作

### 新增（算法与复杂度：AI-021 ~ AI-026 + 算法手册）
- 规则总数 113 → **118**；`ai` 维度覆盖到“算法复杂度反模式”
- 5 条可执行规则（跨行/单行判定，均有反例测试）：
  - `AI-021` 循环里逐条请求外部接口（同步 HTTP；异步循环已由 AI-016 覆盖）
  - `AI-022` 循环里 `+=` 拼接字符串（数值累加不误报）
  - `AI-024` 循环里 `pd.concat`（O(n²) 表复制）
  - `AI-025` 用 list 当队列（`pop(0)` / `insert(0, x)`）
  - `AI-026` `df.iterrows()` 逐行遍历（慢 1–2 个数量级）
- 新增 `references/algorithms-playbook.md`：数据规模判据、数据结构选型速查、经典算法关键点、
  数值/精度陷阱、算法反模式对照表、验证方法（对拍/性质测试/基准）
- 常驻提示词新增「复杂度」一条：按数据量选结构，循环里别做 O(n) 查找/拼接/重复排序/逐条请求
- 精度：`total += 1`（数值累加）、`deque.popleft()`、`await fetch`（异步）均不误报；
  本仓库自检只保留既有 `AI-008` info；flask / express / gin 零新增误报
- 新增 8 个算法规则测试；全量测试 **307 个通过**

### 新增（全栈工程规范：AI-015 ~ AI-020 + 全栈工程手册）
- 规则总数 107 → **113**；`ai` 维度从“AI 代码风险”扩展到“AI 代码风险 / 工程规范”
- 6 条可执行的工程规则（都能在源码里稳定识别，且有反例测试）：
  - `AI-015` 外部请求没有超时（`requests/httpx` 无 `timeout`、`fetch` 无 `signal`、`axios` 无 `timeout`）
  - `AI-016` 循环里串行 `await`（跨行判定；`await import` 不算）
  - `AI-017` 循环里发查询（N+1；异步循环已由 AI-016 覆盖，不重复报）
  - `AI-018` ORM 自动改库（`synchronize/dropSchema/force`，high）
  - `AI-019` Django 开放主机/CORS/CSRF（`ALLOWED_HOSTS=['*']` 等）
  - `AI-020` 用 `print/console.log` 当日志（CLI 文件跳过、测试降级、按文件聚合）
- 新增 `references/fullstack-playbook.md`：前端/后端/API/数据库/异步并发/部署/可观测性/测试的分层检查清单，
  以及“AI 高频工程反模式 → 后果 → 修法 → 规则”对照表
- 常驻提示词新增「工程常识」五条（契约与分页、超时与重试、迁移与 N+1、结构化日志、测试边界）
- 精度：flask / express / gin 实测零新增误报；本仓库只保留 1 条既有的 AI-008 info；
  规则对 `line.find(`、`"await"` 字符串、`await import(` 等做了显式排除
- 新增 `tests/test_engineering_rules.py`（20 个用例）；全量测试 **299 个通过**

### 新增（防退化棘轮：基线 + 趋势 + 维护纪律）
- 进程内第一次扫描某工作区时冻结**基线**；之后每次扫描比较 **新增/修掉** 的 finding，输出
  `baselineScore` / `newFindings` / `fixedFindings` / `trend` 四个字段（`provemark_guard` 与状态块都有）
- 判定联动：较基线**新增 critical/high → `blocking`**；只有中低 → 至少 `warn`。老项目基线差是允许的，
  棘轮只要求"不比进来时更差"——这正是防止"AI 越改越乱"的硬约束
- 状态块在结论后直接显示趋势（例如 `⛔ 较本会话基线 97 分变差：新增 2 条问题（VUL-001(a.py)…）`），
  模型在写最终答复前就能看到"这次改动让项目变差了"
- 提示词新增「维护纪律」四条：只改相关文件、一轮 ≤3–5 个文件、新增问题必须为 0、老项目分批修、
  不许用新 `ignore` 掩盖回归
- 新增技能文档 `references/maintenance-discipline.md`：大仓库维护协议、反模式清单、与 CI/门禁的关系、边界
- selftest 新增 7 条断言（基线比较的新增/修掉/分数差/文案 + 状态块携带趋势）；全量测试保持 279 通过

### 新增（代码安全：VUL-001 ~ VUL-018 + OWASP/CWE 知识库）
- 新扫描器 `security`（`--only security` / `--skip security`），补齐此前恒为 100 的 `security` 评分维度；
  规则总数 89 → **107**
- 18 条代码级规则，每条带 **CWE + OWASP Top 10 映射**（`detail.cwe` / `detail.owasp`，reference 指向 CWE 条目）：
  1. 注入：`VUL-001` SQL（py/js/go）、`VUL-002` 命令、`VUL-003` 模板、`VUL-005` XSS、`VUL-017` Actions 脚本注入
  2. 数据与访问：`VUL-004` 反序列化、`VUL-006` 路径穿越、`VUL-015` XXE
  3. 网络与认证：`VUL-007` SSRF、`VUL-010` TLS 校验关闭、`VUL-012` JWT 校验关闭、`VUL-013` Cookie 安全属性
  4. 密码学：`VUL-008` 弱哈希（安全语境升级 high）、`VUL-009` 弱随机、`VUL-011` 弱算法/模式
  5. 配置与其他：`VUL-014` 调试模式、`VUL-018` 容器提权/Docker socket、`VUL-016` C 危险字符串函数
- 精度设计：注释/文档字符串屏蔽（共用 `scanners/codemask.py`）；参数化 SQL、无安全语境的 MD5 校验和**不报**；
  测试命中降级（置信度 ≤0.5，TLS/调试类测试只保留 low）；同一文件同一规则聚合为一条（`detail.count`/`detail.locations`）
- 新增「安全实战」技能文档 `references/security-playbook.md`：判定顺序、CWE↔OWASP 对照、每类问题的标准修法、工具边界
- 系统提示词的红线新增「注入 / 认证与加密 / 对外请求与文件 / 配置」四组自检，模型写代码时就避开这些坑
- 新增 `tests/test_security_scanner.py`（31 个用例：18 条规则正例 + 9 个反例 + 聚合/降级/注册/映射）；
  全量测试 **279 个通过**；实测故意做坏的样例仓库可命中全部 18 类，flask/express/gin/本仓库无新增误报

### 新增（全程跟踪：改动后自动复扫 + 结论过期提示 + 会话账本）
- **改动触发复扫**：任何 `tool/result` 都把当前结论标为「可能过期」，并在 `changeDebounceMs`（默认 8s）
  后自动复扫；两次改动触发复扫至少间隔 `changeMinRescanMs`（默认 30s），连续编辑不会变成扫描风暴
- **过期提示**：复扫完成前，状态块首行出现 `⚠️ 自上次扫描后又有新的工具操作…`；模型在写最终答复那一步能看到它，
  不会拿旧结论宣布通过
- **会话账本**：状态块末尾累计「自动扫描 N 次 · 累计拦下高危 M 次」，让模型意识到这一路守过几轮
- 提示词文本保持稳定（不含每次变化的计数），避免每步都产生新的上下文快照
- 卸载时清理所有去抖/通知定时器（`ctx.effect` 收尾）
- 配置新增 `scanOnChange` / `changeDebounceMs` / `changeMinRescanMs`；selftest 新增 5 条断言

### 修复
- **默认扫描根会被显式路径带偏**：一次 `provemark_guard(path=别的仓库)` 之后，不带 `path` 的调用
  会继续扫那个仓库。现在默认根固定取「会话工作目录」，显式路径不再污染后续调用（selftest 有回归）
- `security` 规则对参数化 SQL 与无安全语境的 MD5 校验和不再误报（flask / gin / 本仓库实测零新增误报）

### 变更（插件默认联网）
- `provemark-guard` 默认 `offline: false`：后台自动扫描与 `provemark_guard` 默认查询 OSV.dev（依赖漏洞）
  与 deps.dev（依赖许可证），只发包名+版本，不传源码
- 超时随之调整：后台扫描 45s → 60s、工具调用 90s → 120s；`autoFix` 修复后的复扫也按同一联网设置
- 断网/代理不通时行为不变：漏洞与许可证标「未验证」、`score.reliable=false`、报告写明原因；
  `offline: true`（或 `.provemark.toml [network] enabled = false`）仍可完全禁网
- **联网失败现在会真正标注分数不可信**：`Context.network_failed` 由漏洞/许可证查询失败置位，
  `score.reliable = false`，并追加「联网查询失败：漏洞/许可证数据不完整，分数仅供参考」
  （此前只有“过半依赖版本未知”才会标不可信，89/B 可能被误读成健康）
- **缓存命中会明说**：「漏洞数据来自本地缓存（N 个依赖，查询缓存 6 小时），本次未联网校验」，
  避免把缓存结论当成刚校验过的
- 代理：扫描器走 `urllib`，自动继承 `HTTPS_PROXY`/`HTTP_PROXY`；文档补充了这条与缓存 TTL（查询 6h / 许可证 7d）

### 修复（来自真实项目实测：flask 3.1.3 / express 5.3.0 / gin v1.12.0 / serde 1.0.229）
- **崩溃**：Go / JS 的幻觉依赖记录缺少 `confidence` 字段，导致整条 AI 扫描器 `KeyError` 退出；
  现在补齐字段，聚合处也对缺失字段兜底（gin 之前整维度丢失）
- **Go 幻觉依赖误报**：go.mod 声明的是模块路径、import 是包路径；改为前缀匹配后，
  `golang.org/x/net/http2` 这类子包不再被判未声明（gin 的 7 条高危误报归零）
- **文档字符串 / 注释里的 import 不再当成真实依赖**：Python 三引号与 JS/Go 注释先被屏蔽
  （flask 文档里的 `from yourapplication import ...`、"import name of your application" 不再报）
- `if t.TYPE_CHECKING:` / `if typing.TYPE_CHECKING:` 块里的类型导入不再报幻觉依赖
- **许可证识别**：`LICENSE-MIT` / `LICENSE-APACHE` / `LICENSE.rst` / `COPYING.LESSER` 按前缀识别
  （serde 之前被误判「没有许可证」）
- **AI-003 抽象方法未实现**：默认级别 medium → info（基类 `raise NotImplementedError` 是正常写法）
- **SCP-002**：`dev` 作用域的 ruff/tox/pytest 等浮动版本降为 info；**SCP-001** 在
  `project.kind = "library"` 时降为 low（库不提交锁文件是常态），应用仍为 medium
- **测试文件识别**：新增 `*_test.go` / `test_*.py` / `*.test.ts` / `*.spec.js` / `*_test.rs` 与 `testdata/`；
  PII 扫描不再把 `pyproject.toml` / `package.json` 里的作者邮箱当个人数据
- **发布包识别**：根目录有 `PKG-INFO` / `.cargo_vcs_info.json` / `*.dist-info` 时，缺
  SECURITY.md / .gitignore / CI / 归因文件降为提示并写明原因（sdist/crate 本就不带这些）
- **依赖漏洞聚合**：同一「包 + 版本」的多条 OSV 公告合并为一条结论（附公告列表、最高严重度、
  建议升级版本，`DEP-004` 同理）；gin 在线扫描从 51 条公告降为 5 条结论
- 生成文件识别扩展：`*.pb.go` / `*.pb.gw.go` / `*.gen.go` / `zz_generated*`
- 新增 `tests/test_realworld_regressions.py`（14 个回归用例）；全量测试 246 个通过

### 新增
- DeepSeek Harness **常驻插件** `plugin/provemark-dsh/`：把扫描器变成开发过程中的守卫
  - `lib/index.js`：系统提示词段（编码红线）+ 动态上下文块（工作区扫描状态）+ 原生工具
    `provemark_guard` / `provemark_scan` + 后台扫描（会话首步 / 工具活动后，去抖 + TTL 缓存）
  - 新增高危/致命时向 agent 收件箱推送通知；`autoFix: apply` 只补缺失文件、不改业务代码
  - 宿主工具 API 解析：bare specifier → `process.resourcesPath/app.asar/**` → `app.asar.unpacked/**` 三级回退（linked 安装没有自己的 peer 解析）
  - 激活诊断：每次加载写 `<tmp>/provemark-dsh-loaded.json`（pid / 配置 / 各阶段结果 / 警告 / 扫描计数），`install.mjs --check` 直接读
  - `lib/python.js`：Python 发现与扫描器调用单点（CLI 启动器与工具共用）
  - `cordis.patch.yml`：两行 —— `provemark-guard`（本插件）+ `provemark-skill-filesystem`（技能）
  - `scripts/selftest.mjs`：无宿主的端到端自检（假的 `defineTool` 模块 + 真实扫描）
  - 技能新增 `references/tools.md`（工具参数 / 配置 / 自动行为 / 排障）
  - `tests/test_plugin.py`：包清单、两行 patch、技能 frontmatter、随包源码零漂移
- DeepSeek Harness 技能包（首版）`plugin/provemark-dsh/`

### 变更
- `bin/provemark.mjs` 改为复用 `lib/python.js`（不再重复实现解释器探测）
- `scripts/validate.mjs` 增加 host 插件契约检查（`apply()` 唯一导出、无静态宿主 import、两行 patch）
- 插件默认 `timeoutMs` 已随联网默认调整为 60000（后台扫描）/ 120000（工具）；超时/路径/其他错误现在给不同处理提示

### 修复
- `[scan] exclude` 与 vendored 归因的语义对齐：内置默认（`vendor/**` 等）只影响内容扫描，**用户显式排除**的树才跳过 `SCP-014/015`；`provemark vendored` 同样遵守（此前排除后仍报归因缺口）
- `is_excluded` 对 `dir/**` 现在也匹配目录本身（`dir`），不再要求末尾斜杠
- 插件工具：相对 `output` / `aiPrompt` 路径现在相对**被扫仓库**解析并自动建父目录（此前相对宿主进程 cwd）；非法 `format` / `autoFix` 会在 `notes` 里明说而不是静默替换；`only` 局部扫描会标注"分数只反映这些维度"
- 插件缓存按「路径 + `only` + 离线」分键：此前一个范围的结果可能被另一个范围复用（`--only ai` 之后问 `pii` 会拿到 ai 的结论）
- 未知扫描器（`only: "nope"`）现在返回 `verdict: "error"`；`provemark_scan` 不再把整份 markdown 报告灌进上下文（改为短回执 + 报告路径）
- `tests/test_cli.py` 两条缓存目录断言改用 `Path` 归一化（Windows 上不再因 `/tmp` vs `\tmp` 失败；本机全量 232 个测试首次全绿）

## [0.4.0] - 2026-10-27

### 新增
- 新增「敏感数据」维度（`PII-001` ~ `PII-006`）：邮箱、手机号、政府证件号
  （SG NRIC / 泰国身份证 / 印尼 NIK / 马来西亚 MyKad / 菲律宾 PhilSys）、
  银行卡号（Luhn 校验）、日志中拼接 PII、疑似真实数据快照
- 辖区由 `.pdp-compliance.json` 声明；未声明时只做通用格式识别，不做辖区判定
- PII 只输出掩码与位置（不保存原始值、不写缓存），并有测试断言序列化报告不含原文
- `[pii] enabled` 与 `--skip pii` 可整体关闭；测试目录命中降级为低置信度
- 新增许可证组合矩阵：`LIC-009` 报"项目许可证 × 依赖许可证"的确定冲突
  （如 Apache-2.0 依赖进入 GPL-2.0-only 项目），`LIC-010` 聚合无法自动判定的组合；
  `LIC-004` 在"策略禁止但组合兼容"时降为提示
- 新增 `provemark notices`：按依赖树生成 `THIRD_PARTY_NOTICES.md`，未知许可证单独列出，
  不覆盖手写文件；扫描新增 `HYG-014`（缺归因文件）与 `HYG-015`（归因漏包）
- `--offline` 现在会读取缓存里的许可证数据，不再无条件放弃许可证判定
- 新增 `provemark ai-usage`：生成 `AI_USAGE.md`（工具 / 范围 / 人工复核 / 留存），
  自动识别 CLAUDE.md、.cursorrules、copilot-instructions 等痕迹；新增 `AI-013` / `AI-014`
- 新增 `provemark vendored`：生成 `VENDORED.md`（目录 / 许可证 / 上游 / Commit），
  自动识别 vendored 目录与 LICENSE；新增 `SCP-014` / `SCP-015`
- **FOSSA 协同**：新增 `fossa` 扫描器与 8 条规则
  - `FOS-001` 多包仓库未限制分析范围；`FOS-002` vendored 目录未排除
  - `FOS-003` `fossa-deps` 条目不合规（类型 / 版本 / license / 路径）
  - `FOS-004` CI 只 `fossa analyze` 没有 `fossa test`；`FOS-005` 配置版本非 v3
  - `FOS-006` SBOM 与本地许可证结论冲突；`FOS-007` SBOM 补全未知许可证；`FOS-008` 覆盖率缺口
- `scan --sbom <file>`：读取 CycloneDX / SPDX JSON，与本地结论逐包对齐；根目录存在
  `sbom.json` / `bom.json` / `*.spdx.json` 时自动发现
- `provemark fossa-deps` 子命令：生成 `fossa-deps.yml`
  - `--mode missing`（默认）按「含 LICENSE 的最小目录」拆分 vendored 组件
  - `--mode all` 导出全部 FOSSA 支持的依赖，文件头带醒目重叠警告
  - 不覆盖手写文件、自身生成文件可重跑、`--print` 只预览
- 供应链规则 `SCP-012`（`pull_request_target` 检出 PR 代码）、`SCP-013`（`permissions: write-all`）
- GitHub Actions composite Action（`action/action.yml`）：安装 action 自身 ref、默认
  `fail-on=high` + `min-confidence=0.5`、可选上传 SARIF；manifest 有测试校验
- `scan --min-confidence 0-1`：命令行覆盖策略文件里的门禁置信度阈值

### 修复
- `fix --apply` / `init` 在离线或网络不稳定时会静默跳过 LICENSE（默认 Apache-2.0 文本走网络）。
  Apache-2.0 全文改为随包内置，写入不再依赖网络
- 配置中的数值字段（`max_files`、`max_file_bytes`、`timeout`）写成字符串时不再抛 `ValueError`，
  改为明确的配置错误提示
- 配置枚举字段（`gate.fail_on`、`scan.severity_floor`、`license.unknown`、`license.no_license`、
  `project.kind`、`[severity]` 覆盖值）非法时立即报错，不再静默降级或让扫描器整体失败
- `-o` 目标目录不存在时输出友好错误并返回退出码 2，不再抛 `FileNotFoundError`
- `--sbom` 指向不存在的文件时报错，不再静默忽略
- 缓存增加容量上限（20000 条），超出时按时间淘汰到 15000 条

### 变更
- 项目更名为 **Provemark（源印）**，原 RepoSentinel。包名、命令、配置文件、缓存目录、环境变量与默认产物统一改为 `provemark`；旧配置文件 `.reposentinel.toml` 与旧环境变量 `REPOSENTINEL_CACHE_DIR` 仍可读取，但不再写入
- 打包配置改用 `packages.find`，移除指向不存在目录的 `package-data`
- CI 单元测试扩展到 Python 3.11 / 3.12
- 门禁默认值确认为 `fail_on=high` + `min_confidence=0.5`（PRD Q1），并固化到 CLI、策略模板、
  `init` 生成的工作流、Action 四处

### 变更（检测算法）
- import → 包名解析改为「候选集推导」：原名、`_`/`-` 变体、去 `python-`/`py-` 前缀、
  去 `-python`/`-py` 后缀、命名空间根（`google-cloud-*` → `google`）、别名反查。
  修掉 `PIL` / `multipart` / `sklearn` / `google.cloud.*` 一类幻觉依赖误报
- 每条问题新增 `confidence`（0–1）：启发式规则不再与确定性规则等权
- 新增 `gate.min_confidence`（默认 `0.5`）：低置信度问题不阻断 CI，但仍出现在报告里并标注「需人工确认」
- 评分改为按置信度加权：`有效次数 = Σ confidence`，一条 `confidence=0.5` 的高危只扣 30% 的分；
  条数统计不受影响（不过滤、不少报）
- 高熵密钥的变量名词表扩充（`signing_key` / `encryption_key` / `hmac_key` / `master_key` / `session_key`）
- 凭据去重：同一密钥在多个文件/多行出现时合并为一条（保留全部位置，严重度取最高），不再刷屏
- base64 二次识别：字符串字面量若解码后命中凭据特征，同样报为泄漏（置信度 0.85，标明编码方式）；
  二进制/非可见内容、短于 20 字符、解码后无规则命中的一律不报
- 新增检测质量评测基准：17 个带标注的用例 + precision / recall 下限（0.85 / 0.90）

## [0.2.0] - 2026-10-26

### 新增
- **生态适配层** `ecosystems.py`：清单、锁文件、OSV 生态名、deps.dev 系统名、许可证来源统一注册
- 依赖解析从 4 个生态扩展到 19 个：Maven/Gradle/SBT/Clojure、NuGet（含 MSBuild `$(Property)` 与
  集中版本管理）、RubyGems、Packagist、pub、SwiftPM、Hex、CRAN、Hackage、Julia、CPAN、vcpkg、
  Conan、Conda、Deno、GitHub Actions
- 零依赖 YAML 子集解析 `yaml_lite.py`（用于 `pubspec.yaml` / `environment.yml` / `.fossa.yml`）
- 许可证来源扩展到 10 个：deps.dev 7 个系统 + PyPI / npm / crates.io / Packagist / RubyGems /
  Hex / CRAN / Hackage / Maven Central POM / NuGet nuspec
- 控制台新增「技术栈」概览
- 18 个生态解析 fixture + CI 动态矩阵（按目录自动生成，新增生态无需改 YAML）

### 修复
- `REPLACEMENT` 等标识符被误判为占位密钥（AI-001），跨语言误报清零
- `builder` vs `jbuilder` 被误判为仿冒包（`SCP-004`），改为要求首字母一致
- 无 `.env` 的仓库不再报高危 `HYG-005`
- Ruby 库（有 gemspec）与 Composer 库（`type: library`）不再误报「缺少锁文件」
- Maven BOM / NuGet 中央版本管理的依赖不再误报「未指定版本约束」

## [0.1.0] - 2026-10-25

### 新增
- 6 个扫描器：仓库卫生、凭据泄漏、AI 代码风险、依赖漏洞、许可证、供应链，共 65 条规则
- 评分与等级（致命不设上限、单维度封顶 25）、`--fail-on` 门禁、带过期的基线豁免
- 输出格式：终端表格 / JSON / Markdown / SARIF 2.1.0 / 自包含 HTML
- `scan` / `init` / `fix` / `ignore` / `explain` / `rules` / `hook` 子命令
- `--ai-prompt` 生成可交给编码代理的修复指令
- 凭据脱敏、OSV 漏洞查询、deps.dev 许可证查询、离线降级
