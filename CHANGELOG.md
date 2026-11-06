# 更新日志

本文件记录所有版本变更，格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

## [未发布]

### 新增（Python 锁文件解析：让漏洞检查真正跑起来）

- **`uv.lock` / `poetry.lock` / `pdm.lock` / `Pipfile.lock` 解析器**。此前 `ecosystems.py` 把这四个文件列为锁文件，
  却没有对应解析器——于是 `uv.lock` 锁了 213 个包的 fastapi 被报成「79 个依赖版本无法确定」「没有锁文件」，
  漏洞维度全空。现在能解析出 228 个依赖，命中 6 个真实 OSV 漏洞（4 个高危）。
- 锁文件里的非 registry 来源（git / url / path）打上 `url:` / `file:` 前缀，不进 OSV 查询。
- 锁文件依赖标记为间接依赖（`direct=False`），避免 typosquat 规则全量误报。

### 修复（误报治理：真实仓库暴露出来的假警报）

- **HYG-007 按内容判定**。此前 `.npmrc` / `.pypirc` / `.netrc` / `credentials.json` 等凭据文件**只看文件名**，
  于是只写了 `package-lock=false` 的 `.npmrc` 被判「致命：凭据泄漏」。现在读取内容，确实有 token/password 才报；
  私钥文件名与私钥后缀仍无条件报。
- **测试目录里的凭据降级**。`tests/certs/**` 里的过期测试证书此前按真实泄漏计致命，能把整个仓库打成 0 分 F。
  现在降为「高危 · 需人工确认」，仍然报出来；仓库外的真实凭据保持致命。
- **SPDX 别名补齐**。PyPI 元数据里的 `BSD License` / `Apache Software License` / `GNU General Public License v3`
  之前无法归一化，导致已知许可证被报成「无法确定」。
- **PII-004 语境感知**。19 位数字（LinkedIn ID 之类）恰好过 Luhn 就被判「银行卡号，建议立即轮换支付凭证」——
  现在 URL、路径、提交 SHA 里的数字不报。
- **HYG-003 大小写与子目录**。`.github/security.md` 此前被判「缺少 SECURITY.md」。
- **HYG-011 测试文件识别**。`test.js` 这类命名此前匹配不到，会误报「没有找到测试文件」。

### 修复（生成物不该违反自己的规则）

- `init` 生成的 CI 模板此前用 `actions/checkout@v4`、`upload-sarif@v3`（**v3 已被 GitHub 退役**），
  而且用工具自己扫会命中 3 条 `SCP-007`。现在全部固定到 commit SHA 并升级到 `upload-sarif` v4。
- `init` 生成的安装来源此前是 `pip install provemark`，而 PyPI 上并没有这个包（CI 第一步必失败）。
  现在指向可用的 git 标签，并保留注释说明将来上架后如何改回。
- 仓库自带 composite Action 的依赖同样固定到 SHA。
- `fix --only` 增加合法值校验：拼错时明确报错并列出可选值，不再静默什么都不做。

### 修复（插件）

- **自检竞态**：工具注册是异步的（先动态导入宿主工具模块），自检却固定 `sleep(300)`，
  慢机器上必然失败——同一份代码在 Python 测试里通过、命令行跑却失败。改用确定性等待。
- `package.json` 补齐发布字段：`author` / `repository` / `homepage` / `bugs` / `publishConfig.access`。

### 文档

- README 重写：突出 DSH 插件定位（结论直接进上下文，**423 字符**替代模型自行翻找文件的开销），
  并加入**真实开源仓库的实测案例**（fastapi / click / slugify）与误报治理对照表。
- 架构图与技能文档里的规则数改为实测值（AI 25 条）。

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
