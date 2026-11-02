# 常驻守卫：工具、配置与自动行为

插件装上后不是"用户想起来才用"的技能，而是**常驻在会话里**的三件东西：

| 组成 | 机制 | 什么时候生效 |
| --- | --- | --- |
| 编码红线 | 系统提示词段 `provemark:guardrails`（静态） | 每一步都在，引导模型**写的时候**就避开问题 |
| 工作区状态 | 动态上下文块 `provemark:workspace-state` | 只在扫描结果变化时更新，避免每步刷 token |
| 原生工具 | `provemark_guard` / `provemark_scan` | 模型主动调用，或按提示词要求调用 |
| 后台扫描 | 会话首步 + 工具活动后（去抖 + 缓存） | 自动，不阻塞当前步骤 |

## 工具

### `provemark_guard`（默认用它）

参数：

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `path` | 会话工作目录 | 要扫描的仓库根 |
| `only` | 全部 | `repo, secrets, pii, security, ai, dependency, license, supply, fossa` 逗号分隔 |
| `offline` | 插件配置（默认 `false`，即联网） | 传 `true` 跳过 OSV / deps.dev 查询（断网、隐私要求、只想要秒级结果时用） |
| `maxFindings` | 插件配置（默认 5） | 1–20 |
| `autoFix` | 插件配置（默认 `preview`） | `off` / `preview` / `apply`；`apply` 只补缺失文件，不改业务代码 |
| `fresh` | `false` | 忽略缓存，立刻重扫 |
| `resetBaseline` | `false` | 把当前结果设为新基线（在你**明确接受**现状后用；否则基线会一直保留） |

返回：`verdict`（`clean` / `warn` / `blocking` / `error`）、`score` / `grade` / `reliable`、`counts`（critical/high/medium/low/info）、`findings[]`（rule/severity/title/path/line/confidence/remediation/fingerprint/autoFixable）、`autoFixable[]`、`notes[]`、`message`、`durationMs`、`cached`；以及**基线对比**：`baselineScore`、`newFindings`、`fixedFindings`、`trend`（一句话趋势）。

判定口径与 CLI 门禁一致：**有 critical 或 high 即 `blocking`**；另外，**较本会话基线新增 critical/high 时也会 `blocking`**（防止"越改越糟"）。

几个必须知道的行为：

- **棘轮（防退化）**：第一次扫描某工作区时冻结基线，并**持久化**在 `~/.dsh/provemark-dsh/baselines.json`（可用
  `PROVEMARK_DSH_BASELINE_FILE` 覆盖，`persistBaseline: false` 关闭）。重启宿主后 `trend` 仍与跨会话基线比较，
  文案会写「跨会话基线」；确认接受现状后用 `resetBaseline: true` 重置。
  `trend` 出现「新增 X 条」→ 先回退或修掉再继续；`newFindings > 0` 时不要做无关改动。老项目基线差是允许的，只要求"不比进来时更差"。
- **局部扫描不等于整仓结论**：传了 `only` 时，`notes` 会明确写"分数只反映这些维度"——转述时不要把局部分数说成整仓分数。
- **缓存按范围分键**：`路径 + only + 是否离线` 不同就是不同的结果，不会拿"上次全量/上次 ai"的缓存回答"这次 pii"。改完代码要立刻看结果时传 `fresh: true`。
- **未知扫描器**（如 `only: "nope"`）返回 `verdict: "error"` 并带 CLI 的「未知扫描器」提示，**不是通过**。
- **非法 `autoFix`** 不会静默生效：`notes` 会说明按哪个值处理（默认是 `preview`）。
- **缓存**：同一范围在 `cacheTtlMs` 内复用；`fresh: true` 强制重扫。
- **超时**：默认 120s（后台）/ 180s（工具）。4k+ 文件的大仓库可能接近 1 分钟；超时返回 `verdict: "error"` 并提示用 `only` 缩小范围，不要据此宣布通过。
- **联网是默认**：后台扫描会查 OSV.dev（漏洞）与 deps.dev（许可证），只发包名与版本。
  - 断网/代理不通：`notes` 写「联网查询失败：漏洞/许可证数据不完整」，并且 `score.reliable = false`——**必须**说"分数仅供参考"，不能说没有漏洞；
  - 命中本地缓存：`notes` 写「漏洞数据来自本地缓存（N 个依赖，查询缓存 6 小时），本次未联网校验」，这时结论可用，但要注明不是刚刚联网校验的；
  - 完全离线（`offline: true`）：`notes` 写「离线模式：N 个依赖未做漏洞查询」，`reliable` 视依赖版本覆盖率而定。
- **代理**：继承 `HTTPS_PROXY` / `HTTP_PROXY` 环境变量；公司网络下先确认这两个变量，或改用 `offline: true`。
- **错误分类**：路径不存在/不是目录 → 提示改 `path`；超时 → 提示缩小范围；其他 → 提示确认 Python/扫描器。

### `provemark_scan`（出报告 / 单维度 / 门禁对齐）

| 参数 | 说明 |
| --- | --- |
| `format` | `json` / `html` / `markdown` / `sarif`（默认 markdown） |
| `output` | 报告路径；相对路径相对被扫仓库，父目录会自动创建 |
| `only` / `skip` / `offline` / `verbose` | 同 CLI |
| `failOn` | `none/low/medium/high/critical`，命中时 `exitCode: 1` |
| `aiPrompt` | 生成给编码代理的修复指令文件 |
| `sbom` | 交叉核对 CycloneDX / SPDX JSON |

返回：`root`、`reportPath`、`exitCode`、`verdict`、`message`（短回执：门禁结论 + 报告路径 + CLI 摘要尾部，**不会把整份报告灌进上下文**；要完整内容就传 `output=`）。

## 配置（写在 profile 的 `cordis.patch.yml` 里覆盖）

```yaml
- id: provemark-guard
  name: 'provemark-dsh'
  config:
    enabled: true
    autoScan: true              # 后台自动扫描
    offline: false              # 默认联网：OSV 漏洞 + deps.dev 许可证
    autoFix: preview            # off | preview | apply
    maxFindings: 5
    autoScanIntervalMs: 120000  # 同一根目录两次后台扫描的最小间隔（10s–1h）
    cacheTtlMs: 300000          # 工具复用缓存的时间窗
    scanOnChange: true          # 工具活动后自动复扫
    changeDebounceMs: 8000      # 复扫去抖（一串编辑合成一次）
    changeMinRescanMs: 30000    # 改动触发复扫的最小间隔（防扫描风暴）
    timeoutMs: 120000           # 单次后台扫描超时（4k+ 文件的大仓库需要 1–2 分钟）
    toolTimeoutMs: 180000       # 单次工具调用超时
    injectOnNewRisk: true       # 后台扫描发现新的 high/critical 时推一条收件箱消息
    injectMinSeverity: high
    workspace: ""               # 强制根目录；空 = 用会话工作目录
    logPrefix: '[provemark]'    # 置空可静默
```

## 自动行为的确切边界

- **首步扫描**：会话里第一次组装提示词时，如果配置 `autoScan`，对一个可扫描的工作区根启动一次后台扫描（不阻塞）。
- **改动后重扫（全程跟踪）**：任何 `tool/result` 都会把结论标成「可能过期」，并在 `changeDebounceMs`（默认 8s）后复扫；
  两次改动触发复扫之间至少有 `changeMinRescanMs`（默认 30s），所以连续几十次编辑不会变成几十次扫描。
- **过期提示**：在复扫完成前，状态块**首行**会出现 `⚠️ 自上次扫描后又有新的工具操作…`——看到它就不该拿下面的旧结论宣布通过。
- **会话账本**：状态块末尾会累积「自动扫描 N 次 · 累计拦下高危 M 次」，让模型知道本会话已经守过几轮。
- **不扫的根**：文件系统根（`C:\`、`/`）和用户主目录会被拒绝——守卫不该变成性能事故。
- **缓存**：同一根目录的扫描结果在 `cacheTtlMs` 内复用；工具调用可以 `fresh: true` 强制重扫。
- **风险通知**：后台扫描发现**新增**的 high/critical 时，向 agent 收件箱推一条消息（每会话最多 10 分钟一次），下一次模型步骤可见。
- **不写文件**：除非 `autoFix: apply` 或工具显式传 `autoFix: "apply"`。安全修复只新增 LICENSE / .gitignore 条目 / SECURITY.md / .provemark.toml / CI 工作流，绝不改业务代码。

## 排障

| 现象 | 处理 |
| --- | --- |
| 模型看不到 `provemark_guard` | 宿主没加载插件行。重启宿主；或检查 profile `package.json` 的 `dsh.profile.bundles` 里有 `provemark-dsh`，且 `cordis.patch.yml` 里 `provemark-guard` 行不是 `disabled: true` |
| 上下文块一直是「尚未扫描」 | `autoScan: false`、或工作区根被拒绝（`C:\`、`~`）、或 Python 不可用。跑 `node "<PM>\bin\provemark.mjs" --pm-info` 确认 |
| 后台扫描失败但工具能用 | 后台扫描走 `timeoutMs`（默认 120s），4k+ 文件或联网慢时可能超时；调大它，或把 `autoScan` 关掉只用工具 |
| 结果里全是「未验证」「漏洞数据不可用」 | 网络/代理不通。设 `HTTPS_PROXY`/`HTTP_PROXY` 后重试；确认不是公司网络拦了 `api.osv.dev` / `deps.dev`；短期可 `offline: true` 让行为可预期 |
| 觉得提示词太长 | 把 `logPrefix` 置空不解决问题；真正占 token 的是状态块。把 `maxFindings` 调到 2–3，或 `autoScan: false` 只用工具 |
| 宿主启动报 patch 错误 | 先禁用本插件行（`- id: provemark-guard, disabled: true`）让宿主起来，再跑 `node scripts/selftest.mjs` 定位 |
