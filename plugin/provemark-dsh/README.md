# provemark-dsh

把 [Provemark（源印）](../../README.md) 打包成 **DeepSeek Harness 常驻插件**：装上之后，只要在这个 profile 里开发，守卫就在——**引导模型写更安全的代码、自动扫、能自动修的自动修、修不了的给建议**。

- 扫描器随包分发（`python/provemark`），**不需要 `pip install`**，零第三方运行时依赖；
- **默认联网**：后台扫描会查 OSV.dev（依赖漏洞）与 deps.dev（依赖许可证），只发包名与版本，不传源码；
  断网时自动降级为「未验证」并在结论里明说，不会假装没有漏洞；
- 118 条规则 / 8 个维度 / 19 个生态；报告支持 table / JSON / Markdown / SARIF / 单文件 HTML。

## 它做了什么

| 组成 | 机制 | 效果 |
| --- | --- | --- |
| **编码红线** | 系统提示词段 `provemark:guardrails` | 每一步都在，模型写代码时就避开幻觉依赖、硬编码密钥、`except: pass`、危险调用、**注入/认证/加密/SSRF/XXE/容器配置**、PII、许可证与供应链坑 |
| **代码安全** | `VUL-001` ~ `VUL-018`（每条带 CWE + OWASP 映射） | SQL/命令/模板注入、反序列化、XSS、路径穿越、SSRF、弱哈希/随机/加密、关闭 TLS 校验、JWT 校验关闭、XXE、C 危险函数、Actions 脚本注入、容器提权；配套 `references/security-playbook.md` 讲判定顺序与修法 |
| **工作区状态** | 动态上下文块 `provemark:workspace-state` | 只在扫描结果变化时更新（不刷 token）：分数/等级/各严重度计数 + Top 3 + 可自动修项；**改动后首行出现「⚠️ 结论可能已过期」** |
| **原生工具** | `provemark_guard`（快、默认联网、带缓存）、`provemark_scan`（出报告/单维度/门禁） | 模型按提示词要求主动调用，不需要 shell |
| **后台扫描** | 会话首步 + 工具活动后（8s 去抖、最短 30s 一次） | 自动，不阻塞当前步骤；发现**新增**高危/致命时推一条收件箱消息 |
| **全程跟踪** | 会话账本（自动扫描次数 / 累计拦下的高危次数） | 模型能知道自己这一路守过什么，过期结论不会被当成最新结论 |
| **防退化棘轮** | 首次扫描冻结基线，之后每次扫描比较新增/修掉 | `trend` 一句话说明"比进来时变好还是变差"；新增 critical/high 直接 `blocking`，防止 AI 越改越糟；老项目基线差是允许的，只要求不比进来时更差 |
| **安全自动修复** | `autoFix: apply` | 只补缺失的 LICENSE / .gitignore 条目 / SECURITY.md / .provemark.toml / CI 工作流，**绝不改业务代码** |
| **技能** | `provemark` skill | 深度工作流 + **11 本领域手册**（安全/全栈/算法/架构/测试/数据/交付/调试/评审/AI 协作/维护纪律）按需加载 |

判定口径与 CLI 门禁一致：**有 critical 或 high 即 `blocking`**。不会替模型"宣布通过"——`blocking` 必须修或如实说明。

## 前置条件

- **Node**：`^22.19.0 || >=24.0.0`（DSH 自带）。
- **Python 3.11+ 或 DSH 自带运行时**（用于跑随包扫描器；不需要 `pip install`）。
  没有 Python 时插件不会崩，但**扫描不可用**：状态块会显示「扫描器不可用：未找到 Python 3.11+」并给出修复方式。
- Windows / macOS / Linux 均可；安装脚本在 Windows 用 junction、其它平台用目录符号链接，`--copy` 适用于只读/跨卷目录。

## 兼容性

| 项 | 声明 | 生效位置 |
| --- | --- | --- |
| DSH 宿主版本 | `dsh.engines.dsh: ">=0.2.2-rc.1"`；`dsh.compatibility.dshReleases["0.2.2-rc.1"] = compatible` | 插件管理器在安装/激活前按 `engines.dsh` 校验，不满足直接拦住，而不是装上一半 |
| 宿主工具 API | `dependencies` / `optionalDependencies` 必须为空；`@deepseek-ai/dsh-tools` 在运行时动态 import | 本包不 vendor 宿主模块，也不需要 `npm install` / `pip install`（扫描器随包分发）；解析不到时退化为「只有提示词守卫、没有工具」，不让宿主起不来 |
| Node | `engines.node: "^22.19.0 || >=24.0.0"` | 与 DSH 桌面端自带 Node 一致 |
| 实测环境 | DSH `0.2.2-rc.1` + Node `24.21.0` + Python `3.14.7`（Windows 11） | `doctor` 九项全绿；插件 `selftest` 与仓库 `pytest`（325 项）全过 |

## 安装

profile 目录默认 `%USERPROFILE%\.dsh\profiles\<profile>`（macOS/Linux: `~/.dsh/profiles/<profile>`）。

### 方式一：用 Harness 自带的插件管理器（生态标准路径）

本包是标准 DSH bundle（`package.json` 的 `dsh.bundle.patch` 指向 `cordis.patch.yml`），
所以可以直接被 Harness 的 `plugin_manager` 装进当前 profile，不必手工改任何 profile 文件：

```text
plugin_manager action=install_bundle target=<本包绝对目录>   # 例如 F:\扫描神器\plugin\provemark-dsh
plugin_manager action=remove_bundle target=provemark-dsh    # 卸载
# 安装结果是 applied 才算生效；这一步会改 profile 的 package.json / cordis 组合并重启插件行
```

`install_bundle` 会自己完成「链接进 `<profile>/node_modules` → 写 `dependencies` → 追加 `dsh.profile.bundles`」，
不写 profile 之外的任何用户文件；审批由 Harness 的权限模型负责。

### 方式二：仓库内安装脚本（CI / 无 UI 环境）

```pwsh
node .\plugin\provemark-dsh\scripts\install.mjs            # 默认 desktop，或唯一的 profile
node .\plugin\provemark-dsh\scripts\install.mjs --profile web
node .\plugin\provemark-dsh\scripts\install.mjs --check    # 自检：解析 / 技能文件 / 随包源码 / patch 行 / Python
# 重启 DeepSeek Harness —— 插件行与技能行都在启动时组合
```

装完后跑一次 **doctor**，一条命令确认“真的能用”：

```pwsh
node scripts\doctor.mjs        # profile 链接 / 宿主加载 / 工具注册 / Python / 随包扫描器 / 清单 / 漂移 / 自检
node scripts\doctor.mjs --json # CI 或脚本消费
```

安装做的事：

| 位置 | 变更 |
| --- | --- |
| `<profile>/node_modules/provemark-dsh` | 指向本目录的链接（Windows junction / 其它平台目录符号链接），`--copy` 可改为复制 |
| `<profile>/package.json` | `dependencies["provemark-dsh"] = "link:…"`，并在 `dsh.profile.bundles` 追加 `provemark-dsh`（首次写入前备份为 `package.json.provemark-backup`） |
| 插件自身 | 不写任何用户文件 |

宿主加载本包的 `cordis.patch.yml`，插入两行：`provemark-guard`（本插件，见 `lib/index.js`）和 `provemark-skill-filesystem`（把 `skills/` 作为技能根）。`bundledSkillDir` 用 `!!js` 从 `baseUrl` 解析包身份，不写死路径。

## 验证

```pwsh
node scripts\validate.mjs     # 静态检查：清单 / 两行 patch / SKILL.md / 随包源码
node scripts\selftest.mjs     # 无宿主的端到端自检：模拟 ctx，跑真实扫描、两个工具、缓存、事件钩子
node scripts\install.mjs --check   # 安装状态 + 运行中宿主是否真的加载过本插件
node bin\provemark.mjs --pm-info   # 用了哪个 Python、扫描器在不在
```

`selftest.mjs` 用假的 `defineTool` 模块（`PROVEMARK_DSH_TOOLS_MODULE`）在没有宿主的情况下跑通整条链路，所以改了插件逻辑可以先在这里回归，不必拿宿主当测试环境。

### 运行中诊断

插件每次激活都会写 `%TEMP%\provemark-dsh-loaded.json`（POSIX：`$TMPDIR`），记录 pid、配置、各阶段结果：

```json
{ "pid": 9132, "version": "0.4.0",
  "diag": { "stages": {
      "section": "ok", "context": "ok",
      "toolsImport": "ok: file:///…/app.asar/dsh/node_modules/@deepseek-ai/dsh-tools/lib/index.js",
      "toolsRegistration": "ok: provemark_guard, provemark_scan" },
    "warnings": [], "scans": 3, "lastScan": { "score": 80, "grade": "B" } } }
```

`install.mjs --check` 会把这份记录摘出来显示（`loaded:` 一行）。工具没出现时先看 `toolsImport` / `toolsRegistration`。

### 发布（0.5.0 起）

```pwsh
node scripts\release.mjs --version 0.5.1 --dry-run   # 预演：只打印将要改什么
node scripts\release.mjs --version 0.5.1             # 门禁 + 改版本 + 打包到 dist/
node scripts\release.mjs --version 0.5.0 --repack    # 只重打当前版本的 tarball
```

发布脚本先跑 validate / `sync-vendor --check` / selftest 三道门禁，然后统一更新 `package.json`、
`lib/index.js VERSION`、`SKILL.md metadata.version` 与 CHANGELOG（把 `[未发布]` 变成 `[版本] - 日期`），
最后 `npm pack` 到 `dist/` 并打印 SHA-256。**发布动作保持手动**：脚本不执行 `npm publish`。

**为什么 linked 安装也能拿到宿主模块**：本包没有 `node_modules`（junction 到仓库），所以 `import('@deepseek-ai/dsh-tools')` 在某些宿主上解析不到；插件按顺序尝试 bare specifier → `process.resourcesPath/app.asar/...` → `app.asar.unpacked/...`，哪个成功就记在 `toolsImport` 里。失败则退化为"只有提示词守卫、没有工具"，不会让宿主起不来。

## 用起来是什么样

装好并重启后，模型会在每一步看到编码红线，并在改动后自动拿到扫描结论。也可以显式调用：

| 工具 | 用途 |
| --- | --- |
| `provemark_guard` | 快速体检：`verdict` + 分数 + Top N（`文件:行` + 修法 + fingerprint）+ `autoFixable`。参数 `path` / `only` / `autoFix` / `offline` / `maxFindings` / `fresh` |
| `provemark_scan` | 出报告（`html`/`markdown`/`sarif`/`json`）、只跑一个维度、`--sbom` 对齐、`--fail-on` 门禁、`--ai-prompt` 生成修复指令 |
| `provemark_progress` | 读本地扫描历史：单项目的分数时间线 / 已修复 / 仍打开 / 复发，或 `all=true` 跨项目汇总；`action="dashboard"` 在工作区内生成单文件 HTML 仪表盘（图表内联、不联网） |

**进度账本**：每次**完整**扫描都会往 `~/.cache/provemark/history.jsonl` 追加一条记录
（分数、各级别计数、文件/依赖数、问题指纹与相对路径；不含源码和证据文本）。局部扫描
（`only` / `skip`）刻意**不**入账，否则时间线会混进"只看 PII"的分数。插件调用扫描时会带
`--history-source dsh` 标记来源，CLI 手工扫描标记为 `cli`。

技能里的 `<PM>` 命令行入口仍然可用（CI、脚本、没有工具时）：

```pwsh
node "<PM>\bin\provemark.mjs" scan . --offline
node "<PM>\bin\provemark.mjs" scan . --ai-prompt fix.md --test-command "pytest -q"
node "<PM>\bin\provemark.mjs" progress .          # 单项目进度
node "<PM>\bin\provemark.mjs" progress --all      # 跨项目
node "<PM>\bin\provemark.mjs" dashboard -o progress.html
```

## 配置

在 profile 的 `cordis.patch.yml` 里按 id 覆盖（不要改本包里的文件，升级会覆盖）：

```yaml
- id: provemark-guard
  name: 'provemark-dsh'
  config:
    enabled: true
    autoScan: true              # 后台自动扫描
    offline: false              # 默认联网：OSV 漏洞 + deps.dev 许可证
    autoFix: preview            # off | preview | apply（apply 只补缺失文件）
    maxFindings: 5
    autoScanIntervalMs: 120000  # 同根目录两次后台扫描最小间隔（10s–1h）
    cacheTtlMs: 300000          # 工具复用缓存窗口
    scanOnChange: true          # 工具活动后自动复扫（全程跟踪）
    changeDebounceMs: 8000      # 复扫去抖：一串编辑合成一次
    changeMinRescanMs: 30000    # 改动触发复扫的最小间隔：防扫描风暴
    persistBaseline: true       # 基线持久化到 ~/.dsh/provemark-dsh/baselines.json（跨重启的棘轮）
    timeoutMs: 120000           # 后台扫描超时（4k+ 文件的大仓库需要 1–2 分钟）
    toolTimeoutMs: 180000       # 工具调用超时
    injectOnNewRisk: true       # 新增 high/critical 时推收件箱消息
    injectMinSeverity: high
    workspace: ""               # 强制根目录；空 = 会话工作目录
    logPrefix: '[provemark]'    # 置空可静默
```

拒绝扫描文件系统根（`C:\`、`/`）和用户主目录——守卫不该变成性能事故。

## 包结构

```text
provemark-dsh/
├── package.json            # main → lib/index.js；dsh.bundle.patch → cordis.patch.yml；icon → icon.svg
├── cordis.patch.yml        # 两行：provemark-guard（本插件）+ provemark-skill-filesystem
├── icon.svg                # 插件图标（Plugin Manager 读，不激活也能显示）
├── locale/{en,zh}.json     # meta.title / meta.description，中英各一份
├── lib/
│   ├── index.js            # apply(ctx, config)：提示词段 / 动态上下文 / 两个工具 / 后台扫描
│   ├── python.js           # Python 发现 + 一次性运行扫描器（bin 复用同一份）
│   ├── scan.js             # 扫描、分类、缓存、安全修复
│   ├── format.js           # 编码红线 + 状态块 + 工具渲染
│   └── config.js           # 配置归一化
├── bin/provemark.mjs       # CLI 启动器（技能里的命令行入口）
├── python/provemark/       # 随包分发的扫描器（scripts/sync-vendor.mjs 同步）
├── skills/provemark/       # 技能：SKILL.md + 7 份参考（含 tools.md）
└── scripts/                # install / uninstall / sync-vendor / validate / selftest
```

## 维护

扫描器以仓库根的 `provemark/` 为准，插件里的 `python/provemark` 是只读副本：

```pwsh
node plugin\provemark-dsh\scripts\sync-vendor.mjs          # 改动后同步
node plugin\provemark-dsh\scripts\sync-vendor.mjs --check  # 漂移检查（漂移返回 1）
```

改 `SKILL.md` / `references/` 不需要同步；改 `lib/` 后重启宿主（替换已安装包需要重新加载模块世代）。

## 安全与边界

- 插件的网络请求全部来自随包扫描器：**只发包名与版本**（OSV.dev / deps.dev），不传源码、不上传文件；
- 代理：扫描器走 `urllib`，自动遵循 `HTTPS_PROXY` / `HTTP_PROXY` 环境变量（DSH 进程继承即可）；
- 断网 / 代理不通时自动降级：漏洞与许可证标为「未验证」，`score.reliable = false`，报告里写明原因，
  **不会**把"查不到"说成"没有漏洞"；此时可用 `offline: true` 让行为可预期、速度更快；
- 缓存：漏洞查询 6 小时、公告 30 天、许可证 7 天（`~/.cache/provemark`），重复扫描不会重复打网络；
  命中缓存时结论里会注明「来自本地缓存，本次未联网校验」，不会冒充刚刚联网校验的结果；
- `autoFix: apply` 是唯一会写文件的行为，且只新增缺失文件；不覆盖已存在文件、不改业务代码；
  且拒绝通过符号链接写入（`fix --apply` 会跳过指向仓库外的链接目标/父目录）；
- **扫描结果是不可信数据**：扫描对象可能是别人给的仓库，所以文件路径、标题、说明进入模型上下文前都会
  压平成单行并包进 `<untrusted-scanned-repo>` 边界，伪造的边界标签会被剥掉——仓库不能靠文件名伪造一段系统提示；
  工具输出、动态状态块、收件箱通知、`provemark_scan` 回执都走同一条渲染路径；
- **写盘范围受限**：`provemark_scan` 的 `output` / `aiPrompt` 只允许落在会话工作区或系统临时目录内
  （相对路径必须留在工作区内，符号链接会被解析后重新校验）；扫描根目录不是写盘锚点，
  所以「把某个目录当 path 扫一遍」不会变成往那里写文件的能力；
- **仓库策略豁免不再隐形**：仓库自己的 `.provemark.toml` 用 `[[ignore]]`/基线把问题压掉时，
  守卫会在结论里写明「豁免了 N 条问题（未计入分数）」，不会把"策略压干净"当成"没问题"；
- `install.mjs` 会改 profile 的 `package.json`（留备份）。撤销：`node scripts/uninstall.mjs`。

## 图标与本地化

| 资源 | 用途 |
| --- | --- |
| `icon.svg` | 插件图标（512×512，原创）：深墨色圆角瓦片 + 一枚略微倾斜的「印花」印章，印章里是刻出来的对勾——「印」对应源印，对勾对应守卫判定。另有 Q 版「大肥鱼」人物方案留在 `docs/assets/icon-alt-mascot.svg`（同样原创）：想换回去时把它复制到本包根目录，再把 `package.json` 的 `icon` 指向该文件名即可（图标必须在包内） |
| `locale/en.json`、`locale/zh.json` | `meta.title` / `meta.description`：插件列表里显示的名字与一句话能力说明，中英各一份，`exports` 里导出 `./locale/*.json` |

`scripts/validate.mjs` 会校验：图标存在、≤256 KiB、是合法 SVG 根元素、不含脚本/远程引用、`files[]` 真正打包；
本地化文件齐备且 `meta.title`/`meta.description` 非空——这些都是"装了却显示空白"的典型原因。

## 许可

Apache-2.0，与仓库根 `LICENSE` 一致。
