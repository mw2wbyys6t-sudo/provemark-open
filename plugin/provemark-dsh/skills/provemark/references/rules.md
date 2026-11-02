# 规则目录（118 条）

级别是**默认值**，可被策略文件覆盖。`explain <ID>` 可拿到单条规则的判定逻辑与修法。

先分清三套名字，它们不是一回事：

| 名字 | 用途 | 取值 |
| --- | --- | --- |
| **扫描器**（`scan --only/--skip`） | 决定跑哪个扫描模块 | `repo, secrets, pii, security, ai, dependency, license, supply, fossa`（9 个） |
| **`rules --category`** | 过滤规则清单 | `secrets, ai, dependency, license, supply, hygiene, pii, security`（8 个；`fossa` / `ignore` / `repo` 不是合法值） |
| **计分维度**（`score.by_category`） | 分数拆分 | 上述 8 个（`security` 现在由 VUL-001~018 填充，不再是恒 100） |

规则按前缀分组如下。注意 **FOS 与 IGN 没有独立的 `--category`**，它们被折叠进别的维度：

| 前缀组 | 计分维度 | `--category` | 条数 |
| --- | --- | --- | --- |
| `SEC` 凭据泄漏 | secrets | `secrets` | 17 |
| `PII` 敏感数据 | pii | `pii` | 6 |
| `AI` AI 代码风险 | ai | `ai` | 14 |
| `VUL` 代码安全 | security | `security` | 18 |
| `DEP` 依赖漏洞 | dependency | `dependency` | 3 |
| `LIC` 许可证 | license | `license` | 9 |
| `SCP` 供应链 | supply | `supply` | 15 |
| `HYG` 仓库卫生 | hygiene | `hygiene` | 15 |
| `FOS` FOSSA 协同 | license / supply / hygiene | 无 | 8 |
| `IGN` 豁免 | hygiene | 无 | 2 |

`FOS` 的具体归属：`FOS-001/002/006/007/008` → license；`FOS-003/004` → supply；`FOS-005` → hygiene。
`IGN-001/002` → hygiene。因此 `rules --category license` 实际返回 14 条、`supply` 17 条、`hygiene` 18 条——不是上表的前缀条数。

级别：`critical > high > medium > low > info`。

---

## SEC — 凭据泄漏（17）

| ID | 级别 | 说明 |
| --- | --- | --- |
| SEC-001 | critical | OpenAI / 兼容端点 API Key |
| SEC-002 | critical | Anthropic API Key |
| SEC-003 | critical | AWS Access Key ID |
| SEC-004 | critical | AWS Secret Access Key 赋值 |
| SEC-005 | critical | GitHub Token |
| SEC-006 | high | Slack Token |
| SEC-007 | high | Google API Key |
| SEC-008 | critical | Stripe 线上密钥 |
| SEC-009 | critical | 私钥文件内容（PEM 块） |
| SEC-010 | high | Hugging Face Token |
| SEC-011 | high | npm Token |
| SEC-012 | critical | PyPI Token |
| SEC-013 | high | SendGrid API Key |
| SEC-014 | high | Telegram Bot Token |
| SEC-015 | high | URL 内嵌账号密码（`scheme://user:pass@host`） |
| SEC-016 | medium | JWT Token |
| SEC-017 | medium | 疑似硬编码密钥（高熵字符串，confidence 0.5–0.65） |

要点：
- 证据只显示前 4 位 + 后 4 位（`sk-p****yHf6`），**报告与缓存都不保存原文**。base64 编码的密钥会解码后二次识别。
- 同一取值多处出现会合并成一条，`detail.occurrences` 列位置，计分只算一次。
- 占位符（含 `example/dummy/placeholder/your-/xxxx/changeme`）不判 critical；`tests/`、`docs/`、`*.example`、`fixtures/` 里的命中降级为 low。
- 修法优先级：**先吊销/轮换，再改代码，最后清历史**（`git filter-repo` / BFG）。只改代码不轮换等于没修。

## PII — 敏感数据（6）

| ID | 级别 | 说明 |
| --- | --- | --- |
| PII-001 | low | 邮箱地址 |
| PII-002 | medium | 手机号 |
| PII-003 | high | 政府证件号（SG NRIC / 泰国身份证 / 印尼 NIK / 马来 MyKad / 菲律宾 PhilSys） |
| PII-004 | high | 银行卡号（13–19 位 + Luhn + IIN 前缀） |
| PII-005 | high | 疑似真实用户数据快照（单文件 ≥20 个不同邮箱） |
| PII-006 | high | 日志中输出个人信息（日志调用里插值 email/phone 等） |

要点：
- 辖区由 `.pdp-compliance.json` 的 `personalDataProtection.jurisdictions` 决定；未声明时只做通用格式识别，报告标注「未按辖区校验」。
- 隐私不变量：报告/JSON/SARIF 只有掩码与位置；去重哈希只在内存中存在。
- 测试目录命中置信度 ≤ 0.4，不参与门禁。`example.com` / `test.com` / `user@` 等占位值不报。
- 政府证件号优先于银行卡号判定（16 位 NIK 也可能过 Luhn）。

## AI — AI 代码风险 / 工程规范 / 算法复杂度（25）

| ID | 级别 | 说明 |
| --- | --- | --- |
| AI-001 | medium | 占位密钥 / 占位配置残留 |
| AI-002 | info | 未完成实现标记（TODO + 空实现） |
| AI-003 | info | 抽象方法未实现（基类用 `raise NotImplementedError` 声明子类义务是正常写法，仅提示） |
| AI-004 | medium | 异常被静默吞掉（`except: pass`、`catch {}`） |
| AI-005 | high | 危险调用：`eval/exec/pickle.loads/yaml.load/shell=True 拼接/verify=False` |
| AI-006 | high | 前端危险注入点（`innerHTML`、`dangerouslySetInnerHTML` 等） |
| AI-007 | low | 生产代码中的示例 / mock 数据 |
| AI-008 | low | 调试输出残留（`console.log`、`print`、`debugger`） |
| AI-009 | low | 硬编码的个人机器路径（`C:\Users\xxx`、`/home/xxx`） |
| AI-010 | medium | 关闭类型检查 / 全文件忽略（`# type: ignore`、`// @ts-nocheck`、`# noqa`） |
| AI-011 | low | 空实现函数体 |
| AI-012 | **high** | **幻觉依赖：import 了清单中没有、且不是标准库/本地模块的包** |
| AI-013 | info | 检测到 AI 助手配置（CLAUDE.md / .cursorrules …）但没有 `AI_USAGE.md` |
| AI-014 | info | `AI_USAGE.md` 缺必需小节，或仍含「待填写」 |
| AI-015 | medium | 外部请求没有超时设置（`requests/httpx` 无 timeout、`fetch` 无 signal、`axios` 无 timeout） |
| AI-016 | medium | 循环里串行 await（可并发/批量；`await import` 不算） |
| AI-017 | medium | 循环里发查询（N+1） |
| AI-018 | high | ORM 开了 schema 自动同步/强制重建（`synchronize/dropSchema/force`） |
| AI-019 | medium | Django 默认开放主机/CORS/CSRF（`ALLOWED_HOSTS=['*']`、`CORS_ALLOW_ALL_ORIGINS`） |
| AI-020 | low | 用 `print` / `console.log` 当日志（CLI 文件与测试降级） |
| AI-021 | medium | 循环里逐条请求外部接口（同步 HTTP 放循环里） |
| AI-022 | low | 循环里用 `+=` 拼接字符串（O(n²)） |
| AI-024 | medium | 循环里 `pd.concat`（越拼越慢） |
| AI-025 | low | 用 list 当队列（`pop(0)` / `insert(0, x)`） |
| AI-026 | low | 用 `iterrows` 逐行遍历 DataFrame |

要点：
- `AI-012` 是这套规则里最值得优先讲的一条：运行期才炸，且常是 AI 顺手 import 的产物。修法二选一——**确认包真实存在并写进清单**，或删掉未使用的导入。
- `tests/`、`examples/`、`scripts/` 里的调试残留会降级；CLI 入口文件里的 `print` 不报。
- **测试代码不参与工程规则**（AI-003/004/005/016/017/020/022/025/026）：测试用 pickle 造夹具、吞掉断言异常、
  循环里跑检查都是正常写法；安全维度（secrets/PII）仍会覆盖测试文件（PII-001/004 在测试夹具里跳过）。
- **vendored 第三方代码跳过**（`vendor/`、`third_party/`、`node_modules/`、`bower_components/`、`external/`）：
  扫 jQuery 的 catch 块只会制造噪音。

## DEP — 依赖漏洞（3）

| ID | 级别 | 说明 |
| --- | --- | --- |
| DEP-001 | high* | 依赖存在已知漏洞（级别随公告严重度） |
| DEP-003 | info | 依赖版本无法确定（只有范围、没有锁文件） |
| DEP-004 | medium | 命中公告但未能获取详情（网络/数据问题） |

要点：数据来自 OSV.dev；`--offline` 时不查询，改为 `packages_unverified` 计数。只发**包名与版本**，不发源码。修复建议会给到具体修复版本。

## LIC — 许可证（9）

| ID | 级别 | 说明 |
| --- | --- | --- |
| LIC-002 | medium | 许可证声明与 LICENSE 文件不一致 |
| LIC-003 | medium | 许可证文件无法识别 |
| LIC-004 | high | 依赖许可证被项目策略禁止（`deny`） |
| LIC-005 | medium | 依赖许可证无法确定 |
| LIC-006 | low | 依赖使用弱传染许可证（MPL/EPL/LGPL） |
| LIC-007 | low | 项目许可证不在团队白名单内 |
| LIC-008 | info | 许可证问题过多，已折叠 |
| LIC-009 | **high** | **许可证组合冲突**（项目类 × 依赖类 = incompatible） |
| LIC-010 | info | 组合无法自动判定（按组合聚合，最多 5 组） |

要点：
- 组合矩阵把许可证归并成 11 类：permissive / apache / mpl / epl / lgpl2 / lgpl3 / gpl2 / gpl2plus / gpl3 / agpl3 / source-available。
- 项目许可证「声明优先、文件兜底」；项目许可证缺失或无法归类时**完全跳过矩阵**，不猜。
- 常见真冲突：GPL-2.0-only 项目引入 Apache-2.0（专利条款）；Apache-2.0 项目引入 GPL-3.0/AGPL。
- `conditional`（弱传染在保留声明前提下可用）不产出 finding，避免噪音。
- 结论是**工程判断，不是法律意见**——转述时要带上这句。

## VUL — 代码安全（18）

OWASP Top 10 里能在源码中直接看见的高信号模式。每条规则带 CWE 与 OWASP 映射，`detail.cwe` / `detail.owasp` 可直接用于报告与整改单。

| ID | 级别 | 说明 | CWE | OWASP |
| --- | --- | --- | --- | --- |
| VUL-001 | high | SQL 注入：查询由字符串拼接/格式化产生 | CWE-89 | A03 |
| VUL-002 | high | 命令注入：拼接后交给 shell | CWE-78 | A03 |
| VUL-003 | high | 服务端模板注入（SSTI） | CWE-1336 | A03 |
| VUL-004 | high | 不可信数据反序列化（marshal/dill/jsonpickle/shelve） | CWE-502 | A08 |
| VUL-005 | high | 未转义 HTML 输出（Markup / document.write） | CWE-79 | A03 |
| VUL-006 | high | 路径穿越：用户输入拼进文件路径 | CWE-22 | A01 |
| VUL-007 | medium | SSRF：请求目标来自用户输入 | CWE-918 | A10 |
| VUL-008 | medium | 弱哈希（MD5/SHA1），安全语境升级为 high | CWE-327 | A02 |
| VUL-009 | medium | 非密码学随机数生成令牌/密钥 | CWE-338 | A02 |
| VUL-010 | high | 关闭 TLS 证书校验（测试代码降为 low） | CWE-295 | A07 |
| VUL-011 | medium | 弱加密算法/模式（ECB / DES / createCipher） | CWE-327 | A02 |
| VUL-012 | high | JWT 校验关闭或接受 alg=none | CWE-347 | A07 |
| VUL-013 | low | Cookie 缺少 Secure/HttpOnly | CWE-614 | A05 |
| VUL-014 | medium | 生产代码开启调试模式 | CWE-489 | A05 |
| VUL-015 | high | XML 外部实体（XXE） | CWE-611 | A05 |
| VUL-016 | high | C/C++ 危险字符串函数（缓冲区溢出） | CWE-120 | A03 |
| VUL-017 | high | GitHub Actions 脚本注入（不可信事件字段进 run） | CWE-94 | A03 |
| VUL-018 | medium | 容器提权 / 挂载 Docker socket | CWE-250 | A05 |

要点：
- 只覆盖**能在源码里直接看见**的模式；运行时配置、依赖链、业务逻辑漏洞不在内；
- 注释与文档字符串会被屏蔽（文档里举例的 `eval(` 不算漏洞）；同一文件同一规则聚合为一条；
- 测试目录命中降级（置信度 ≤0.5），TLS/调试这类测试常见写法只保留 low；
- 参数化 SQL、无安全语境的 MD5 校验和**不报**——这是规则的质量线；
- 扫描器名是 `security`：`--only security` / `--skip security`。

## SCP — 供应链（15）

| ID | 级别 | 说明 |
| --- | --- | --- |
| SCP-001 | medium | 依赖没有锁文件（`project.kind = "library"` 时为 low：库通常不提交锁文件） |
| SCP-002 | medium | 依赖未指定版本约束（`*` / `latest`） |
| SCP-003 | critical | 依赖是已知恶意包名 |
| SCP-004 | high | 疑似仿冒包（typosquatting，编辑距离） |
| SCP-005 | high | 依赖源使用明文 HTTP |
| SCP-006 | medium | 依赖来自非默认源（`--extra-index-url` 等） |
| SCP-007 | low | GitHub Action 未固定到 SHA |
| SCP-008 | medium | 脚本中存在下载即执行（`curl … | bash`） |
| SCP-009 | low | Dockerfile 基础镜像未固定版本（`:latest`） |
| SCP-010 | low | Git / 本地路径依赖（不可验证） |
| SCP-011 | info | `package.json` 定义了安装期脚本 |
| SCP-012 | high | `pull_request_target` 里检出了 PR 代码（pwn request） |
| SCP-013 | medium | 工作流授予 `write-all` 权限 |
| SCP-014 | medium | vendored 代码缺少来源记录（无 `VENDORED.md`） |
| SCP-015 | low | vendored 来源记录不完整（漏目录 / 仍是「待补齐」） |

## HYG — 仓库卫生（15）

| ID | 级别 | 说明 |
| --- | --- | --- |
| HYG-001 | high | 没有 LICENSE 文件 |
| HYG-002 | medium | 缺少 README |
| HYG-003 | medium | 缺少 SECURITY.md |
| HYG-004 | medium | 缺少 .gitignore |
| HYG-005 | high | .gitignore 没有忽略 `.env` |
| HYG-006 | **critical** | `.env` 已被提交 |
| HYG-007 | **critical** | 凭据 / 私钥文件已被提交 |
| HYG-008 | high | 依赖 / 缓存目录被提交（`node_modules`、`__pycache__`、venv…） |
| HYG-009 | medium | 仓库中有较大的二进制文件 |
| HYG-010 | low | 没有 CI 配置 |
| HYG-011 | info | 没有找到测试文件 |
| HYG-012 | low | 系统垃圾文件被提交（`.DS_Store`、`Thumbs.db`） |
| HYG-013 | low | 同一生态存在多个锁文件 |
| HYG-014 | low | 缺少 THIRD_PARTY_NOTICES |
| HYG-015 | info | THIRD_PARTY_NOTICES 与依赖不一致（最多列 20 个缺失包） |

## FOS — FOSSA 协同（8）

| ID | 级别 | 说明 |
| --- | --- | --- |
| FOS-001 | medium | 多包仓库未限制 FOSSA 分析范围（缺 `paths.only`） |
| FOS-002 | medium | vendored / 依赖目录没从 FOSSA 扫描中排除 |
| FOS-003 | medium | `fossa-deps` 条目不合规（type/version/license/路径） |
| FOS-004 | medium | CI 只跑 `fossa analyze`，没有 `fossa test`（报告生成了但构建不会失败） |
| FOS-005 | low | FOSSA 配置无法解析或版本过旧 |
| FOS-006 | medium | SBOM 与本地许可证结论不一致（需人工看 LICENSE 原文） |
| FOS-007 | info | SBOM 可补全本地无法确定的许可证（会给可粘贴的 `license.exceptions` 片段） |
| FOS-008 | info | SBOM 里有本地没解析到的组件（覆盖缺口） |

## IGN — 豁免（2）

| ID | 级别 | 说明 |
| --- | --- | --- |
| IGN-001 | medium | 豁免已过期（自动恢复计分） |
| IGN-002 | high | 致命问题不允许被豁免 |

---

## 置信度（confidence）

| 来源 | 置信度 |
| --- | --- |
| 确定性规则（缺 LICENSE、明文 HTTP、Action 未固定 SHA…） | 1.0 |
| 幻觉依赖（生产代码 import 未声明包） | 0.8 |
| SBOM 与本地结论冲突 | 0.85 |
| 仅凭高熵判定的疑似密钥 | 0.5–0.65 |
| 测试目录里的同类命中 | 0.4–0.5 |

`confidence` 只影响**扣分与门禁**，不影响 `counts` 的条数统计（不因此少报）。`< 0.6` 在报告里标「需人工确认」，转述时要保留这个限定词。门禁默认 `min_confidence = 0.5`。

## 评分

- 维度内：`扣分 = 权重 × (1 + 0.7 × log₂(有效次数))`
- 有效次数 = Σ confidence（全置信度时等于条数；下限 0.05 防对数发散）
- 权重：critical 35 / high 8 / medium 2 / low 0.8 / info 0.1
- 除 critical 外**单维度封顶 25 分**；critical 不设上限（一条真实密钥就足以把分数压到 D 以下）
- 总分 = `max(0, 100 - Σ各维度扣分)`；等级 A≥90 / B≥80 / C≥70 / D≥60 / F<60
- `score.reliable = false` 时（离线，或过半依赖版本未知）标注「分数仅供参考」
