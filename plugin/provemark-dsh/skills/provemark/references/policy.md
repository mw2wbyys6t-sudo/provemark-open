# 策略文件与豁免

扫描器只读仓库里的策略文件，不改任何东西（只有 `init --apply` / `fix --apply` / `ignore` 会写）。

## 配置文件

查找顺序（仓库根目录，取第一个存在的）：

```
.provemark.toml  →  provemark.toml  →  .provemark.yml  →  .provemark.yaml
.reposentinel.toml / .yml / .yaml        # 0.3 及更早旧名，只读兼容，不再写入
```

- 也支持 YAML（后缀 `.yml` / `.yaml`），字段相同。
- `scan --config <路径>` 可显式指定。
- 语法错误 → 退出码 2，stderr 会指出是哪个键。
- 没有策略文件时用内置默认值（`fail_on=high`、`min_confidence=0.5`、`kind=library`）。

## 完整字段

```toml
[project]
kind = "library"              # library | app | docs（docs 不强制 LICENSE）
license = ""                  # 留空 = 从 LICENSE 文件 / 清单字段推断
# allowed_licenses = ["MIT", "Apache-2.0"]   # 项目许可证白名单（LIC-007 用）
# 默认值就是 permissive 列表：0BSD/Apache-2.0/BSD-2/BSD-3/BSL-1.0/CC0-1.0/ISC/MIT/MIT-0/OFL-1.1/PostgreSQL/Python-2.0/PSF-2.0/Unlicense/WTFPL/Zlib

[scan]
# exclude = ["vendor/**", "third_party/**"]  # 额外排除的 glob（默认已排除 node_modules、__pycache__、.git 等）
max_file_bytes = 1500000
# max_files = …                               # 单次扫描文件数上限
# severity_floor = "info"                     # 低于该级别不产出 finding

[gate]
fail_on = "high"              # none | low | medium | high | critical
min_confidence = 0.5          # 0 = 全部参与门禁；0.8 = 只拦最确定的问题

[license]
# allow = ["MIT", "Apache-2.0"]                        # 默认 = permissive 列表
# warn  = ["MPL-2.0", "LGPL-3.0-only"]                 # 默认 = 弱传染列表（CDDL/EPL-2.0/LGPL-2.1/LGPL-3.0/MPL-2.0）
# deny  = ["GPL-3.0-only", "AGPL-3.0-only"]            # 默认 = 强传染列表（AGPL/GPL-2.0/GPL-3.0/SSPL-1.0/BUSL-1.1/Elastic-2.0）
unknown = "medium"            # 依赖许可证未知时的级别（LIC-005）
# no_license = "high"         # 项目无许可证时的级别（HYG-001）

[license.exceptions]
# "some-lgpl-lib" = "仅内部工具使用，不对外分发"
# 键 = 包名，值 = 原因（必填）。有例外时该包不再报 LIC-004。

[pii]
enabled = true                # false = 永久关闭 PII 扫描（也可用 --skip pii 单次跳过）

[ai]
allow_debug_logs = false      # true = 生产代码里允许 console.log / print 调试输出（AI-008）

[network]
enabled = true                # false = 等价于始终 --offline
# timeout = 8                 # 单次网络请求超时（秒）

[supply]
# allowed_indexes = ["pypi.org", "registry.npmjs.org"]   # 非默认源时不再报 SCP-006

[severity]
# 按规则覆盖级别：AI-004 = "info"、HYG-010 = "medium"
# 键必须是形如 XX-000 的规则 ID

[[ignore]]
fingerprint = "07e06440c00da1fe"
reason = "该告警已被上游确认误报，等 3.2 升级后移除"
expires = "2027-01-31"
```

### 排除语义（`[scan] exclude`）

排除分两种，行为不同：

| 来源 | 例子 | 内容扫描（文件、依赖、PII…） | vendored 归因（`SCP-014/015`） |
| --- | --- | --- | --- |
| **内置默认** | `node_modules/**`、`vendor/**`、`dist/**`… | 跳过 | **仍然检查**（归因规则正是为 `vendor/` 而设） |
| **用户显式加** | `mock-repo/**`、`plugin/x/python/**` | 跳过 | 跳过 |

要连归因一起忽略某个树，写一条比内置默认更具体的排除（如 `mock-repo/**`），不要指望 `vendor/**` 生效。

### `[[ignore]]` 的约束

- `reason` **必填**；否则配置直接报错。
- `fingerprint` / `rule` / `path` 至少给一个：
  - `fingerprint`：最精确（报告里可复制，不含行号，代码上下移动不失效）
  - `rule = "SCP-007"`：按规则豁免
  - `path = "tools/**"`：按路径 glob 豁免
- `expires` 省略时默认 **90 天**；到期自动恢复计分并新增 `IGN-001 豁免已过期`。
- **critical 不允许被豁免**（`IGN-002`）：真实密钥、已提交的 `.env`、恶意包名必须当次修掉。
- CLI 等价写法：
  ```pwsh
  node "<PM>\bin\provemark.mjs" ignore <fingerprint> --reason "…" --expires 2026-12-31
  node "<PM>\bin\provemark.mjs" ignore --rule SCP-007 --path "tools/**" --reason "内部脚本" --expires 2026-12-31
  ```
- 被豁免的条目会出现在 JSON 的 `suppressed[]`，不是消失。报告里折叠显示。

## PII 辖区声明：`.pdp-compliance.json`

```json
{
  "personalDataProtection": {
    "jurisdictions": ["sg-pdpa", "th-pdpa", "id-pdp", "my-pdpa", "ph-dpa"],
    "mode": "strictest-wins",
    "reviewPolicy": "warn"
  }
}
```

- 支持的辖区：`sg-pdpa`（新加坡 NRIC，含加权校验位）、`th-pdpa`（泰国身份证 mod 11）、`id-pdp`（印尼 NIK：省份 + 出生日期）、`my-pdpa`（马来 MyKad：出生日期 + 州代码）、`ph-dpa`（菲律宾 PhilSys，需 `philsys`/`umid` 关键词）。
- **未声明** → 只做通用格式识别（邮箱、手机号、Luhn 银行卡），报告标注「未按辖区校验」；不猜法域。
- 声明了不认识的辖区代码 → 忽略该条，不报错。
- 文件缺失或 JSON 非法 → 不报错，静默退化为通用格式。

## 改策略时的常见坑

| 坑 | 后果 / 正确做法 |
| --- | --- |
| 把 `fail_on` 调成 `none` 来“过 CI” | 门禁形同虚设；应改 `min_confidence` 或修问题 |
| 用 `[[ignore]]` 代替修复 | 到期会回来（`IGN-001`），且 critical 免疫 |
| `[license] deny` 写成许可证全名（`GNU GPL v3`） | 只认 SPDX 标识（`GPL-3.0-only`），否则匹配不上 |
| 在 `[project] license` 里写 `Apache 2.0` | 应写 `Apache-2.0`；写错会导致 LIC-002 判定不一致 |
| YAML 版本用 tab 缩进 | 解析失败，退出码 2 |
| `[[ignore]]` 漏 `reason` | 配置直接非法（退出码 2） |
| 把 `.provemark.toml` 加进 `.gitignore` | 策略就不随仓库分发了；CI 与本地会跑出不同结论 |

策略文件本身建议进版本库：它决定“什么算问题”，属于团队约定的一部分。
