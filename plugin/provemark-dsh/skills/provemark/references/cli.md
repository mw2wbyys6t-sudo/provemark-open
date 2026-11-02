# Provemark CLI 参考（v0.4.0）

调用形式：`node "<PM>\bin\provemark.mjs" <子命令> [参数]`。
等价形式：`$env:PYTHONPATH="<PM>\python"; python -P -B -m provemark <子命令> [参数]`。

**退出码**：`0` 通过 / `1` 命中门禁（仅 `scan`）/ `2` 用法或运行错误（路径不存在、未知扫描器、配置文件非法、`-o` 父目录不存在、SBOM 文件缺失）。

---

## scan — 扫描仓库

```pwsh
node "<PM>\bin\provemark.mjs" scan [path] [options]
```

| 参数 | 默认 | 说明 |
| --- | --- | --- |
| `path` | `.` | 仓库路径 |
| `-f, --format` | `auto` | `table` / `json` / `markdown` / `sarif` / `html`；`auto` 按 `-o` 扩展名推断，无 `-o` 时为 `table` |
| `-o, --output` | 无 | 写入文件；**父目录必须已存在**，否则报 `写入失败` 并返回 2；不给则写 stdout |
| `--fail-on` | 策略文件值（默认 `high`） | `none/low/medium/high/critical`，命中则退出码 1 |
| `--min-confidence` | 策略文件值（默认 `0.5`） | 低于该置信度的问题不参与门禁（仍会列出） |
| `--offline` | 关 | 不访问网络：跳过 OSV 漏洞查询与 deps.dev 许可证查询，结果标「未验证 / 分数仅供参考」 |
| `--staged` | 关 | 只扫 Git 暂存区（pre-commit 用） |
| `--only` | 无 | 只跑指定扫描器，逗号分隔 |
| `--skip` | 无 | 跳过指定扫描器，逗号分隔 |
| `-v, --verbose` | 关 | 终端显示全部问题（默认只显示优先处理的若干条） |
| `--quiet` | 关 | 静默：**没有 `-o` 时什么都不打印**；有 `-o` 时只保留文件与 stderr 的两行摘要 |
| `--no-color` | 关 | 关闭颜色（非 TTY 时本就会自动关） |
| `--config` | 无 | 指定策略文件路径（默认在仓库根找 `.provemark.toml`） |
| `--ai-prompt FILE` | 无 | 写出一份给编码代理的修复指令 Markdown |
| `--test-command` | 空 | 写入 AI 修复指令里的验证命令，如 `pytest -q` |
| `--sbom FILE` | 无 | 读 FOSSA / CycloneDX / SPDX JSON，与本地许可证结论交叉核对 |

**扫描器名**（`--only` / `--skip` 的取值）：`repo, secrets, pii, security, ai, dependency, license, supply, fossa`
- `repo` = 仓库卫生（HYG）
- `secrets` = 凭据（SEC）
- `pii` = 敏感数据（PII）
- `ai` = AI 代码风险 + 幻觉依赖（AI）
- `dependency` = 依赖解析 + 漏洞（DEP）
- `license` = 许可证 + 组合矩阵（LIC）
- `supply` = 供应链（SCP）
- `fossa` = FOSSA 配置体检与 SBOM 对齐（FOS）

**输出路由**（容易踩坑）：
- 终端 `table` 报告 → stdout；`-o` 成功后的两行摘要（`Provemark: 88/100 (B) · …`、`报告已写入 …`）→ stderr。
- `scan --quiet` 且无 `-o`：没有任何输出。要一行结论请用 `-f json -o file` 再读 `score`。
- 报告里出现「数据不完整」= `score.reliable=false`；不要把这种情况说成「没有漏洞」。

**示例**：
```pwsh
node "<PM>\bin\provemark.mjs" scan . --offline
node "<PM>\bin\provemark.mjs" scan . -f json -o "$env:TEMP\provemark\last.json"
node "<PM>\bin\provemark.mjs" scan . --only pii
node "<PM>\bin\provemark.mjs" scan . --skip pii,license --fail-on critical
node "<PM>\bin\provemark.mjs" scan . --staged --fail-on high -f sarif -o provemark.sarif
node "<PM>\bin\provemark.mjs" scan . --ai-prompt fix.md --test-command "pytest -q"
```

---

## explain — 解释一条规则

```pwsh
node "<PM>\bin\provemark.mjs" explain AI-012
```

输出：规则标题、维度、默认级别、「为什么是问题」、「怎么修」。规则 ID 形如 `SEC-001`、`LIC-009`、`HYG-006`（全 107 条见 `references/rules.md`）。未知 ID 返回 2。

## rules — 列出规则

```pwsh
node "<PM>\bin\provemark.mjs" rules
node "<PM>\bin\provemark.mjs" rules --category pii
```

`--category` 只接受 **7 个**值：`secrets / pii / ai / dependency / license / supply / hygiene`。
`security`、`fossa`、`ignore`、`repo` 不是合法值（分别对应「无规则」「已折叠进 license/supply/hygiene」「扫描器名」）。
注意 `fossa` 是**扫描器名**（`scan --only fossa`），不是规则维度。输出是纯文本表格（`规则ID  级别  标题`），可直接转述。

---

## init — 初始化策略与 CI（只创建缺失文件）

```pwsh
node "<PM>\bin\provemark.mjs" init [path] [--license Apache-2.0] [--author "Name"] [--no-ci] [--apply]
```

- 默认 **dry-run**，只列出将要创建的文件；`--apply` 才写。
- 会补：`.provemark.toml`、`LICENSE`（按 `--license`）、`.gitignore` 条目、`SECURITY.md`、`.github/workflows/provemark.yml`（`--no-ci` 关闭）。
- 只创建，不覆盖已有文件。`--author` 省略时取 `git user.name`。
- 退出码 2 表示配置错误（如既有 `.provemark.toml` 语法非法）。

## fix — 修不需要判断的问题（默认 preview）

```pwsh
node "<PM>\bin\provemark.mjs" fix [path] [--apply] [--force] [--only license,gitignore,security,config,ci] [--license X] [--author Y]
```

- 只做「补文件」类修复：`LICENSE`、`.gitignore` 条目、`SECURITY.md`、`.provemark.toml`、CI 工作流。
- **绝不改业务代码**；代码层修法只走 `--ai-prompt`。
- 已存在文件不覆盖，除非 `--force`。`--only` 限定范围。

## ignore — 登记豁免

```pwsh
node "<PM>\bin\provemark.mjs" ignore <fingerprint> --reason "为什么可以接受" [--expires 2026-12-31] [--config 路径] [--root .]
node "<PM>\bin\provemark.mjs" ignore --rule SCP-007 --path "tools/**" --reason "内部脚本" --expires 2026-12-31
```

- 三种定位方式：指纹（报告里可复制）、`--rule`、`--path` glob。
- `--reason` 必填；`--expires` 省略时默认 90 天后。写入 `.provemark.toml` 的 `[[ignore]]`。
- 到期后自动恢复计分，并新增一条 `IGN-001 豁免已过期`。
- **critical 不允许被豁免**（`IGN-002`），真实密钥必须当次修掉。

## hook — pre-commit 钩子

```pwsh
node "<PM>\bin\provemark.mjs" hook install [path] [--force]
node "<PM>\bin\provemark.mjs" hook uninstall [path]
```

安装后 `git commit` 只扫描暂存区（等价 `--staged`），出现 high 及以上时阻止提交。`--force` 覆盖已有钩子。

## fossa-deps — 补齐 FOSSA 扫不到的依赖

```pwsh
node "<PM>\bin\provemark.mjs" fossa-deps [path] [-o out.yml] [--mode missing|all] [--limit 5000] [--force] [--print]
```

- `--mode missing`（默认）：只按「含 LICENSE 的最小目录」拆 vendored 组件。
- `--mode all`：导出全部 FOSSA 支持类型的依赖（文件头带醒目警告：会与自动扫描重叠）。
- 目标文件已存在且非本工具生成时**不覆盖**，改写 `fossa-deps.provemark.yml`；`--force` 才覆盖。
- Conda / Julia / vcpkg / Conan / GitHub Actions 无对应 FOSSA 类型，会计入跳过统计并明说。

## notices / ai-usage / vendored — 生成三份声明

```pwsh
node "<PM>\bin\provemark.mjs" notices  [path] [-o FILE] [--offline] [--force] [--print]
node "<PM>\bin\provemark.mjs" ai-usage [path] [-o FILE] [--force] [--print]
node "<PM>\bin\provemark.mjs" vendored [path] [-o FILE] [--force] [--print]
```

| 命令 | 生成 | 要点 |
| --- | --- | --- |
| `notices` | `THIRD_PARTY_NOTICES.md` | 只列运行时依赖；拿不到许可证的进「许可证未知」；`--offline` 只用缓存 |
| `ai-usage` | `AI_USAGE.md` | 自动识别 `CLAUDE.md`、`AGENTS.md`、`.cursorrules`、`.github/copilot-instructions.md` 等痕迹；未填字段留「待填写」；**不推断**没检测到的使用 |
| `vendored` | `VENDORED.md` | 复用 FOSSA 的 vendored 目录识别；从目录内 LICENSE 判定 SPDX；上游/Commit 留「待补齐」 |

共同规则：`--print` 只打印不落盘；手写文件不覆盖（改写 `*.provemark.md`）；`--force` 覆盖。

---

## `--pm-info`（插件自带，非 Provemark 子命令）

```pwsh
node "<PM>\bin\provemark.mjs" --pm-info
```

打印 JSON：`packageRoot / skillRoot / pythonRoot / python{cmd,version} / probed[]`。排查「到底用了哪个 Python」时用。
