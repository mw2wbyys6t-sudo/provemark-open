# 排障

## 先做自检

```pwsh
node "<PM>\bin\provemark.mjs" --pm-info
```

看三件事：`python` 是否为 `null`、`python.version` 是否 ≥ 3.11、`packageRoot` 是否指向你以为的那个目录（多 profile 时容易装错）。

同时可以单独确认扫描器本体可用：

```pwsh
node "<PM>\bin\provemark.mjs" --version          # provemark 0.4.0
node "<PM>\bin\provemark.mjs" rules --category secrets | Select-Object -First 3
```

---

## 启动器 / Python

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| `no Python 3.11+ interpreter found` 且退出码 2 | PATH 上没有合适解释器，DSH 运行时也没找到 | 装 Python 3.11+；或 `$env:PROVEMARK_PYTHON='C:\Python312\python.exe'`；启动器会依次尝试 `PROVEMARK_PYTHON` → `python3`/`python`/`py -3` → `~/.dsh/dsh-runtimes/**` → `DSH_APP_ROOT` |
| 只找到 3.10 及以下 | 版本探测不通过 | 升级解释器；Provemark 用了 3.11 的 `tomllib`，无法降级运行 |
| `bundled scanner missing at …\python\provemark` | 插件包不完整（cp 时漏了 python/） | 重新同步：`node "<PM>\scripts\sync-vendor.mjs"` |
| `failed to start …: EACCES/ENOENT` | 解释器路径含空格未加引号，或被杀软拦 | 用绝对路径 + 引号；换 `PROVEMARK_PYTHON` |
| 想确认到底用了哪个 Python | — | `--pm-info` 的 `probed[]` 列出了每个候选及结果 |

## 输出 / 编码

| 现象 | 处理 |
| --- | --- |
| `写入失败：[Errno 2] No such file or directory` | `-o` **不会创建父目录**：先 `New-Item -ItemType Directory -Force <目录>` |
| 中文在终端里乱码 | 插件已强制 `PYTHONUTF8=1` + `PYTHONIOENCODING=utf-8`；直接用 `python -m provemark` 时需自行设置；报告文件本身始终 UTF-8 |
| PowerShell 把正常输出显示成红色 `NativeCommandError` | 那是 python/node 写 stderr 被 PS 当作 error record，不是失败。以 `$LASTEXITCODE` 为准；想安静可加 `2>&1` 或 `$ErrorActionPreference='Continue'` |
| `--quiet` 什么都没输出 | 预期行为：无 `-o` 时静默。要一行结论用 `-f json -o <file>` 读 `score` |
| 报告里 `confidence < 0.6` 很多 | 启发式命中（高熵疑似密钥、测试目录），标注「需人工确认」，不是结论 |

## 扫描结果可疑

| 现象 | 说明 |
| --- | --- |
| 「分数 0/100 等级 F（数据不完整）」 | 有 critical（真实密钥/.env 已提交）+ 离线降级。先讲 critical，再说数据不完整 |
| `score.reliable = false` | 离线或过半依赖版本未知 → 必须说「分数仅供参考」 |
| `packages_unverified > 0` | 这些依赖没做漏洞查询（离线或版本未知），是覆盖面缺口，不是「无漏洞」 |
| `DEP-003 依赖版本无法确定` 很多 | 没有锁文件或只写了范围；`SCP-001` 通常同时出现 |
| `LIC-005` 全是 unknown | 离线，或该生态没有公开许可证 API（Dart/Swift/Julia/vcpkg/Conan 会提示人工确认） |
| `--only pii` 报了一堆邮箱 | 测试数据/文档里的示例；占位值本应被过滤，测试目录命中置信度 ≤ 0.4 |
| `HYG-013` 同一生态多个锁文件 | npm+yarn、pip+poetry 并存；不是错误，但会影响“版本裁决”，值得提醒 |

## 命令与参数

| 现象 | 处理 |
| --- | --- |
| `未知扫描器：xxx` | `--only/--skip` 只接受 `repo, secrets, pii, security, ai, dependency, license, supply, fossa` |
| `配置错误：… 解析失败` | TOML/YAML 语法问题，退出码 2；注意 `[[ignore]]` 必须写 `reason` |
| `扫描失败：--staged 需要在 Git 仓库中使用…` | 当前目录不是 Git 仓库，或读不到暂存区；提交前门禁必须在仓库内跑 |
| `路径不存在：…` | 路径写错（Windows 下注意反斜杠与引号） |
| `SBOM 文件不存在` / 不是 JSON / 超 20MB | 只接受标准 CycloneDX / SPDX JSON；FOSSA 的 `fossa test --format json` 原始输出**不支持**，请改导出 SBOM |
| `ignore` 报错 | 必须带 `--reason`；`--expires` 建议显式给日期 |

## 网络与缓存

| 现象 | 处理 |
| --- | --- |
| 扫描很慢（几十秒到几分钟） | 默认会查 OSV + deps.dev；加 `--offline`，或只跑 `--only` 一个维度 |
| 公司网络/代理导致请求失败 | 用 `--offline`；或在 `.provemark.toml` 设 `[network] timeout = 5`；失败会记 `DEP-004`，不会伪造“无漏洞” |
| 想彻底禁网 | `.provemark.toml` 里 `[network] enabled = false`（等价永久 `--offline`） |
| 缓存位置 / 想清理 | 默认 `~/.cache/provemark`，可用 `PROVEMARK_CACHE_DIR` 改；漏洞查询缓存 6 小时、公告 30 天、许可证 7 天 |

## 沙箱与权限

| 现象 | 处理 |
| --- | --- |
| 在 DSH 沙箱内 `-o` 写到仓库外被拒 | 报告写到工作区内（如 `./.provemark/last.json`）或申请更宽的文件权限 |
| DSH 的 shell 工具本身一启动就失败（Windows 报 `0xC0000142` / DLL 初始化失败） | 这是宿主沙箱与 `pwsh` 的兼容问题，**不是插件问题**：同样命令在宿主非沙箱模式或系统终端里可跑。可先在终端验证 `node "<PM>\bin\provemark.mjs" --version` |
| 扫描到 `node_modules` 慢 | 默认已排除；自定义 `[scan] exclude = ["dist/**"]`；超大仓库用 `[scan] max_files` / `max_file_bytes` |

## 安装 / 卸载

| 现象 | 处理 |
| --- | --- |
| 宿主里看不到 `provemark` 技能 | 装完需要重启宿主（技能目录在启动时扫描）；确认 profile 正确：`node "<PM>\scripts\install.mjs" --check` |
| 装完宿主起不来（loader 报 patch 行错误） | 插件行的 `bundledSkillDir` 用了 `!!js` 表达式解析包路径；说明包没被放到该 profile 的 `node_modules` 下。删掉 profile `package.json` 里 `dsh.profile.bundles` 的 `provemark-dsh` 一行即可回滚，或用 `scripts/uninstall.mjs` |
| 想迁移到另一台机器/另一个 profile | `node "<PM>\scripts\install.mjs" --profile <name>` |
