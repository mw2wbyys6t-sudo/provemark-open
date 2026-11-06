# 端到端工作流

每一步都给了「完成判定」——没有达到就不要对用户说“搞定了”。

---

## 1. 陌生仓库首次体检

**目标**：一条命令给出全貌 + 该先修什么。

```pwsh
New-Item -ItemType Directory -Force "$env:TEMP\provemark" | Out-Null
node "<PM>\bin\provemark.mjs" scan <repo> -f json -o "$env:TEMP\provemark\first.json"
node "<PM>\bin\provemark.mjs" scan <repo> -f html  -o "$env:TEMP\provemark\first.html"
```

回复用户的顺序：
1. `score.total` / `grade`，并**先说 `reliable`**（false → 「分数仅供参考，原因是离线/依赖版本未知」）。
2. 最差的 1–2 个维度（`score.by_category` 最低者）+ 条数。
3. Top 3–5 条：`[级别] 规则ID 一句话` / `文件:行` / 一句修法。
4. 下一步二选一：能自动修的（`fix`）vs 要人判断的（`--ai-prompt`）。
5. HTML 路径（单文件、可直接打开）。

**完成判定**：用户能回答“我现在最该动的 3 处是什么”。

---

## 2. 提交前门禁

**目标**：问题不进历史。

一次性建立：

```pwsh
node "<PM>\bin\provemark.mjs" init <repo> --apply          # 策略文件 + CI 工作流 + 缺失的基础文件
node "<PM>\bin\provemark.mjs" hook install <repo>          # pre-commit：只扫暂存区
```

之后每次 `git commit` 自动只扫 `--staged`，出现 high 及以上阻止提交。

手动跑一次等价命令：

```pwsh
node "<PM>\bin\provemark.mjs" scan <repo> --staged --fail-on high --min-confidence 0.5
```

**完成判定**：`echo $LASTEXITCODE` 为 0；如果是 1，逐条处理或（有正当理由的）登记 `ignore`，而不是改阈值。

---

## 3. AI 修复循环

**目标**：把“问题清单”变成“可执行的修复任务”，改完能验证。

```pwsh
# ① 生成指令（只写指令文件，不改代码）
node "<PM>\bin\provemark.mjs" scan <repo> --ai-prompt fix.md --test-command "pytest -q"

# ② 把 fix.md 交给编码代理执行（指令里已写明：不改无关代码、不加新依赖、逐条给完成判定）

# ③ 验证
node "<PM>\bin\provemark.mjs" scan <repo> -f json -o "$env:TEMP\provemark\after.json"
```

对比口径（三件事都要看，只看分数会误判）：
- `score.total` 上升
- **新增问题 = 0**（`after` 里出现 `before` 没有的 `fingerprint` 就是回归）
- 验证命令本身通过（`--test-command` 指定的那条）

**完成判定**：三件事同时成立，且用户确认没有引入新依赖。修复清单之外的改动属于越界，要指出来。

---

## 4. 发布前合规包

**目标**：对外分发时能拿得出来「用了谁的代码、什么许可证、AI 用到什么程度」。

```pwsh
node "<PM>\bin\provemark.mjs" notices  <repo>       # THIRD_PARTY_NOTICES.md（第三方归因）
node "<PM>\bin\provemark.mjs" ai-usage <repo>       # AI_USAGE.md（AI 使用声明）
node "<PM>\bin\provemark.mjs" vendored <repo>       # VENDORED.md（vendored 来源）
node "<PM>\bin\provemark.mjs" scan <repo> -f html -o release-report.html
```

- 三个生成器都**不覆盖手写文件**（已有手写版本时改写 `*.provemark.md`）；先 `--print` 预览再落盘更稳。
- 生成物里会留「待填写 / 待补齐」字段——**必须由人补齐**，不要把占位当结果。
- 之后重扫应看到 `HYG-014` / `HYG-015` / `AI-013` / `AI-014` / `SCP-014` / `SCP-015` 消失或降级。

**完成判定**：`THIRD_PARTY_NOTICES.md`、`AI_USAGE.md`、`VENDORED.md` 均已补齐（无「待填写」），且重扫无上述规则命中。

---

## 5. 与 FOSSA / SBOM 对齐

**目标**：两边结论交叉核对，冲突的挑出来给人看，缺口明确说出来。

```pwsh
# 导出标准 SBOM（FOSSA 支持 CycloneDX / SPDX JSON）
fossa analyze
fossa test --format json                       # CI 门禁
fossa report attribution --format cyclonedx-json -o sbom.json

# 本地结论 × SBOM
node "<PM>\bin\provemark.mjs" scan <repo> --sbom sbom.json
```

结果怎么讲：
| 规则 | 含义 | 该做什么 |
| --- | --- | --- |
| `FOS-006` | 两边许可证家族不同 | 人工看 LICENSE 原文，别自动选边 |
| `FOS-007` | 本地 unknown、SBOM 有结论 | 把报告给的 `license.exceptions` 片段粘进 `.provemark.toml` |
| `FOS-008` | SBOM 有、本地没解析到 | 覆盖缺口（vendored / 私有包 / 不支持的清单格式） |

补齐 FOSSA 盲区：

```pwsh
node "<PM>\bin\provemark.mjs" fossa-deps <repo> --print    # 先看
node "<PM>\bin\provemark.mjs" fossa-deps <repo>            # 落盘 fossa-deps.yml（不覆盖手写版本）
```

**完成判定**：每条 `FOS-*` 都有结论（人工确认 or 已写入例外），且明确说出覆盖率缺口。

---

## 6. PII / 隐私专项

**目标**：确认仓库里没有真实个人信息，且辖区判定是“按声明做的”。

```pwsh
node "<PM>\bin\provemark.mjs" scan <repo> --only pii -f json -o "$env:TEMP\provemark\pii.json"
```

检查顺序：
1. 有没有 `.pdp-compliance.json`？没有就是「未按辖区校验」——先问用户业务辖区，不要替他猜。
2. `PII-005`（真实数据快照）、`PII-006`（日志打印 PII）优先于格式类命中。
3. 测试目录里的命中 `confidence ≤ 0.4`，属于「需人工确认」，不要当泄漏事件上报。
4. 不要回显 `evidence` 之外的内容；不要试图还原原文。

**完成判定**：用户知道（a）有没有真实数据、（b）按哪个辖区判的、（c）下一步是清理还是补辖区声明。

---

## 7. CI 接入（GitHub Code Scanning）

```yaml
- run: pip install -e .
- run: provemark scan --fail-on high --min-confidence 0.5 --format sarif -o provemark.sarif
- uses: github/codeql-action/upload-sarif@33d7b85da1a04171e211befe2c739303b9a4c066 # v4.39.3
  with:
    sarif_file: provemark.sarif
```

或直接用仓库自带的 composite Action（`action/action.yml`，版本与 CLI 一致）：

```yaml
- uses: <owner>/provemark/action@v0.4.0
  with:
    fail-on: high
    min-confidence: "0.5"
```

在 DSH 里做这件事时：优先用 `init --apply` 生成工作流，再让用户确认 `permissions: security-events: write` 这一段。

**完成判定**：工作流文件存在且 `scan … -f sarif -o …` 与上传步骤都在；用户知道失败会在 Security 面板按行展示。

---

## 通用节奏

1. **先扫描，后动作**——没跑出结果前不要建议改策略。
2. **能自动修的别手写**（`fix`），**要判断的别自动修**（`--ai-prompt`）。
3. **每次改动后重扫**，并且同时看分数、新增问题数、验证命令三件事。
4. **不确定就说不确定**：`confidence < 0.6`、`reliable=false`、`packages_unverified > 0` 都要如实说。
