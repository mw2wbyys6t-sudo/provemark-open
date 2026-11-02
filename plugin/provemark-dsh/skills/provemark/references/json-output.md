# JSON 输出契约（`-f json`）

```pwsh
New-Item -ItemType Directory -Force "$env:TEMP\provemark" | Out-Null
node "<PM>\bin\provemark.mjs" scan . -f json -o "$env:TEMP\provemark\last.json"
```

写入用 UTF-8；`-o` 的父目录必须先存在。文件可以放心交给脚本消费，也可以直接给人看（字段名是稳定的）。

## 顶层字段

| 字段 | 类型 | 含义 |
| --- | --- | --- |
| `tool` | string | 恒为 `"provemark"` |
| `version` | string | 扫描器版本，如 `"0.4.0"` |
| `root` | string | 被扫描仓库的绝对路径 |
| `scanned_at` | string | ISO8601 带时区，如 `"2026-10-28T23:57:02+08:00"` |
| `score` | object | 见下 |
| `stats` | object | 见下 |
| `counts` | object | `{by_severity, by_category}`，与 `score.counts` 同源 |
| `findings` | array | 参与计分的问题 |
| `suppressed` | array | 被豁免的问题 + 低置信度未参与门禁的条目（结构同 finding） |
| `packages` | array | 解析到的依赖 |

### `score`

| 字段 | 含义 |
| --- | --- |
| `total` | 0–100（可能为 0.0；也可能出现 `99.9` 这类小数） |
| `grade` | `A` / `B` / `C` / `D` / `F` |
| `by_category` | 8 个维度各自得分：`dependency, license, secrets, pii, security, ai, supply, hygiene` |
| `counts` | `{critical, high, medium, low, info}` |
| `reliable` | `false` = 数据不完整（离线 / 过半依赖版本未知），必须说「分数仅供参考」 |

### `stats`

| 字段 | 含义 |
| --- | --- |
| `files_scanned` / `bytes_scanned` | 覆盖面 |
| `packages_total` / `packages_direct` | 依赖数 / 直接依赖数 |
| `packages_unverified` | 未获得漏洞数据的依赖数（离线时等于总数） |
| `duration_s` | 耗时（秒，浮点） |
| `network_used` | 本次是否联网 |
| `notes` | 降级与局限说明（字符串数组），**原文转述给用户** |

### `findings[]` / `suppressed[]`

| 字段 | 含义 |
| --- | --- |
| `rule_id` | 规则 ID，如 `SEC-001`、`LIC-009` |
| `category` / `category_label` | 维度键 / 中文名 |
| `severity` / `severity_label` | `critical/high/medium/low/info` / 中（致命/高危/中危/低危/提示） |
| `title` | 一句话结论 |
| `message` | 完整描述，含「为什么」与重复出现的位置 |
| `path` / `line` / `column` | 定位（`line`/`column` 可能为 0 或缺失） |
| `evidence` | **已掩码**的片段，永不还原 |
| `remediation` | 修法（一句话，可直接转述） |
| `reference` | 参考链接（可能为空串） |
| `source` | `local` / `osv` / `deps.dev` / `registry` |
| `confidence` | 0–1；`< 0.6` 需人工确认 |
| `fingerprint` | 稳定指纹（不含行号），`ignore` 时用它 |
| `detail` | 规则私有结构：如 `{pattern, count, occurrences[]}` 或 `{kind, jurisdiction}` 或 `{cve, fixed_version}` |

### `packages[]`

| 字段 | 含义 |
| --- | --- |
| `name` | 包名 |
| `ecosystem` | `PyPI` / `npm` / `Maven` / `NuGet` / `Go` / `crates.io` / `Packagist` / `RubyGems` / `GitHub Actions` … |
| `version` | 解析到的版本；空串 = 无法确定 |
| `declared` | 清单里声明的范围（如 `"^4.17.0"`、`"v4"`） |
| `scope` | `runtime` / `dev` / `build` |
| `manifest` | 来源清单文件的仓库相对路径 |
| `direct` | 是否直接依赖 |

## 真实样例（截断）

```json
{
  "tool": "provemark",
  "version": "0.4.0",
  "root": "F:\\扫描神器",
  "scanned_at": "2026-10-28T23:57:02+08:00",
  "score": {
    "total": 88,
    "grade": "B",
    "by_category": { "dependency": 99.9, "license": 100.0, "secrets": 99.94, "pii": 96.03,
                     "security": 100.0, "ai": 98.46, "supply": 94.12, "hygiene": 100.0 },
    "counts": { "critical": 0, "high": 0, "medium": 8, "low": 13, "info": 5 },
    "reliable": false
  },
  "stats": {
    "files_scanned": 67, "bytes_scanned": 550710,
    "packages_total": 4, "packages_direct": 4, "packages_unverified": 4,
    "duration_s": 1.01, "network_used": false,
    "notes": ["离线模式：0 个依赖未做漏洞查询", "超过一半依赖无法确定版本，分数仅供参考"]
  },
  "findings": [
    {
      "rule_id": "PII-003", "category": "pii", "category_label": "敏感数据",
      "severity": "medium", "severity_label": "中危",
      "title": "仓库中出现政府证件号",
      "message": "在 tests/test_pii.py 第 112 行发现符合 sg-pdpa 规则的证件号，属于敏感个人信息。 同一取值在另外 3 处重复出现（已合并计分）：tests/test_pii.py:112、…",
      "path": "tests/test_pii.py", "line": 112, "column": 50,
      "evidence": "******67D",
      "remediation": "立即从仓库与历史中移除，改用掩码样例；如属生产数据，按泄露流程评估通知义务。",
      "reference": "", "source": "local", "confidence": 0.4,
      "fingerprint": "461a3521d765cf14",
      "detail": { "kind": "government_id", "jurisdiction": "sg-pdpa", "count": 4,
                  "occurrences": ["tests/test_pii.py:112", "tests/test_pii.py:147"] }
    }
  ],
  "suppressed": [ { "rule_id": "SEC-001", "…": "被 ignore 记录或被降噪的条目" } ],
  "packages": [
    { "name": "actions/checkout", "ecosystem": "GitHub Actions", "version": "",
      "declared": "v4", "scope": "runtime",
      "manifest": ".github/workflows/provemark.yml", "direct": true }
  ]
}
```

## 消费配方（PowerShell）

**只取结论**
```pwsh
$r = Get-Content "$env:TEMP\provemark\last.json" -Raw -Encoding utf8 | ConvertFrom-Json
"{0}/100 {1} · reliable={2} · high={3} medium={4}" -f $r.score.total, $r.score.grade, $r.score.reliable, $r.score.counts.high, $r.score.counts.medium
```

**Top 问题（按严重度）**
```pwsh
$order = @{critical=0;high=1;medium=2;low=3;info=4}
$r.findings | Sort-Object { $order[$_.severity] }, @{Expression={-$_.confidence}} |
  Select-Object -First 5 rule_id, severity, title, path, line, remediation
```

**按维度计数**
```pwsh
$r.counts.by_category.PSObject.Properties | Sort-Object Value -Descending | Format-Table Name, Value
```

**收集指纹以便豁免**
```pwsh
$r.findings | Where-Object { $_.rule_id -eq 'SCP-007' } | Select-Object -ExpandProperty fingerprint
```

**前后对比（修完再扫）**
```pwsh
$before = Get-Content "$env:TEMP\provemark\before.json" -Raw | ConvertFrom-Json
$after  = Get-Content "$env:TEMP\provemark\after.json"  -Raw | ConvertFrom-Json
"score {0} -> {1}; findings {2} -> {3}" -f $before.score.total, $after.score.total, $before.findings.Count, $after.findings.Count
```

## 其它格式

| 格式 | 用途 | 备注 |
| --- | --- | --- |
| `table` | 人看 | 默认；非 TTY 自动去色 |
| `markdown` | 贴 PR / issue | 含「需要优先处理」段 |
| `html` | 存档、发给人 | 单文件、无外部资源、离线可开（约 30–40KB 起） |
| `sarif` | GitHub Code Scanning | SARIF 2.1.0，按行展示 |
