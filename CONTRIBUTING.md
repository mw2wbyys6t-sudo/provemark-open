# 参与开发

这个项目的目标是**零第三方运行时依赖、本地优先、结论可解释**。改代码前请先读完这一页，能省掉一轮返工。

## 环境

```bash
git clone <repo> && cd provemark
python -m unittest discover -s tests -v     # 不需要 pip install
python -m provemark scan . --offline     # 对自身做一次狗粮扫描
```

- Python 3.11+（用到了 `tomllib`），macOS / Linux / Windows 都可以。
- 运行时只用标准库；**不要给 `dependencies` 加包**。确实需要可选能力时，像 `.provemark.yml` 那样做成「缺失就报错并给替代方案」。

## 提交前必须跑

```bash
python -m unittest discover -s tests          # 必须全绿
python -m provemark scan . --offline --fail-on high   # 自身不能有高危
```

第一条保证行为，第二条保证这个「查别人」的工具自己不被查出高危。

## 加一条规则

1. 在 `provemark/rules/catalog.py` 的 `MANUAL` 里登记 `id` / `title` / `severity` / `category` / `message` / `remediation`。
   `provemark explain <ID>` 直接读这里，缺字段会导致测试失败。
2. 在对应扫描器里 `make_finding(...)` 产出问题。规则 ID 用 `前缀-三位数字`（`SEC` / `AI` / `DEP` / `LIC` / `SCP` / `HYG` / `FOS` / `IGN`）。
3. **必须能说出「为什么是问题」和「怎么改」**。只报现象不给修法的规则不接受。
4. 补测试，并在真实仓库上验证误报率——宁可规则少一条，也不要让用户在一堆噪音里找真问题。

误报处理优先级：先收紧匹配条件 → 再考虑降级严重度 → 最后才是豁免。规则里的豁免必须带原因和到期日。

## 加一个生态

1. 在 `provemark/ecosystems.py` 的 `ECOSYSTEMS` 加一行：OSV 生态名、deps.dev 系统名、许可证来源、锁文件名。
2. 在 `MANIFESTS` 里登记清单文件名（支持 glob）。
3. 在 `provemark/scanners/manifests.py` 写解析函数并挂到 `HANDLERS`；无法解析的字段留空，**不要猜**。
4. 在 `tests/fixtures/ecosystems/<名字>/` 放一份最小清单 + `expected.json`。CI 会自动发现目录并生成矩阵，
   测试里的「每个生态都要有 fixture」断言也会拦住漏加。
5. 版本号能精确就精确（`plain_version`），拿不到就留空——留空会走「无法确定版本」的提示路径，而不是假装覆盖。

## 调检测规则：先加评测用例

改匹配条件、阈值、别名表之前，先在 `tests/quality/cases/<名字>/` 加一个用例：

```text
tests/quality/cases/my-case/
├── case.json      # {"scope": ["AI-012"], "expect": [], "forbid": ["AI-012"], "risk": "防什么"}
└── src/app.py     # 一份最小可复现代码
```

- `scope`：只评估这些规则，其他规则的输出不参与统计；
- `expect`：必须命中的规则；`forbid`：绝不允许出现的规则；
- `risk`：一句话说明这个用例防的是哪种误报/漏报（没有写明风险的用例不接受）。

跑单个用例：

```bash
QUALITY_CASE=my-case python -m unittest discover -s tests -p "test_quality.py" -v
```

全量跑时会汇总 precision / recall，低于 0.85 / 0.90 直接失败。**先看数字，再改规则**；只凭感觉放宽阈值一定会把误报带回来。

## 置信度怎么写

新规则如果是启发式（猜的），必须给 `confidence`，别默认 1.0：

| 确定性 | 举例 | 建议 |
| --- | --- | --- |
| 完全确定 | 文件不存在、明文 HTTP、`permissions: write-all` | `1.0` |
| 强启发 | import 未声明的包、SBOM 冲突 | `0.8–0.9` |
| 弱启发 | 高熵字符串、名字近似仿冒 | `0.4–0.65` |

`gate.min_confidence` 默认 `0.5`，低于阈值的问题照样进报告，只是不阻断 CI——这样既不会漏掉线索，也不会用噪音拦住提交。

confidence 同时是**评分权重**：扣分按 `有效次数 = Σ confidence` 折算。所以别为了"保险"统一写 1.0，那等于把猜测当事实扣分；也别随手写 0.1，那会让真问题失去分量。

## 代码约定

- 只用标准库。网络请求统一走 `net.py`（带超时、重试、`NetworkError`）。
- 扫描器失败不能拖垮整次扫描：`engine.py` 会捕获单个扫描器的异常并记 note，扫描器内部也要对单个文件容错。
- 证据（evidence）里**绝不能出现完整凭据**，只保留首尾各 4 位；文件名、行号、指纹要稳定，便于基线豁免。
- 注释和错误信息用中文，错误信息要包含「怎么修」。
- 配置解析必须校验类型与枚举，非法值立即报 `ConfigError`，不要 `int()` 直接转或静默降级。
- 新增文件写失败、路径不存在这类错误，返回退出码 2 并给出可执行的下一步，不抛 traceback。

## 目录速查

| 路径 | 职责 |
| --- | --- |
| `cli.py` | 子命令与退出码 |
| `engine.py` | 扫描编排、严重度覆盖、基线、门禁 |
| `ecosystems.py` | 生态注册表（唯一事实来源） |
| `scanners/` | 6 个扫描器 + 依赖解析（`deps.py` / `manifests.py`） |
| `rules/` | 规则数据、许可证元数据、解释目录 |
| `report/` | table / json / markdown / sarif / html |
| `fossa_deps.py` | `fossa-deps` 生成器 |
| `plugin/provemark-dsh/` | DeepSeek Harness 插件包（常驻守卫、工具、技能） |

## 插件开发（DeepSeek Harness 集成）

```bash
cd plugin/provemark-dsh
node scripts/validate.mjs     # 清单 / patch / SKILL / 随包源码
node scripts/selftest.mjs     # 模拟宿主跑通工具 + 扫描 + 事件钩子
node scripts/sync-vendor.mjs  # 改了仓库根 provemark/ 之后同步随包副本
node scripts/doctor.mjs       # 安装、宿主加载、Python、工具注册一次体检
node scripts/stress.mjs       # 暴力测试：边界输入 / 并发 / 安装生命周期 / 报告格式
```

- **随包源码必须与仓库根一致**：改完 `provemark/**` 一定跑 `sync-vendor.mjs`，否则 `test_plugin` 会失败；
- 插件逻辑（`lib/**`）改动要先在同一进程模拟里回归（`selftest.mjs`），再装到真实 profile 验证；
- 发布：`node scripts/release.mjs --version x.y.z`（三道门禁 + 版本同步 + tarball + SHA-256），脚本不执行 `npm publish`。

