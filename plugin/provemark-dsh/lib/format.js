/**
 * Text the model sees, and the compact shape the tools return.
 *
 * Two audiences:
 *  - `GUARDRAILS` is a static system-prompt section: the rules the scanner
 *    enforces, phrased so the model can follow them *while writing* code.
 *  - `stateText()` is a dynamic per-agent context block: what the last scan of
 *    this workspace said. It stays byte-identical between steps unless a scan
 *    produced a new answer, which keeps the prompt prefix stable.
 */
import { severityRank } from './config.js';

export const SECTION_NAME = 'provemark:guardrails';
export const CONTEXT_NAME = 'provemark:workspace-state';

export const GUARDRAILS = `## Provemark 守卫（常驻）

这个工作区装有本地风险扫描器（Provemark）。写代码时就按下面的红线来，不要等扫描器来指出：

- **依赖**：只 import 真实存在、且已写进清单（package.json / pyproject / requirements / go.mod / Cargo.toml …）的包。要加新依赖时，先确认它存在再写代码，并同步改清单。凭空 import 是 AI 最常见的运行时事故。
- **密钥**：不在源码、测试、示例、注释里写真实 key/token/密码；一律走环境变量，示例统一用尖括号占位（如 \`<API_KEY>\`）。
- **错误处理**：不写静默吞异常的空处理（Python 里 except 后面直接过、JS 里 catch 配空块）；要记录或重新抛出。
- **危险调用**：不用 \`eval\`/\`exec\`、\`pickle.loads\`、\`yaml.load\`（用 safe_load）、\`shell=True\` 拼接用户输入、\`verify=False\`、\`innerHTML\` 塞不可信内容。
- **注入**：SQL 只用参数化查询；命令用参数列表、不经 shell；模板源码不来自用户输入；文件名/URL 先白名单再拼接。
- **认证与加密**：JWT 固定算法并校验签名/exp；口令用 bcrypt/argon2；令牌用 \`secrets\`/\`crypto.randomBytes\`，不用 \`random\`/\`Math.random\`；不关 TLS 证书校验。
- **对外请求与文件**：SSRF 目标用白名单并拒绝私网/回环/169.254.169.254；路径拼接后校验仍在根目录内。
- **配置**：生产不开 debug、不打印堆栈；容器不用 \`privileged\`、不挂 \`docker.sock\`；GitHub Actions 不把事件字段直接插进 \`run:\`。
- **个人信息**：不把真实邮箱、手机号、证件号、银行卡号写进代码或测试；日志里不要打印 PII。
- **许可证**：新增依赖前确认它的 license；GPL/AGPL/SSPL 进入闭源分发链路是合规问题，不是风格问题。
- **供应链**：改依赖时保持锁文件同步；版本别写 \`*\`/\`latest\`；GitHub Action 固定到 SHA；不引入 \`curl … | bash\`。
- **归因**：拷进来的第三方代码（vendor/、third_party/）要有来源记录。

工程常识（全栈，写代码时就按这个来）：
- **接口契约**：先定方法/状态码/错误体/分页；列表接口必须分页；写操作考虑幂等（重试不产生重复副作用）。
- **超时与重试**：任何外部调用都要有超时；重试有限次 + 退避，非幂等写不重试。
- **数据库**：schema 变更走迁移（生产不开 synchronize/dropSchema）；列表查询避免 N+1，循环里别串行 await。
- **复杂度**：按数据量选结构（set/dict 查成员、deque 做队列、堆取 Top-K）；循环里别做 O(n) 查找/字符串拼接/重复排序，别逐条请求外部接口。
- **日志与可观测性**：用结构化日志（不要 print/console.log 当日志），带 request id 与耗时；关键路径有指标。
- **测试**：改行为补测试；覆盖空态/错误态/边界，不只 happy path。

工具与节奏：
- 改完源码或依赖清单后，调用 \`provemark_guard\`（联网、秒级）看有没有新问题；同一个工作区连续改动不必每次都跑。
- 交付前必须至少跑一次 \`provemark_guard\`：\`blocking\`（有致命/高危）时先修，修不动就如实说明，不能宣布完成。

维护纪律（防止"越改越乱"）：
- **只改与当前任务相关的文件**：不做顺手重构、重命名、批量格式化；一轮最多动 3–5 个文件。
- **新增问题必须为 0**：\`provemark_guard\` 返回的 \`trend\` 显示"新增 X 条"时，先回退或修掉这批新增，再继续做别的；不要一边报新增一边扩大改动。
- **基线差的老项目不要一次清空**：先修最高危的一组（按 CWE/严重度），其余登记带原因与到期日的 \`ignore\` 或写进待办，并在回复里说明"这轮只动了这些"。
- **别用 suppress 掩盖回归**：新增问题不能用新加的 \`[[ignore]]\` 消掉；ignore 只用于已确认的历史问题。
- \`autoFixable\` 非空时**直接调用 \`provemark_guard(autoFix: "apply")\` 补齐**（只新增缺失的 LICENSE/.gitignore/SECURITY.md/CI 等文件，不覆盖已有文件、不改业务代码），并在回复里说明补了什么；业务代码的修法用 \`provemark scan --ai-prompt\` 生成指令，不要手改无关代码。
- 不要用 \`ignore\` 或改门禁阈值来"消除"问题；扫描失败或超时要如实说，不要推测成"没有风险"。`;

function plural(number, unit) {
  return `${number}${unit}`;
}

export function stateText(state) {
  if (!state) return '';
  const lines = ['## Provemark 守卫状态'];
  if (state.root) lines.push(`工作区：${state.root}`);
  const health = state.health ?? {};
  if (health.python === false) {
    lines.push('⚠️ 扫描器不可用：未找到 Python 3.11+。');
    lines.push('修复：安装 Python 3.11+（python.org 或系统包管理器），或设置环境变量 `PROVEMARK_PYTHON=<解释器绝对路径>` 后重启宿主；DSH 自带运行时会被自动识别。');
    lines.push('在此之前不要宣称"没有风险"——本插件现在只能提供规则提示，不能给出扫描结论。');
    return lines.join('\n');
  }
  if (health.scanner === false) {
    lines.push('⚠️ 随包扫描器缺失（`python/provemark` 不完整）：插件无法扫描。');
    lines.push('修复：重装插件（`node scripts/install.mjs --copy`），或检查安装目录是否被杀软/同步盘截断。');
    return lines.join('\n');
  }
  if (health.tools === false) {
    lines.push('⚠️ 原生工具未注册（宿主未解析 `@deepseek-ai/dsh-tools`）：只能用技能里的 CLI 兜底，提示词引导仍生效。');
  }
  // "Stale" only means something once a conclusion exists; before the first
  // scan the caption is "pending", not "out of date".
  if (state.stale && state.summary) {
    lines.push(
      '⚠️ 自上次扫描后又有新的工具操作，下面的结论可能已过期；' +
        '交付前先调用 `provemark_guard`（可传 `fresh: true`）确认，别拿旧结论宣布通过。',
    );
  }
  if (state.error) {
    lines.push(`最近扫描失败：${state.error}`);
    if (state.scannedAt) lines.push(`时间：${state.scannedAt}`);
    lines.push('处理：确认扫描器可用后重试 `provemark_guard`；在此之前不要宣称"没有风险"。');
    return lines.join('\n');
  }
  if (!state.summary) {
    if (state.scanning) {
      lines.push('首次扫描进行中…（大仓库可能需要几十秒；可以继续其他工具调用，结果出来后会出现在这里）。');
    } else {
      lines.push('尚未扫描：本会话还没有可用的扫描结果（首次扫描会在下一步自动进行）。');
    }
    return lines.join('\n');
  }
  const summary = state.summary;
  const flags = [];
  if (!summary.reliable) flags.push('数据不完整，分数仅供参考');
  if (summary.unverified > 0) flags.push(`${summary.unverified} 个依赖未做漏洞查询`);
  lines.push(
    `最近扫描：${state.scannedAt}${state.cached ? '（缓存）' : ''} · ${state.mode} · ` +
      `${plural(summary.files, ' 个文件')} · ${plural(summary.packages, ' 个依赖')}`,
  );
  lines.push(
    `结论：${summary.score === null ? '—' : `${summary.score}/100`} ${summary.grade} · ` +
      `致命 ${summary.counts.critical} / 高危 ${summary.counts.high} / 中危 ${summary.counts.medium} / ` +
      `低危 ${summary.counts.low} / 提示 ${summary.counts.info}`,
  );
  if (flags.length > 0) lines.push(`注意：${flags.join('；')}`);
  if (state.trendText) lines.push(state.trendText);
  if (summary.top.length === 0) {
    lines.push('没有需要处理的问题——可以继续，但改动后要重新确认。');
  } else {
    lines.push('优先处理：');
    for (const finding of summary.top.slice(0, 3)) {
      const where = finding.path ? ` ${finding.path}${finding.line ? `:${finding.line}` : ''}` : '';
      const confidence = finding.confidence > 0 && finding.confidence < 0.6 ? '（需人工确认）' : '';
      lines.push(`- [${finding.severity}] ${finding.rule} ${finding.title}${where}${confidence}`);
      if (finding.remediation) lines.push(`  修法：${finding.remediation}`);
    }
  }
  if (summary.autoFixable.length > 0) {
    lines.push(`可自动修：${[...new Set(summary.autoFixable)].join('、')} —— 需要时调用 provemark_guard(autoFix="apply")。`);
  }
  const ledger = state.ledger;
  if (ledger && ledger.scans > 0) {
    const parts = [`自动扫描 ${ledger.scans} 次`];
    if (ledger.blocking > 0) parts.push(`累计拦下高危 ${ledger.blocking} 次`);
    lines.push(`本会话：${parts.join(' · ')}。`);
  }
  return lines.join('\n');
}

export function toolText(payload) {
  const head = payload.cached ? `（缓存结果，${payload.durationMs}ms）` : `（${payload.durationMs}ms）`;
  if (payload.verdict === 'error') {
    const message = String(payload.message ?? '');
    let hint = '处理：不要据此判断"没有风险"；先确认 Python/扫描器可用（`--pm-info`），再重试。';
    if (/no Python 3.11\+|未找到 Python/i.test(message)) {
      hint =
        '处理：这台机器没有可用的 Python 3.11+。让用户安装 Python（python.org / 系统包管理器），' +
        '或设置 `PROVEMARK_PYTHON=<解释器绝对路径>` 后重启宿主；装好后重试。在此之前不要宣称"没有风险"。';
    } else if (/无法扫描：/.test(message)) {
      hint = '处理：按上面的提示修正 path 后重试（需要的是目录，不是文件）。';
    } else if (/未知扫描器|unknown scanner/i.test(message)) {
      hint = '处理：only/skip 只能用 repo, secrets, pii, ai, dependency, license, supply, fossa。改用合法值重试，不要把它当成"通过"。';
    } else if (/timed out/i.test(message)) {
      hint = '处理：仓库太大。用 `only` 缩小到关键维度，或让用户调大 `toolTimeoutMs` / 关掉 `autoScan`。在此之前不要宣布通过。';
    }
    return `Provemark 扫描失败：${message}\n${hint}`;
  }
  const counts = payload.counts;
  const lines = [
    `Provemark ${payload.root}`,
    `分数 ${payload.score}/100 ${payload.grade}${payload.reliable ? '' : '（数据不完整，仅供参考）'} · ` +
      `致命 ${counts.critical} / 高危 ${counts.high} / 中危 ${counts.medium} / ` +
      `低危 ${counts.low} / 提示 ${counts.info} ${head}`,
    `判定：${payload.verdict === 'blocking' ? '阻断（存在致命/高危）' : payload.verdict === 'warn' ? '需关注' : '通过'}`,
  ];
  if (payload.trend) lines.push(payload.trend);
  if (payload.verdict === 'blocking' && payload.newFindings > 0) {
    lines.push('这次改动让项目变差了：先回退/修掉新增项，再继续别的改动。');
  }
  if (payload.findings.length > 0) {
    lines.push('', '需要处理：');
    for (const finding of payload.findings) {
      const where = finding.path ? ` ${finding.path}${finding.line ? `:${finding.line}` : ''}` : '';
      const mapping = finding.cwe ? `（${finding.cwe}${finding.owasp ? ` · ${finding.owasp}` : ''}）` : '';
      const confidence = finding.confidence > 0 && finding.confidence < 0.6 ? ` 置信度 ${finding.confidence}（需人工确认）` : '';
      lines.push(`- [${finding.severity}] ${finding.rule} ${finding.title}${where}${mapping}${confidence}`);
      lines.push(`  修法：${finding.remediation}`);
      if (finding.fingerprint) lines.push(`  fingerprint: ${finding.fingerprint}`);
    }
  }
  if (payload.autoFixable.length > 0) {
    lines.push('', `可自动修：${payload.autoFixable.join('、')}（调用 provemark_guard(autoFix="apply")）。`);
  }
  for (const note of payload.notes) lines.push(`注：${note}`);
  if (payload.message) lines.push('', payload.message);
  return lines.join('\n');
}

export function severityOf(finding) {
  return severityRank(finding.severity);
}
