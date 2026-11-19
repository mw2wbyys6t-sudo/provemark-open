/**
 * Capability configuration surface (`Config`) for the guard plugin.
 *
 * A "tool & capability" plugin should be discoverable and tunable from the
 * plugin page, not only by hand-editing the profile patch. The Host validates
 * a row's `config` against this schema before activation, so every knob the
 * plugin reads has to be declared here — `scripts/validate.mjs` checks that the
 * two lists (this schema and `lib/config.js` DEFAULTS) cannot drift apart.
 *
 * Why the schema is loaded dynamically instead of `import z from ...`:
 * this package intentionally ships zero dependencies and is usually installed
 * as a `link:` directory with no `node_modules` of its own, so a static import
 * of the Host's schemastery would make the whole plugin fail to load. We try a
 * bare specifier first (works when the package is installed with deps), then
 * the Electron resources layout, and finally degrade to "no schema" — the
 * plugin keeps working with `cordis.patch.yml` config exactly as before.
 *
 * None of the fields are volatile on purpose: `apply()` reads the settings once
 * and builds its caches from them, so a changed value must restart the plugin
 * rather than silently pretend to be live.
 */

import { isAbsolute, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const rawCandidates = [];
const explicit = process.env.PROVEMARK_DSH_SCHEMASTERY_MODULE;
if (explicit) rawCandidates.push(explicit);
rawCandidates.push('@deepseek-ai/schemastery');
if (process.resourcesPath) {
  for (const root of ['app.asar', 'app.asar.unpacked']) {
    rawCandidates.push(
      pathToFileURL(join(process.resourcesPath, root, 'dsh', 'node_modules', '@deepseek-ai', 'schemastery', 'lib', 'index.mjs'))
        .href,
    );
  }
}

/**
 * `import()` needs a URL or a bare specifier — a raw Windows path throws
 * ERR_UNSUPPORTED_ESM_URL_SCHEME. Accept either form from the environment.
 */
function toSpecifier(value) {
  const text = String(value ?? '').trim();
  if (!text) return null;
  if (/^[a-zA-Z]:[\\/]/.test(text)) return pathToFileURL(resolve(text)).href;
  if (/^(file|data|node):/i.test(text)) return text;
  if (isAbsolute(text) || text.startsWith('.')) return pathToFileURL(resolve(text)).href;
  return text;
}

const candidates = rawCandidates.map(toSpecifier).filter(Boolean);

let z = null;
let resolvedFrom = '';
const failures = [];
for (const specifier of candidates) {
  try {
    const module = await import(specifier);
    const candidate = module?.default ?? module;
    if (candidate && typeof candidate.object === 'function' && typeof candidate.string === 'function') {
      z = candidate;
      resolvedFrom = specifier;
      break;
    }
    failures.push(`${specifier}: no schema factory`);
  } catch (error) {
    failures.push(`${specifier}: ${String(error?.code ?? error?.message ?? error)}`);
  }
}

/** One entry per declared field, so the validator can compare it with DEFAULTS. */
export const CONFIG_FIELDS = [
  'enabled',
  'autoScan',
  'autoScanIntervalMs',
  'cacheTtlMs',
  'scanOnChange',
  'changeDebounceMs',
  'changeMinRescanMs',
  'persistBaseline',
  'offline',
  'timeoutMs',
  'toolTimeoutMs',
  'maxFindings',
  'autoFix',
  'injectOnNewRisk',
  'injectMinSeverity',
  'scanOnly',
  'workspace',
  'logPrefix',
];

export const CONFIG_SCHEMA_STATUS = {
  available: z !== null,
  source: resolvedFrom,
  failures,
};

function build(schema) {
  const bound = (field, { min, max, def, description }) => {
    let value = field;
    if (min !== undefined && typeof value.min === 'function') value = value.min(min);
    if (max !== undefined && typeof value.max === 'function') value = value.max(max);
    if (def !== undefined) value = value.default(def);
    if (description && typeof value.description === 'function') value = value.description(description);
    return value;
  };
  const bool = (def, description) => bound(schema.boolean(), { def, description });
  const number = (def, description, min, max) => bound(schema.number(), { def, description, min, max });
  const text = (def, description) => bound(schema.string(), { def, description });
  const oneOf = (values, def, description) => {
    try {
      if (typeof schema.union === 'function' && typeof schema.const === 'function') {
        return bound(schema.union(values.map((value) => schema.const(value))), { def, description });
      }
    } catch {
      /* fall through to a plain string field */
    }
    return text(def, `${description}（可选值：${values.join(' / ')}）`);
  };

  return schema.object({
    enabled: bool(true, '总开关：关闭后不注册工具、不扫描，只保留空插件行'),
    autoScan: bool(true, '后台扫描：会话首步 + 工具活动后自动重扫'),
    autoScanIntervalMs: number(120000, '两次后台扫描的最小间隔（毫秒）', 10000, 3600000),
    cacheTtlMs: number(300000, '扫描结果缓存有效期（毫秒）', 0, 3600000),
    scanOnChange: bool(true, '工具活动后触发一次去抖重扫，而不是等固定间隔'),
    changeDebounceMs: number(8000, '批量改动的去抖窗口（毫秒）', 1000, 120000),
    changeMinRescanMs: number(30000, '两次「改动触发」重扫的最小间隔（毫秒）', 1000, 600000),
    persistBaseline: bool(true, '把每个工作区的首个基线持久化，跨重启比较趋势'),
    offline: bool(false, '默认离线：跳过 OSV/deps.dev 查询（漏洞与许可证标为未验证）'),
    timeoutMs: number(120000, '后台扫描超时（毫秒）', 5000, 600000),
    toolTimeoutMs: number(180000, '工具调用（显式扫描/进度）超时（毫秒）', 10000, 900000),
    maxFindings: number(5, '状态块与工具输出里展示的问题条数', 1, 20),
    autoFix: oneOf(['off', 'preview', 'apply'], 'preview', '安全修复模式：apply 只新增缺失文件，绝不改业务代码'),
    injectOnNewRisk: bool(true, '后台扫描发现新增高危/致命时，向会话推一条提醒'),
    injectMinSeverity: oneOf(['info', 'low', 'medium', 'high', 'critical'], 'high', '触发提醒的最低严重度'),
    scanOnly: text('', '只运行指定扫描器（逗号分隔），留空表示全部'),
    workspace: text('', '强制扫描根目录；留空使用会话工作目录'),
    logPrefix: text('[provemark]', '插件日志前缀；留空则静默'),
  });
}

export const Config = z === null ? undefined : build(z);
