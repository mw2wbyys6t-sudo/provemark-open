/**
 * Config surface for the always-on guardrail.
 *
 * Values come from the loader row config (`cordis.patch.yml`), so users tune
 * the guardrail in their own patch layer and the setting survives upgrades.
 * Nothing here throws: an unknown value falls back to the documented default.
 */

export const DEFAULTS = {
  /** Master switch for the background guardrail (tools + prompt context stay off when false). */
  enabled: true,
  /** Background scans: on first step of a session and after tool activity. */
  autoScan: true,
  /** Minimum gap between two background scans of the same root. */
  autoScanIntervalMs: 120_000,
  /** Reuse a cached scan result within this window. */
  cacheTtlMs: 300_000,
  /** Rescan shortly after the agent touches the workspace, instead of waiting for the interval. */
  scanOnChange: true,
  /** Debounce for that change-triggered rescan (one scan per burst of tool calls). */
  changeDebounceMs: 8_000,
  /** Minimum gap between two change-triggered rescans (protects the session from scan storms). */
  changeMinRescanMs: 30_000,
  /** Persist the first baseline per workspace so "did this get worse?" survives restarts. */
  persistBaseline: true,
  /** Background scans use the network (OSV + deps.dev) so vulnerabilities and licenses are real answers. */
  offline: false,
  /** Hard timeout for one background scan. A 4k-file repo takes ~1-2 minutes; never block the step. */
  timeoutMs: 120_000,
  /** Hard timeout for an interactive tool scan (large repo, many dependencies). */
  toolTimeoutMs: 180_000,
  /** How many findings the prompt context and tool output surface. */
  maxFindings: 5,
  /** `off` never writes; `preview` reports what the safe fixer would do; `apply` writes missing files. */
  autoFix: 'preview',
  /** Inject an agent inbox notice when a background scan finds new high/critical issues. */
  injectOnNewRisk: true,
  /** Severity threshold for that notice. */
  injectMinSeverity: 'high',
  /** Extra globs the scanner should skip, merged into nothing — kept for parity with the CLI. */
  scanOnly: '',
  /** Optional absolute workspace override; when empty the session working directory is used. */
  workspace: '',
  /** Log line prefix; set empty to silence the plugin's own logging. */
  logPrefix: '[provemark]',
};

const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function severityRank(severity) {
  return SEVERITY_RANK[String(severity ?? '').toLowerCase()] ?? 0;
}

function bool(value, fallback) {
  return typeof value === 'boolean' ? value : fallback;
}

function int(value, fallback, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const number = typeof value === 'number' ? value : Number(value);
  if (!Number.isFinite(number)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(number)));
}

export function normalizeConfig(raw) {
  const input = raw && typeof raw === 'object' ? raw : {};
  const autoFix = ['off', 'preview', 'apply'].includes(input.autoFix) ? input.autoFix : DEFAULTS.autoFix;
  const injectMinSeverity = Object.hasOwn(SEVERITY_RANK, String(input.injectMinSeverity ?? ''))
    ? String(input.injectMinSeverity)
    : DEFAULTS.injectMinSeverity;
  return {
    enabled: bool(input.enabled, DEFAULTS.enabled),
    autoScan: bool(input.autoScan, DEFAULTS.autoScan),
    autoScanIntervalMs: int(input.autoScanIntervalMs, DEFAULTS.autoScanIntervalMs, { min: 10_000, max: 3_600_000 }),
    cacheTtlMs: int(input.cacheTtlMs, DEFAULTS.cacheTtlMs, { min: 0, max: 3_600_000 }),
    scanOnChange: bool(input.scanOnChange, DEFAULTS.scanOnChange),
    changeDebounceMs: int(input.changeDebounceMs, DEFAULTS.changeDebounceMs, { min: 1_000, max: 120_000 }),
    changeMinRescanMs: int(input.changeMinRescanMs, DEFAULTS.changeMinRescanMs, { min: 1_000, max: 600_000 }),
    persistBaseline: bool(input.persistBaseline, DEFAULTS.persistBaseline),
    offline: bool(input.offline, DEFAULTS.offline),
    timeoutMs: int(input.timeoutMs, DEFAULTS.timeoutMs, { min: 5_000, max: 600_000 }),
    toolTimeoutMs: int(input.toolTimeoutMs, DEFAULTS.toolTimeoutMs, { min: 10_000, max: 900_000 }),
    maxFindings: int(input.maxFindings, DEFAULTS.maxFindings, { min: 1, max: 20 }),
    autoFix,
    injectOnNewRisk: bool(input.injectOnNewRisk, DEFAULTS.injectOnNewRisk),
    injectMinSeverity,
    scanOnly: typeof input.scanOnly === 'string' ? input.scanOnly.trim() : DEFAULTS.scanOnly,
    workspace: typeof input.workspace === 'string' ? input.workspace.trim() : DEFAULTS.workspace,
    logPrefix: typeof input.logPrefix === 'string' ? input.logPrefix : DEFAULTS.logPrefix,
  };
}
