/**
 * Running the scanner, classifying its output, and caching the last answer.
 *
 * Everything the guardrail shows the model is derived from `scan -f json`, so
 * the numbers here are the scanner's own — the plugin never re-scores anything.
 */
import { existsSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { isAbsolute, parse as parsePath, resolve } from 'node:path';
import { parseScanJson, runProvemark, scannerPresent } from './python.js';
import { severityRank } from './config.js';

/** Rules `provemark fix` can resolve without touching business code. */
export const AUTO_FIXABLE_RULES = new Set([
  'HYG-001', // no LICENSE
  'HYG-002', // no README
  'HYG-003', // no SECURITY.md
  'HYG-004', // no .gitignore
  'HYG-005', // .gitignore does not ignore .env
  'HYG-010', // no CI config
]);

const cache = new Map();

/**
 * Cache key: a scan of one scope is not an answer for another. Asking for
 * `--only pii` after a full scan (or after `--only ai`) must run the scanner
 * again, otherwise the model gets findings from a different question.
 */
function cacheKey(root, scope = '') {
  return `${root}\u0000${scope}`;
}

export function cachedScan(root, scope = '') {
  return cache.get(cacheKey(root, scope)) ?? null;
}

export function rememberScan(root, entry, scope = '') {
  cache.set(cacheKey(root, scope), entry);
  if (cache.size > 32) {
    const oldest = [...cache.entries()].sort((a, b) => a[1].at - b[1].at)[0];
    if (oldest) cache.delete(oldest[0]);
  }
}

export function clearScanCache() {
  cache.clear();
}

/**
 * Turn whatever the caller offered into an absolute, scannable directory.
 * Refuses the filesystem root and the user's home directory: a guardrail that
 * silently scans C:\ or ~ is a performance incident, not a safety net.
 */
export function resolveRoot(candidate) {
  if (typeof candidate !== 'string' || candidate.trim() === '') {
    return { root: null, error: 'no path given' };
  }
  const expanded = candidate.startsWith('~')
    ? resolve(homedir(), candidate.slice(1).replace(/^[\\/]+/, ''))
    : candidate;
  const absolute = isAbsolute(expanded) ? expanded : resolve(process.cwd(), expanded);
  let info;
  try {
    info = statSync(absolute);
  } catch {
    return { root: null, error: `path does not exist: ${absolute}` };
  }
  if (!info.isDirectory()) return { root: null, error: `not a directory: ${absolute}` };
  const parsed = parsePath(absolute);
  const tooBroad = absolute === parsed.root || absolute === homedir();
  if (tooBroad) return { root: null, error: `refusing to scan a filesystem/home root: ${absolute}` };
  return { root: absolute, error: null };
}

export function summarizeScan(result, maxFindings) {
  const score = result?.score ?? {};
  const counts = score.counts ?? result?.counts?.by_severity ?? {};
  const findings = Array.isArray(result?.findings) ? result.findings : [];
  const ordered = [...findings].sort(
    (a, b) => severityRank(b.severity) - severityRank(a.severity) || (b.confidence ?? 0) - (a.confidence ?? 0),
  );
  // The same rule hitting the same normalized line in the same file produces the
  // same fingerprint (SCP-007 on three `uses:` lines of one workflow). For a
  // guardrail bullet, that is one fact, not three: show it once and keep the
  // scanner's own counts untouched.
  const seen = new Set();
  const unique = [];
  for (const finding of ordered) {
    const key = `${finding.rule_id ?? ''}|${finding.fingerprint ?? `${finding.path ?? ''}:${finding.line ?? 0}`}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push(finding);
  }
  const top = unique.slice(0, Math.max(1, maxFindings)).map((finding) => ({
    rule: String(finding.rule_id ?? ''),
    severity: String(finding.severity ?? ''),
    title: String(finding.title ?? ''),
    path: String(finding.path ?? ''),
    cwe: String(finding.detail?.cwe ?? ''),
    owasp: String(finding.detail?.owasp ?? ''),
    line: Number(finding.line ?? 0),
    confidence: Number(finding.confidence ?? 0),
    remediation: String(finding.remediation ?? ''),
    fingerprint: String(finding.fingerprint ?? ''),
    autoFixable: AUTO_FIXABLE_RULES.has(String(finding.rule_id ?? '')),
  }));
  const autoFixable = unique
    .filter((finding) => AUTO_FIXABLE_RULES.has(String(finding.rule_id ?? '')))
    .map((finding) => String(finding.rule_id ?? ''));
  // Every fingerprint with its rule/severity, so a later scan can say *which*
  // findings are new rather than only how many.
  const index = new Map();
  for (const finding of ordered) {
    const fingerprint = String(finding.fingerprint ?? '');
    if (!fingerprint || index.has(fingerprint)) continue;
    index.set(fingerprint, {
      rule: String(finding.rule_id ?? ''),
      severity: String(finding.severity ?? ''),
      path: String(finding.path ?? ''),
    });
  }
  return {
    score: typeof score.total === 'number' ? score.total : null,
    grade: String(score.grade ?? ''),
    reliable: score.reliable !== false,
    counts: {
      critical: Number(counts.critical ?? 0),
      high: Number(counts.high ?? 0),
      medium: Number(counts.medium ?? 0),
      low: Number(counts.low ?? 0),
      info: Number(counts.info ?? 0),
    },
    files: Number(result?.stats?.files_scanned ?? 0),
    packages: Number(result?.stats?.packages_total ?? 0),
    unverified: Number(result?.stats?.packages_unverified ?? 0),
    notes: Array.isArray(result?.stats?.notes) ? result.stats.notes.map(String) : [],
    top,
    autoFixable: [...new Set(autoFixable)],
    fingerprints: new Set(ordered.map((finding) => String(finding.fingerprint ?? '')).filter(Boolean)),
    index,
  };
}

/**
 * Freeze the first scan of a workspace as the session baseline.
 *
 * The point is not "make the repo clean" — a legacy project starts messy and
 * that is allowed. The point is that *this session* must not make it worse:
 * every later scan is compared against this snapshot, so "AI kept patching and
 * the project got worse" becomes a number the model can see.
 */
export function createBaseline(summary) {
  return {
    at: Date.now(),
    score: typeof summary?.score === 'number' ? summary.score : null,
    grade: String(summary?.grade ?? ''),
    counts: { ...(summary?.counts ?? {}) },
    fingerprints: new Set(summary?.fingerprints ?? []),
    index: new Map(summary?.index ?? []),
  };
}

const SEVERITY_RANK_FOR_TREND = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export function compareToBaseline(baseline, summary) {
  if (!baseline || !summary) return null;
  const current = summary.fingerprints ?? new Set();
  const added = [];
  for (const fingerprint of current) {
    if (baseline.fingerprints.has(fingerprint)) continue;
    const info = summary.index?.get(fingerprint) ?? { rule: '', severity: 'medium', path: '' };
    added.push({ fingerprint, ...info });
  }
  const fixed = [];
  for (const fingerprint of baseline.fingerprints) {
    if (current.has(fingerprint)) continue;
    const info = baseline.index?.get(fingerprint) ?? { rule: '', severity: 'medium', path: '' };
    fixed.push({ fingerprint, ...info });
  }
  added.sort(
    (a, b) => (SEVERITY_RANK_FOR_TREND[b.severity] ?? 0) - (SEVERITY_RANK_FOR_TREND[a.severity] ?? 0),
  );
  const worstNew = added[0]?.severity ?? '';
  const scoreDelta =
    typeof summary.score === 'number' && typeof baseline.score === 'number'
      ? Math.round((summary.score - baseline.score) * 10) / 10
      : 0;
  return {
    baselineScore: baseline.score,
    baselineGrade: baseline.grade,
    baselineAt: Number(baseline.at ?? 0),
    crossSession: Boolean(baseline.persisted),
    scoreDelta,
    newCount: added.length,
    fixedCount: fixed.length,
    newFindings: added.slice(0, 8),
    fixedFindings: fixed.slice(0, 8),
    worstNewSeverity: worstNew,
    regressed: added.length > 0,
    improved: added.length === 0 && fixed.length > 0,
  };
}

/** Turn a raw comparison into the one line a model should read. */
export function describeTrend(trend) {
  if (!trend) return '';
  const scope = trend.crossSession ? '跨会话基线' : '本会话基线';
  const baselineText =
    typeof trend.baselineScore === 'number' ? `${scope} ${trend.baselineScore} 分` : scope;
  if (trend.newCount > 0) {
    const list = trend.newFindings
      .slice(0, 4)
      .map((item) => `${item.rule || '?'}${item.path ? `(${item.path})` : ''}`)
      .join('、');
    const severe = ['critical', 'high'].includes(trend.worstNewSeverity);
    return `${severe ? '⛔' : '⚠️'} 较${baselineText}变差：新增 ${trend.newCount} 条问题（${list}${trend.newCount > 4 ? '…' : ''}）。${severe ? '先回退或修掉这些再继续。' : '不要继续扩大改动，先处理新增项。'}`;
  }
  if (trend.fixedCount > 0) {
    const sign = trend.scoreDelta > 0 ? `+${trend.scoreDelta}` : String(trend.scoreDelta);
    return `较${baselineText}：已修掉 ${trend.fixedCount} 条（${sign} 分）。`;
  }
  return `较${baselineText}：无新增。`;
}

export function verdictOf(summary) {
  if (summary.counts.critical > 0 || summary.counts.high > 0) return 'blocking';
  if (summary.counts.medium > 0) return 'warn';
  return 'clean';
}

/**
 * Run one scan. `only` mirrors `scan --only`; an empty string keeps every
 * scanner. Returns a classified summary instead of the raw JSON.
 */
export async function scan({
  root,
  offline = true,
  timeoutMs = 30_000,
  maxFindings = 5,
  only = '',
  signal,
} = {}) {
  if (!scannerPresent()) {
    return { ok: false, error: 'bundled scanner is missing — reinstall provemark-dsh', code: 2 };
  }
  const { root: safeRoot, error } = resolveRoot(root);
  if (safeRoot === null) return { ok: false, error, code: 2 };

  const args = ['scan', safeRoot, '-f', 'json', '--no-color'];
  if (offline) args.push('--offline');
  if (only) args.push('--only', only);

  const startedAt = Date.now();
  const outcome = await runProvemark(args, { timeoutMs, signal });
  const durationMs = Date.now() - startedAt;
  if (outcome.timedOut) {
    return { ok: false, error: `scan timed out after ${Math.round(timeoutMs / 1000)}s`, code: 2, durationMs };
  }
  const result = parseScanJson(outcome.stdout);
  if (result === null) {
    const detail = String(outcome.stderr ?? '').trim().split('\n').slice(-3).join(' ');
    return { ok: false, error: detail || `scan exited ${outcome.code} without JSON`, code: outcome.code, durationMs };
  }
  return { ok: true, root: safeRoot, result, summary: summarizeScan(result, maxFindings), durationMs, code: outcome.code };
}

/** Rules the safe fixer would address, run for real (`--apply` only creates missing files). */
export async function applySafeFixes({ root, timeoutMs = 60_000, only = 'license,gitignore,security,config,ci', signal } = {}) {
  const { root: safeRoot, error } = resolveRoot(root);
  if (safeRoot === null) return { ok: false, error };
  const outcome = await runProvemark(['fix', safeRoot, '--apply', '--only', only], { timeoutMs, signal });
  return {
    ok: outcome.code === 0,
    code: outcome.code,
    output: String(outcome.stdout ?? '').trim(),
    stderr: String(outcome.stderr ?? '').trim(),
  };
}

/** Fingerprints present in `next` but not in `previous` (a regression, not a fix). */
export function newFindings(previous, next) {
  if (!previous || !next) return [];
  return next.top.filter((finding) => finding.fingerprint && !previous.fingerprints.has(finding.fingerprint));
}

export function findBySeverity(summary, minSeverity) {
  const floor = severityRank(minSeverity);
  return summary.top.filter((finding) => severityRank(finding.severity) >= floor);
}

export function isScannableDir(path) {
  try {
    return existsSync(path) && statSync(path).isDirectory();
  } catch {
    return false;
  }
}
