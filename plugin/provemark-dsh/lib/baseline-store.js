/**
 * Persistent baselines: the ratchet must survive a host restart.
 *
 * Until now the baseline lived in memory, so "did this change make the project
 * worse?" reset every time DeepSeek Harness restarted — exactly when a long
 * maintenance session is most likely to span restarts. This store keeps one
 * compact baseline per workspace under the user's cache area (never inside the
 * scanned repository) and is written atomically.
 *
 * Format: { version: 1, roots: { <sha256(root)[:16]>: { root, at, score, grade,
 *   counts, fingerprints: { <fp>: { rule, severity, path } } } } }
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

const MAX_ROOTS = 50;
const MAX_FINGERPRINTS = 500;

export function baselineFile() {
  return (
    process.env.PROVEMARK_DSH_BASELINE_FILE ||
    join(homedir(), '.dsh', 'provemark-dsh', 'baselines.json')
  );
}

function keyOf(root) {
  return createHash('sha256').update(String(root)).digest('hex').slice(0, 16);
}

function readStore() {
  const file = baselineFile();
  if (!existsSync(file)) return { version: 1, roots: {} };
  try {
    const parsed = JSON.parse(readFileSync(file, 'utf8'));
    if (parsed && typeof parsed === 'object' && parsed.roots && typeof parsed.roots === 'object') {
      return parsed;
    }
  } catch {
    /* a corrupt cache must never break scanning: start fresh */
  }
  return { version: 1, roots: {} };
}

function writeStore(store) {
  const file = baselineFile();
  try {
    mkdirSync(join(file, '..'), { recursive: true });
    const tmp = `${file}.${process.pid}.tmp`;
    writeFileSync(tmp, `${JSON.stringify(store)}\n`, 'utf8');
    renameSync(tmp, file);
    return true;
  } catch {
    return false;
  }
}

/** Load the persisted baseline for a root, shaped like scan.createBaseline(). */
export function loadBaseline(root) {
  const store = readStore();
  const entry = store.roots[keyOf(root)];
  if (!entry || entry.root !== root) return null;
  const index = new Map();
  for (const [fingerprint, info] of Object.entries(entry.fingerprints ?? {})) {
    index.set(fingerprint, info);
  }
  return {
    at: Number(entry.at ?? 0),
    score: typeof entry.score === 'number' ? entry.score : null,
    grade: String(entry.grade ?? ''),
    counts: { ...(entry.counts ?? {}) },
    fingerprints: new Set(Object.keys(entry.fingerprints ?? {})),
    index,
    persisted: true,
  };
}

/** Persist the current baseline for a root (best effort, bounded). */
export function saveBaseline(root, baseline) {
  const store = readStore();
  const fingerprints = {};
  let count = 0;
  for (const fingerprint of baseline.fingerprints ?? []) {
    if (count >= MAX_FINGERPRINTS) break;
    const info = baseline.index?.get(fingerprint) ?? {};
    fingerprints[fingerprint] = {
      rule: String(info.rule ?? ''),
      severity: String(info.severity ?? ''),
      path: String(info.path ?? ''),
    };
    count += 1;
  }
  store.version = 1;
  store.roots[keyOf(root)] = {
    root: String(root),
    at: Number(baseline.at ?? Date.now()),
    score: typeof baseline.score === 'number' ? baseline.score : null,
    grade: String(baseline.grade ?? ''),
    counts: { ...(baseline.counts ?? {}) },
    fingerprints,
  };
  const entries = Object.entries(store.roots).sort((a, b) => Number(b[1].at ?? 0) - Number(a[1].at ?? 0));
  store.roots = Object.fromEntries(entries.slice(0, MAX_ROOTS));
  return writeStore(store);
}

/** Remove one root's baseline (used by tests and by "start over"). */
export function forgetBaseline(root) {
  const store = readStore();
  delete store.roots[keyOf(root)];
  return writeStore(store);
}
