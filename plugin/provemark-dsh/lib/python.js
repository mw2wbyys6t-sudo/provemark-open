/**
 * Python discovery and one-shot scanner invocation.
 *
 * Shared by the CLI launcher (`bin/provemark.mjs`) and the in-process tools, so
 * "which Python does this package use" has exactly one answer.
 *
 * Probe order: $PROVEMARK_PYTHON → python3 / python / py -3 on PATH → the
 * interpreters bundled with a DSH runtime (~/.dsh/dsh-runtimes/**) → the
 * Electron resources layout named by $DSH_APP_ROOT / $DSH_RESOURCES_DIR.
 */
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, readdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { delimiter, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const PYTHON_ROOT = join(PACKAGE_ROOT, 'python');
export const MIN_PYTHON = { major: 3, minor: 11 };
const IS_WIN = process.platform === 'win32';

const resolved = { value: null };

export function parseVersion(text) {
  const match = /^(\d+)\.(\d+)\.(\d+)/.exec(String(text).trim());
  if (match === null) return null;
  return { major: Number(match[1]), minor: Number(match[2]), patch: Number(match[3]) };
}

export function versionAtLeast(version) {
  if (version === null) return false;
  if (version.major !== MIN_PYTHON.major) return version.major > MIN_PYTHON.major;
  return version.minor >= MIN_PYTHON.minor;
}

export function formatVersion(version) {
  return `${version.major}.${version.minor}.${version.patch}`;
}

function probe(cmd, prefix) {
  const result = spawnSync(
    cmd,
    [...prefix, '-c', 'import sys;print("%d.%d.%d"%sys.version_info[:3])'],
    { encoding: 'utf8', windowsHide: true, timeout: 20000 },
  );
  if (result.error || result.status !== 0) return null;
  return parseVersion(result.stdout ?? '');
}

function runtimeCandidates() {
  const found = [];
  const runtimeRoot = join(homedir(), '.dsh', 'dsh-runtimes');
  try {
    const entries = readdirSync(runtimeRoot, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name)
      .sort()
      .reverse();
    for (const entry of entries) {
      const base = join(runtimeRoot, entry, 'dependencies', 'python');
      found.push(IS_WIN ? join(base, 'python.exe') : join(base, 'bin', 'python3'));
      found.push(join(base, 'bin', 'python3'));
    }
  } catch {
    /* no DSH runtime directory on this host */
  }
  for (const key of ['DSH_APP_ROOT', 'DSH_RESOURCES_DIR']) {
    const value = process.env[key];
    if (!value) continue;
    for (const rel of [
      ['runtime', 'primary-runtime', 'dependencies', 'python'],
      ['resources', 'runtime', 'primary-runtime', 'dependencies', 'python'],
    ]) {
      const base = join(value, ...rel);
      found.push(IS_WIN ? join(base, 'python.exe') : join(base, 'bin', 'python3'));
      found.push(join(base, 'bin', 'python3'));
    }
  }
  return found.filter((candidate, index) => existsSync(candidate) && found.indexOf(candidate) === index);
}

/**
 * Resolve (and cache) the interpreter. Returns `{ python, tried }`, where
 * `python` is null when nothing usable exists.
 *
 * `PROVEMARK_PYTHON=none` is a diagnostics/test switch: it forces "no Python"
 * so the degradation path (banner + actionable tool error) can be exercised
 * without uninstalling a runtime.
 */
export function resolvePython() {
  if (resolved.value !== null) return resolved.value;
  const tried = [];
  const explicit = process.env.PROVEMARK_PYTHON;
  if (explicit === 'none') {
    resolved.value = { python: null, tried: [{ cmd: 'none', prefix: [], ok: false, version: null }] };
    return resolved.value;
  }
  const accept = (cmd, prefix, version) => {
    tried.push({ cmd, prefix, ok: version !== null, version: version && formatVersion(version) });
    return version !== null && versionAtLeast(version) ? { cmd, prefix, version } : null;
  };

  let python = null;
  if (explicit) python = accept(explicit, [], probe(explicit, []));

  if (python === null) {
    for (const [cmd, prefix] of IS_WIN
      ? [['python3', []], ['python', []], ['py', ['-3']]]
      : [['python3', []], ['python', []]]) {
      python = accept(cmd, prefix, probe(cmd, prefix));
      if (python !== null) break;
    }
  }
  if (python === null) {
    for (const candidate of runtimeCandidates()) {
      python = accept(candidate, [], probe(candidate, []));
      if (python !== null) break;
    }
  }

  resolved.value = { python, tried };
  return resolved.value;
}

/** Drop the discovery cache (tests / diagnostics only). */
export function resetPythonCache() {
  resolved.value = null;
}

const status = { value: null, at: 0 };

/**
 * Cheap health probe for the prompt context: "can this plugin scan at all?".
 * Cached for a minute so a broken host still gets retried without paying the
 * probe cost on every step.
 */
export function pythonStatus({ refresh = false, ttlMs = 60_000 } = {}) {
  const now = Date.now();
  if (!refresh && status.value !== null && now - status.at < ttlMs) return status.value;
  const { python, tried } = resolvePython();
  status.value = {
    ready: python !== null,
    version: python === null ? null : formatVersion(python.version),
    cmd: python === null ? null : python.cmd,
    tried,
    at: now,
  };
  status.at = now;
  return status.value;
}

export function scannerEnv(extra = {}) {
  return {
    ...process.env,
    PYTHONPATH: [PYTHON_ROOT, process.env.PYTHONPATH].filter(Boolean).join(delimiter),
    PYTHONUTF8: '1',
    PYTHONIOENCODING: 'utf-8',
    PYTHONDONTWRITEBYTECODE: '1',
    PROVEMARK_PLUGIN_ROOT: PACKAGE_ROOT,
    PROVEMARK_DSH: '1',
    ...extra,
  };
}

/** Whether the vendored scanner is actually present. */
export function scannerPresent() {
  return existsSync(join(PYTHON_ROOT, 'provemark', '__init__.py'));
}

/**
 * Run the scanner once and collect its output. Never rejects for a non-zero
 * exit: the caller decides what a gate failure means.
 */
export function runProvemark(args, { timeoutMs = 60000, signal } = {}) {
  return new Promise((resolvePromise) => {
    const { python } = resolvePython();
    if (python === null) {
      resolvePromise({ code: 2, stdout: '', stderr: 'no Python 3.11+ interpreter found', timedOut: false });
      return;
    }
    if (!scannerPresent()) {
      resolvePromise({ code: 2, stdout: '', stderr: `bundled scanner missing at ${PYTHON_ROOT}`, timedOut: false });
      return;
    }
    const child = spawn(python.cmd, [...python.prefix, '-P', '-B', '-m', 'provemark', ...args], {
      cwd: PACKAGE_ROOT,
      env: scannerEnv(),
      windowsHide: true,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const stdout = [];
    const stderr = [];
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      try {
        child.kill('SIGKILL');
      } catch {
        /* already gone */
      }
    }, timeoutMs);
    const onAbort = () => {
      try {
        child.kill('SIGKILL');
      } catch {
        /* already gone */
      }
    };
    if (signal) {
      if (signal.aborted) onAbort();
      else signal.addEventListener('abort', onAbort, { once: true });
    }
    child.stdout.on('data', (chunk) => stdout.push(chunk));
    child.stderr.on('data', (chunk) => stderr.push(chunk));
    const settle = (code) => {
      clearTimeout(timer);
      if (signal) signal.removeEventListener('abort', onAbort);
      resolvePromise({
        code: code ?? 2,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
        timedOut,
      });
    };
    child.on('error', (error) => {
      clearTimeout(timer);
      resolvePromise({ code: 2, stdout: '', stderr: String(error?.message ?? error), timedOut: false });
    });
    child.on('close', (code) => settle(code));
  });
}

/** Parse the JSON that `scan -f json` prints on stdout. */
export function parseScanJson(stdout) {
  const text = String(stdout ?? '').trim();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    const start = text.indexOf('{');
    const end = text.lastIndexOf('}');
    if (start === -1 || end <= start) return null;
    try {
      return JSON.parse(text.slice(start, end + 1));
    } catch {
      return null;
    }
  }
}
