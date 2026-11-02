/**
 * One-shot "is this install actually usable?" report.
 *
 * Landing a plugin is mostly about the first five minutes: is it linked into a
 * profile, did the host load it, is there a Python to run the scanner, is the
 * bundled scanner complete, are the shipped copies in sync? This script answers
 * those in one command and prints the exact fix for each failure.
 *
 *   node scripts/doctor.mjs          # human report, exit 1 on any failure
 *   node scripts/doctor.mjs --json   # machine-readable
 */
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = resolve(HERE, '..');
const json = process.argv.includes('--json');
const checks = [];

function run(label, command, args, { optional = false } = {}) {
  const started = Date.now();
  const result = spawnSync(command, args, { cwd: PACKAGE_ROOT, encoding: 'utf8', timeout: 120_000, windowsHide: true });
  return {
    label,
    optional,
    ok: !result.error && result.status === 0,
    status: result.status,
    error: result.error ? String(result.error.message ?? result.error) : null,
    stdout: String(result.stdout ?? ''),
    stderr: String(result.stderr ?? ''),
    ms: Date.now() - started,
  };
}

function push(label, ok, detail, advice) {
  checks.push({ label, ok: Boolean(ok), detail: detail ?? '', advice: ok ? '' : advice ?? '' });
}

// 1) installed into a profile?
const dshHome = process.env.DSH_HOME || join(homedir(), '.dsh');
const profilesRoot = join(dshHome, 'profiles');
let install = null;
try {
  const { readdirSync } = await import('node:fs');
  for (const name of readdirSync(profilesRoot, { withFileTypes: true }).filter((entry) => entry.isDirectory()).map((entry) => entry.name)) {
    const linked = join(profilesRoot, name, 'node_modules', 'provemark-dsh', 'package.json');
    if (existsSync(linked)) {
      install = { profile: name, path: linked };
      break;
    }
  }
} catch {
  /* no profiles directory yet */
}
push(
  'profile link',
  install !== null,
  install ? `profile ${install.profile}` : `no provemark-dsh under ${profilesRoot}`,
  'run: node scripts/install.mjs --dry-run  (then without --dry-run)',
);

// 2) did a running host load it?
const marker = join(tmpdir(), 'provemark-dsh-loaded.json');
let loaded = null;
if (existsSync(marker)) {
  try {
    loaded = JSON.parse(readFileSync(marker, 'utf8'));
  } catch {
    loaded = null;
  }
}
const packageVersion = JSON.parse(readFileSync(join(PACKAGE_ROOT, 'package.json'), 'utf8')).version;
push(
  'host load',
  loaded !== null,
  loaded ? `pid ${loaded.pid}, v${loaded.version}, ${loaded.at}` : 'no activation marker',
  'restart DeepSeek Harness (marker is written on every load)',
);
if (loaded) {
  push(
    'host version',
    loaded.version === packageVersion,
    `host v${loaded.version}, package v${packageVersion}`,
    'the running host still executes the old build — restart DeepSeek Harness to load the new version',
  );
  const stages = loaded.diag?.stages ?? {};
  push('tools registered', /^ok:/.test(String(stages.toolsRegistration ?? '')), String(stages.toolsRegistration ?? 'unknown'), 'check diag.warnings in the marker; the host may not resolve @deepseek-ai/dsh-tools');
}

// 3) Python + vendored scanner
const version = run('scanner --version', process.execPath, [
  join(PACKAGE_ROOT, 'bin', 'provemark.mjs'),
  '--pm-info',
]);
let info = null;
try {
  info = JSON.parse(version.stdout);
} catch {
  info = null;
}
push(
  'python 3.11+',
  info?.python != null,
  info?.python ? `${info.python.version ?? 'found'}` : 'not found',
  'install Python 3.11+, or set PROVEMARK_PYTHON=<interpreter>; DSH bundled runtimes are auto-detected',
);
push(
  'vendored scanner',
  existsSync(join(PACKAGE_ROOT, 'python', 'provemark', '__init__.py')),
  'python/provemark/__init__.py',
  'reinstall with: node scripts/install.mjs --copy',
);

// 4) package integrity + shipped copy drift
const validate = run('validate', process.execPath, [join(PACKAGE_ROOT, 'scripts', 'validate.mjs')]);
push('manifest/patch/skill', validate.ok, validate.ok ? '' : validate.stderr.trim().split('\n').slice(-3).join(' | '), 'fix the reported file, then rerun');
const sync = run('vendor sync', process.execPath, [join(PACKAGE_ROOT, 'scripts', 'sync-vendor.mjs'), '--check']);
push('vendor in sync', sync.ok, sync.ok ? '' : sync.stderr.trim() || sync.stdout.trim(), 'run: node scripts/sync-vendor.mjs');

// 5) scanner selftest (host contract)
const selftest = run('selftest', process.execPath, [join(PACKAGE_ROOT, 'scripts', 'selftest.mjs')]);
push('host-contract selftest', selftest.ok, selftest.ok ? '' : selftest.stderr.trim().split('\n').slice(-5).join(' | '), 'see the failing assertion above');

const failed = checks.filter((check) => !check.ok);
if (json) {
  console.log(JSON.stringify({ ok: failed.length === 0, checks }, null, 2));
} else {
  console.log('[doctor] provemark-dsh install report');
  for (const check of checks) {
    console.log(`  ${check.ok ? 'OK  ' : 'FAIL'} ${check.label.padEnd(24)} ${check.detail}`);
    if (!check.ok && check.advice) console.log(`       → ${check.advice}`);
  }
  console.log(failed.length === 0 ? '[doctor] pass' : `[doctor] ${failed.length} problem(s)`);
  console.log('[doctor] cold start: restart DeepSeek Harness once after upgrading, then rerun — "host version" must match the package.');
}
process.exit(failed.length === 0 ? 0 : 1);
