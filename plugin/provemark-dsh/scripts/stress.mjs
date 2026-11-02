/**
 * Stress / brute-force pass for the plugin before a public release.
 *
 * Covers what the deterministic unit suite does not: persistence limits, cache
 * and concurrency behaviour, malformed host events, config abuse, CLI edge
 * inputs (empty / unicode / huge / symlink cycles / drive root / home), report
 * formats, and the full install → check → reinstall → uninstall lifecycle in a
 * throw-away DSH home.
 *
 *   node scripts/stress.mjs            # full pass
 *   node scripts/stress.mjs --quick    # skip the slow CLI cycle
 *
 * Uses temp directories and env overrides only; never touches the real profile,
 * the real activation marker, or the real baseline cache.
 */
import { spawnSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const REPO = resolve(ROOT, '..', '..');
const QUICK = process.argv.includes('--quick');
const scratch = mkdtempSync(join(tmpdir(), 'provemark-stress-'));
const failures = [];
const notes = [];
let checks = 0;

function check(label, ok, detail = '') {
  checks += 1;
  if (ok) {
    console.log(`  ok   ${label}`);
  } else {
    failures.push({ label, detail });
    console.log(`  FAIL ${label}${detail ? ` — ${detail}` : ''}`);
  }
}

function temp(name) {
  const dir = join(scratch, name);
  mkdirSync(dir, { recursive: true });
  return dir;
}

function write(file, content) {
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, content);
}

function runNode(args, { cwd = ROOT, env = process.env, timeout = 60_000 } = {}) {
  const started = Date.now();
  const result = spawnSync(process.execPath, args, {
    cwd,
    env,
    encoding: 'utf8',
    timeout,
    windowsHide: true,
    maxBuffer: 32 * 1024 * 1024,
  });
  return {
    code: result.status,
    signal: result.signal,
    stdout: String(result.stdout ?? ''),
    stderr: String(result.stderr ?? ''),
    ms: Date.now() - started,
  };
}

function cli(args, options = {}) {
  return runNode([join(ROOT, 'bin', 'provemark.mjs'), ...args], options);
}

const smallRepo = temp('repo-small');
write(join(smallRepo, 'pyproject.toml'), '[project]\nname = "stress-demo"\nversion = "0.1"\n');
write(join(smallRepo, 'README.md'), '# stress demo\n');
write(join(smallRepo, 'LICENSE'), 'MIT License\n');
write(join(smallRepo, 'SECURITY.md'), '# Security\n');
write(join(smallRepo, '.gitignore'), 'node_modules\n');
write(join(smallRepo, 'pkg', 'app.py'), 'def add(a, b):\n    return a + b\n');

// ---------------------------------------------------------------- 1. baseline store
console.log('\n[1/5] baseline store limits');
{
  const storeFile = join(scratch, 'baselines.json');
  process.env.PROVEMARK_DSH_BASELINE_FILE = storeFile;
  const store = await import(pathToFileURL(join(ROOT, 'lib', 'baseline-store.js')).href);
  const summary = (score) => ({
    at: Date.now(),
    score,
    grade: 'A',
    counts: { high: 0 },
    fingerprints: new Set([`fp-${score}`]),
    index: new Map([[`fp-${score}`, { rule: 'HYG-001', severity: 'low', path: '' }]]),
  });

  for (let index = 0; index < 60; index += 1) {
    store.saveBaseline(join(scratch, 'roots', `r${index}`), summary(90 + index));
  }
  const raw = JSON.parse(readFileSync(storeFile, 'utf8'));
  check('store prunes to 50 workspaces', Object.keys(raw.roots).length === 50, `got ${Object.keys(raw.roots).length}`);
  check('newest workspace is still present', Boolean(store.loadBaseline(join(scratch, 'roots', 'r59'))));

  const unicodeRoot = join(scratch, 'weird', '中文 空格 & symbols');
  store.saveBaseline(unicodeRoot, summary(88));
  const loadedUnicode = store.loadBaseline(unicodeRoot);
  check('unicode + spaces round-trip', loadedUnicode?.score === 88);

  const manyFingerprints = {
    at: Date.now(),
    score: 70,
    grade: 'C',
    counts: {},
    fingerprints: new Set(Array.from({ length: 600 }, (_, index) => `bulk-${index}`)),
    index: new Map(Array.from({ length: 600 }, (_, index) => [`bulk-${index}`, { rule: 'X', severity: 'low', path: '' }])),
  };
  store.saveBaseline(join(scratch, 'roots', 'bulk'), manyFingerprints);
  check('fingerprint list is capped at 500', store.loadBaseline(join(scratch, 'roots', 'bulk'))?.fingerprints.size === 500);

  writeFileSync(storeFile, '{ this is not json', 'utf8');
  check('corrupt store degrades to empty, not a crash', store.loadBaseline(join(scratch, 'roots', 'r1')) === null);
  store.saveBaseline(join(scratch, 'roots', 'after-corrupt'), summary(95));
  check('store rewrites cleanly after corruption', store.loadBaseline(join(scratch, 'roots', 'after-corrupt'))?.score === 95);
}

// ---------------------------------------------------------------- 2. plugin runtime
console.log('\n[2/5] plugin runtime');
{
  process.env.PROVEMARK_DSH_TOOLS_MODULE = pathToFileURL(join(scratch, 'fake-tools.mjs')).href;
  process.env.PROVEMARK_DSH_MARKER = join(scratch, 'marker.json');
  write(join(scratch, 'fake-tools.mjs'), 'export const defineTool = (definition) => definition;\n');

  const { apply } = await import(pathToFileURL(join(ROOT, 'lib', 'index.js')).href);
  const registered = { sections: [], contexts: [], tools: [], listeners: new Map() };
  const ctx = {
    logger: { info() {}, warn() {}, error() {} },
    effect(fn) {
      const dispose = fn();
      return typeof dispose === 'function' ? dispose : () => {};
    },
    on(event, handler) {
      registered.listeners.set(event, handler);
      return () => {};
    },
    inject(services, callback) {
      const provided = {};
      provided.effect = (fn) => {
        const dispose = fn();
        return typeof dispose === 'function' ? dispose : () => {};
      };
      for (const service of services) {
        if (service === 'systemPrompt') {
          provided.systemPrompt = {
            section: (options) => registered.sections.push(options),
            context: (options) => registered.contexts.push(options),
          };
        } else if (service === 'tools') {
          provided.tools = { register: (definition) => registered.tools.push(definition) };
        } else if (service === 'workingDirectory') {
          provided.workingDirectory = { get: (session) => session?.cwd ?? null };
        }
      }
      callback(provided);
    },
  };
  apply(ctx, { autoScan: true, offline: true, autoFix: 'off', logPrefix: '[stress]' });
  const sleep = (ms) => new Promise((resolveSleep) => setTimeout(resolveSleep, ms));
  for (let waited = 0; waited < 5_000; waited += 100) {
    if (registered.tools.length >= 2) break;
    await sleep(100);
  }
  const agent = { session: { id: 'stress', cwd: smallRepo }, inject: () => {}, ctx: { fiber: { assertActive() {} } } };
  const context = registered.contexts[0];
  const guard = registered.tools.find((tool) => tool.name === 'provemark_guard');
  check('both tools register under the fake host module', Boolean(guard) && registered.tools.length === 2);

  check('exactly one context is registered', registered.contexts.length === 1);
  let renderError = null;
  let longest = 0;
  try {
    for (let index = 0; index < 40; index += 1) {
      const text = context?.text?.({ agent }) ?? '';
      longest = Math.max(longest, text.length);
    }
  } catch (error) {
    renderError = String(error?.message ?? error);
  }
  check('40 consecutive context renders do not throw', renderError === null, renderError ?? '');
  check('state block stays bounded', longest < 12_000, `${longest} chars`);

  const results = guard
    ? await Promise.all(
        Array.from({ length: 20 }, () => guard.execute({ path: smallRepo, offline: true, maxFindings: 1 }, {})),
      )
    : [];
  check(
    '20 concurrent guard calls all resolve',
    results.length === 20 && results.every((item) => item.root === smallRepo),
    guard ? '' : 'guard tool was not registered',
  );

  const listener = registered.listeners.get('session/event');
  let eventError = null;
  const weird = [
    null,
    undefined,
    {},
    { type: 'tool/result' },
    { type: 'tool/result', data: { error: new Error('x') } },
    { type: 'user/message', data: { content: 'x'.repeat(100_000) } },
    { type: 42 },
  ];
  try {
    for (const event of weird) listener?.(agent.session, event);
    listener?.(null, { type: 'tool/result' });
    listener?.({ id: 'other' }, { type: 'user/message', data: {} });
  } catch (error) {
    eventError = String(error?.message ?? error);
  }
  check('malformed session events are tolerated', eventError === null, eventError ?? '');

  const { normalizeConfig } = await import(pathToFileURL(join(ROOT, 'lib', 'config.js')).href);
  const abused = normalizeConfig({
    autoScanIntervalMs: -5,
    toolTimeoutMs: Number.POSITIVE_INFINITY,
    maxFindings: 1e9,
    autoFix: 'nonsense',
    offline: 'yes',
    persistBaseline: 'no',
  });
  check(
    'config clamps hostile values',
    abused.autoScanIntervalMs >= 10_000 && abused.maxFindings <= 20 && abused.autoFix === 'preview',
    JSON.stringify({ autoScanIntervalMs: abused.autoScanIntervalMs, maxFindings: abused.maxFindings, autoFix: abused.autoFix }),
  );

  const { stateText } = await import(pathToFileURL(join(ROOT, 'lib', 'format.js')).href);
  const hugeSummary = {
    score: 10,
    grade: 'F',
    reliable: true,
    counts: { critical: 1, high: 500, medium: 500, low: 0, info: 0 },
    files: 1000,
    packages: 0,
    unverified: 0,
    notes: [],
    top: Array.from({ length: 1000 }, (_, index) => ({
      rule: 'VUL-001',
      severity: 'high',
      title: `finding ${index}`,
      path: `src/${index}.py`,
      line: index + 1,
      remediation: 'fix it',
      fingerprint: `fp${index}`,
      autoFixable: false,
    })),
    autoFixable: [],
  };
  const hugeText = stateText({ root: 'x', summary: hugeSummary, mode: '离线', scannedAt: 'now', ledger: { changes: 0, scans: 3, blocking: 1 } });
  check('huge finding set renders a bounded block', hugeText.length < 8_000 && hugeText.includes('结论：'));

  const python = await import(pathToFileURL(join(ROOT, 'lib', 'python.js')).href);
  const status = python.pythonStatus({ refresh: true });
  if (status.ready) {
    check('python health probe reports a usable interpreter', Boolean(status.version));
  } else {
    notes.push('skip python-health assertion: no Python 3.11+ in this environment');
  }
  const previous = process.env.PROVEMARK_PYTHON;
  process.env.PROVEMARK_PYTHON = 'none';
  python.resetPythonCache();
  const forced = python.pythonStatus({ refresh: true });
  process.env.PROVEMARK_PYTHON = previous ?? '';
  python.resetPythonCache();
  check('PROVEMARK_PYTHON=none forces the degradation path', forced.ready === false);
}

// ---------------------------------------------------------------- 3. CLI edge inputs
console.log('\n[3/5] CLI edge inputs');
{
  const empty = temp('repo-empty');
  const emptyScan = cli(['scan', empty, '--offline', '--no-color', '--fail-on', 'none', '-f', 'json']);
  check('empty directory scans without crashing', [0, 1].includes(emptyScan.code) && emptyScan.ms < 30_000, `exit ${emptyScan.code} in ${emptyScan.ms}ms`);

  const missing = cli(['scan', join(scratch, 'nope-not-here'), '--offline', '--no-color']);
  check('missing path exits 2 with a message', missing.code === 2 && /无法|不存在|not found/i.test(missing.stderr), `exit ${missing.code}`);

  const filePath = cli(['scan', join(smallRepo, 'README.md'), '--offline', '--no-color']);
  check('file path is rejected (exit 2)', filePath.code === 2, `exit ${filePath.code}`);

  const rootPath = process.platform === 'win32' ? 'C:\\' : '/';
  const rootScan = cli(['scan', rootPath, '--offline', '--no-color']);
  check('drive root is refused (exit 2)', rootScan.code === 2, `exit ${rootScan.code}`);

  const home = process.env.USERPROFILE || process.env.HOME || '';
  const homeScan = cli(['scan', home, '--offline', '--no-color']);
  check('home directory is refused (exit 2)', homeScan.code === 2, `exit ${homeScan.code}`);

  const weird = temp('repo 中文 空格 &符号');
  write(join(weird, 'pyproject.toml'), '[project]\nname = "weird"\nversion = "0.1"\n');
  write(join(weird, 'a.py'), 'print("hi")\n');
  const weirdScan = cli(['scan', weird, '--offline', '--no-color', '--fail-on', 'none', '-f', 'json']);
  check('unicode + spaces path scans', [0, 1].includes(weirdScan.code), `exit ${weirdScan.code}`);

  const bigFile = temp('repo-bigfile');
  write(join(bigFile, 'pyproject.toml'), '[project]\nname = "big"\nversion = "0.1"\n');
  write(join(bigFile, 'huge.txt'), 'x'.repeat(2 * 1024 * 1024));
  const bigScan = cli(['scan', bigFile, '--offline', '--no-color', '--fail-on', 'none', '-f', 'json']);
  check('2 MB file does not stall the scan', [0, 1].includes(bigScan.code) && bigScan.ms < 30_000, `exit ${bigScan.code} in ${bigScan.ms}ms`);

  const binary = temp('repo-binary');
  write(join(binary, 'pyproject.toml'), '[project]\nname = "bin"\nversion = "0.1"\n');
  writeFileSync(join(binary, 'image.png'), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 1, 2, 3]));
  const binaryScan = cli(['scan', binary, '--offline', '--no-color', '--fail-on', 'none', '-f', 'json']);
  check('binary files are skipped cleanly', [0, 1].includes(binaryScan.code), `exit ${binaryScan.code}`);

  const deep = temp('repo-deep');
  let cursor = deep;
  for (let depth = 0; depth < 60; depth += 1) {
    cursor = join(cursor, `d${depth}`);
  }
  write(join(cursor, 'pyproject.toml'), '[project]\nname = "deep"\nversion = "0.1"\n');
  write(join(cursor, 'x.py'), 'x = 1\n');
  const deepScan = cli(['scan', deep, '--offline', '--no-color', '--fail-on', 'none', '-f', 'json']);
  check('60-level nesting scans', [0, 1].includes(deepScan.code), `exit ${deepScan.code}`);

  if (process.platform === 'win32') {
    const loopRoot = temp('repo-loop');
    write(join(loopRoot, 'pyproject.toml'), '[project]\nname = "loop"\nversion = "0.1"\n');
    write(join(loopRoot, 'a.py'), 'x = 1\n');
    try {
      symlinkSync(loopRoot, join(loopRoot, 'cycle'), 'junction');
      const loopScan = cli(['scan', loopRoot, '--offline', '--no-color', '--fail-on', 'none', '-f', 'json'], { timeout: 45_000 });
      check('junction cycle terminates', [0, 1].includes(loopScan.code) && loopScan.ms < 45_000, `exit ${loopScan.code} in ${loopScan.ms}ms`);
    } catch (error) {
      notes.push(`skip junction cycle: ${String(error?.message ?? error)}`);
    }
  }

  const staged = cli(['scan', smallRepo, '--staged', '--offline', '--no-color', '--fail-on', 'none']);
  check('--staged outside git degrades without crashing', [0, 1, 2].includes(staged.code), `exit ${staged.code}`);

  const unknown = cli(['scan', smallRepo, '--offline', '--no-color', '--only', 'nope']);
  check('unknown scanner exits 2', unknown.code === 2, `exit ${unknown.code}`);

  const reportDir = temp('reports');
  const formats = [
    ['json', '.json'],
    ['sarif', '.sarif'],
    ['html', '.html'],
    ['markdown', '.md'],
  ];
  for (const [format, suffix] of formats) {
    const out = join(reportDir, `report${suffix}`);
    const result = cli(['scan', smallRepo, '--offline', '--no-color', '--fail-on', 'none', '-f', format, '-o', out], { timeout: 90_000 });
    let ok = result.code === 0 && existsSync(out);
    let detail = `exit ${result.code}`;
    if (ok && format === 'json') {
      try {
        const parsed = JSON.parse(readFileSync(out, 'utf8'));
        ok = typeof parsed.score?.total === 'number' && Array.isArray(parsed.findings);
      } catch (error) {
        ok = false;
        detail = String(error?.message ?? error);
      }
    } else if (ok && format === 'sarif') {
      const parsed = JSON.parse(readFileSync(out, 'utf8'));
      ok = parsed.version === '2.1.0' && Array.isArray(parsed.runs) && parsed.runs.length > 0;
    } else if (ok && format === 'html') {
      ok = readFileSync(out, 'utf8').length > 1024;
    } else if (ok && format === 'markdown') {
      ok = readFileSync(out, 'utf8').includes('Provemark');
    }
    check(`${format} report is valid`, ok, detail);
  }

  const gateRepo = temp('repo-gate');
  write(join(gateRepo, 'pyproject.toml'), '[project]\nname = "gate"\nversion = "0.1"\n');
  write(join(gateRepo, 'app.py'), 'def run(user_input):\n    return eval(user_input)\n');
  const gate = cli(['scan', gateRepo, '--offline', '--no-color', '--fail-on', 'high', '-f', 'json']);
  check('--fail-on high exits 1 on a high finding', gate.code === 1, `exit ${gate.code}`);
  const noGate = cli(['scan', gateRepo, '--offline', '--no-color', '--fail-on', 'none', '-f', 'json']);
  check('--fail-on none exits 0 on the same repo', noGate.code === 0, `exit ${noGate.code}`);
}

// ---------------------------------------------------------------- 4. install lifecycle
if (!QUICK) {
  console.log('\n[4/5] install lifecycle (temporary DSH home)');
  const dshHome = temp('dsh-home');
  const profile = join(dshHome, 'profiles', 'stress');
  mkdirSync(profile, { recursive: true });
  write(
    join(profile, 'package.json'),
    `${JSON.stringify({ name: 'stress-profile', version: '0.0.0', dependencies: {}, dsh: { profile: { bundles: [] } } }, null, 2)}\n`,
  );
  const installEnv = { ...process.env, DSH_HOME: dshHome };
  const install = (extra) =>
    runNode([join(ROOT, 'scripts', 'install.mjs'), '--profile', 'stress', '--dsh-home', dshHome, ...extra], {
      env: installEnv,
      timeout: 120_000,
    });

  const dry = install(['--dry-run']);
  check('dry-run install exits 0', dry.code === 0, `exit ${dry.code}`);
  const copied = install(['--copy']);
  check('copy install exits 0', copied.code === 0, `exit ${copied.code}: ${copied.stderr.slice(-200)}`);
  check('package linked into the profile', existsSync(join(profile, 'node_modules', 'provemark-dsh', 'package.json')));
  const manifestAfter = JSON.parse(readFileSync(join(profile, 'package.json'), 'utf8'));
  check('profile manifest records the dependency', Boolean(manifestAfter.dependencies?.['provemark-dsh']));
  check('profile manifest lists the bundle', (manifestAfter.dsh?.profile?.bundles ?? []).includes('provemark-dsh'));

  const again = install(['--copy']);
  check('reinstall is idempotent', again.code === 0, `exit ${again.code}`);

  const checkRun = install(['--check']);
  check('--check reports a healthy install', checkRun.code === 0 && /state\s*:\s*OK/.test(checkRun.stdout), `exit ${checkRun.code}`);
  check('--check reports the scanner interpreter line', /scanner\s*:/.test(checkRun.stdout));

  const uninstall = runNode(
    [join(ROOT, 'scripts', 'uninstall.mjs'), '--profile', 'stress', '--dsh-home', dshHome],
    { env: installEnv, timeout: 120_000 },
  );
  check('uninstall exits 0', uninstall.code === 0, `exit ${uninstall.code}`);
  const manifestFinal = JSON.parse(readFileSync(join(profile, 'package.json'), 'utf8'));
  check('uninstall removes the dependency row', !manifestFinal.dependencies?.['provemark-dsh']);
  check('uninstall removes the bundle row', !(manifestFinal.dsh?.profile?.bundles ?? []).includes('provemark-dsh'));
}

// ---------------------------------------------------------------- 5. summary
console.log('\n[5/5] summary');
console.log(`  checks: ${checks} · failures: ${failures.length}`);
for (const failure of failures) console.log(`  FAIL ${failure.label}${failure.detail ? ` — ${failure.detail}` : ''}`);
for (const note of notes) console.log(`  note: ${note}`);

rmSync(scratch, { recursive: true, force: true });
process.exit(failures.length === 0 ? 0 : 1);
