/**
 * Deterministic release step for the plugin package.
 *
 *   node scripts/release.mjs --version 0.5.0 --dry-run   # show what would change
 *   node scripts/release.mjs --version 0.5.0             # bump + pack a tarball
 *
 * Gates (all must pass before anything is written): validate, vendored-copy
 * sync, host-contract selftest. Then it bumps the four places a version lives,
 * turns the CHANGELOG's "未发布" section into the release section, packs the
 * tarball into `dist/` and prints its SHA-256. Publishing is intentionally a
 * manual step: the script never runs `npm publish`.
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Windows needs a shell to run `npm.cmd`; that path is fixed (no user input) but
// Node still prints a deprecation warning. Keep release output clean.
process.noDeprecation = true;

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const args = process.argv.slice(2);
const flag = (name) => args.includes(name);
const valueOf = (name) => {
  const index = args.indexOf(name);
  return index === -1 ? null : args[index + 1] ?? null;
};

const dryRun = flag('--dry-run');
const next = valueOf('--version');
if (!next || !/^\d+\.\d+\.\d+$/.test(next)) {
  console.error('[release] usage: node scripts/release.mjs --version <major.minor.patch> [--dry-run] [--skip-checks]');
  process.exit(2);
}

const pkgFile = join(ROOT, 'package.json');
const pkg = JSON.parse(readFileSync(pkgFile, 'utf8'));
const alreadyCurrent = next === pkg.version;
if (alreadyCurrent && !flag('--repack')) {
  console.error(`[release] version ${next} is already current; pass --repack to only rebuild the tarball`);
  process.exit(2);
}
const skipEdits = alreadyCurrent && flag('--repack');
if (!skipEdits && !flag('--force') && !isGreater(next, pkg.version)) {
  console.error(`[release] refusing to go backwards (${pkg.version} → ${next}); pass --force to override`);
  process.exit(2);
}

function isGreater(a, b) {
  const parse = (v) => v.split('.').map((part) => Number(part));
  const [a1, a2, a3] = parse(a);
  const [b1, b2, b3] = parse(b);
  return a1 - b1 || a2 - b2 || a3 - b3;
}

function run(label, command, commandArgs, { shell = false, env = process.env } = {}) {
  const result = spawnSync(command, commandArgs, {
    cwd: ROOT,
    encoding: 'utf8',
    timeout: 180_000,
    windowsHide: true,
    shell,
    env,
  });
  return {
    label,
    ok: !result.error && result.status === 0,
    stdout: String(result.stdout ?? ''),
    stderr: String(result.stderr ?? ''),
  };
}

if (!flag('--skip-checks')) {
  const checks = [
    ['validate', process.execPath, [join(ROOT, 'scripts', 'validate.mjs')]],
    ['vendor sync', process.execPath, [join(ROOT, 'scripts', 'sync-vendor.mjs'), '--check']],
    ['selftest', process.execPath, [join(ROOT, 'scripts', 'selftest.mjs')]],
  ];
  for (const [label, command, commandArgs] of checks) {
    const result = run(label, command, commandArgs);
    if (!result.ok) {
      console.error(`[release] gate failed: ${label}`);
      console.error((result.stderr || result.stdout).trim().split('\n').slice(-8).join('\n'));
      process.exit(1);
    }
    console.log(`[release] gate ok: ${label}`);
  }
}

// Four places a version lives; keep them in one place so they cannot drift.
if (!skipEdits) {
  const edits = [
    {
      file: pkgFile,
      before: `"version": "${pkg.version}"`,
      after: `"version": "${next}"`,
      note: 'package.json',
    },
    {
      file: join(ROOT, 'lib', 'index.js'),
      before: `export const VERSION = '${pkg.version}'`,
      after: `export const VERSION = '${next}'`,
      note: 'lib/index.js VERSION',
    },
    {
      file: join(ROOT, 'skills', 'provemark', 'SKILL.md'),
      before: `version: "${pkg.version}"`,
      after: `version: "${next}"`,
      note: 'skill metadata version',
    },
  ];

  const pending = [];
  for (const edit of edits) {
    const text = readFileSync(edit.file, 'utf8');
    if (!text.includes(edit.before)) {
      console.error(`[release] anchor not found in ${edit.note}: ${edit.before}`);
      process.exit(1);
    }
    pending.push({ ...edit, text, updated: text.replace(edit.before, edit.after) });
  }

  const changelogCandidates = [
    join(ROOT, 'CHANGELOG.md'),
    resolve(ROOT, '..', '..', 'CHANGELOG.md'),
  ];
  const changelogFile = changelogCandidates.find((file) => existsSync(file)) ?? null;
  if (!changelogFile) {
    console.error('[release] no CHANGELOG.md found (looked in the package and the repo root)');
    process.exit(1);
  }
  const changelog = readFileSync(changelogFile, 'utf8');
  if (!/^## \[未发布\]/m.test(changelog)) {
    console.error('[release] CHANGELOG.md has no "## [未发布]" section to release');
    process.exit(1);
  }
  const today = new Date().toISOString().slice(0, 10);
  const releasedChangelog = changelog.replace(
    /^## \[未发布\][^\n]*\n/m,
    `## [未发布]\n\n## [${next}] - ${today}\n`,
  );

  console.log(`[release] ${pkg.version} → ${next}${dryRun ? ' (dry run)' : ''}`);
  console.log(`  package.json          version → ${next}`);
  console.log(`  lib/index.js          VERSION → ${next}`);
  console.log(`  SKILL.md              metadata.version → ${next}`);
  console.log(`  CHANGELOG.md          [未发布] → [${next}] - ${today}（并保留新的 [未发布] 段）`);

  if (dryRun) {
    console.log('[release] dry run only: no files written, no tarball');
    process.exit(0);
  }

  for (const edit of pending) writeFileSync(edit.file, edit.updated, 'utf8');
  writeFileSync(changelogFile, releasedChangelog, 'utf8');
} else {
  console.log(`[release] already at ${next}; skipping version/changelog edits (--repack)`);
  if (dryRun) {
    console.log('[release] dry run only: no files written, no tarball');
    process.exit(0);
  }
}

const dist = join(ROOT, 'dist');
mkdirSync(dist, { recursive: true });
writeFileSync(join(dist, '.gitignore'), '*\n', 'utf8');
// Windows cannot spawn `npm.cmd` without a shell; NODE_NO_WARNINGS keeps the
// resulting Node deprecation notice out of the release output.
const pack =
  process.platform === 'win32'
    ? run('npm pack', 'npm.cmd', ['pack', '--pack-destination', dist, '--silent'], {
        shell: true,
        env: { ...process.env, NODE_NO_WARNINGS: '1' },
      })
    : run('npm pack', 'npm', ['pack', '--pack-destination', dist, '--silent']);
if (!pack.ok) {
  console.error('[release] npm pack failed');
  console.error((pack.stderr || pack.stdout).trim());
  process.exit(1);
}
const tarballName = pack.stdout.trim().split('\n').filter(Boolean).pop();
const tarball = join(dist, tarballName);
const sha = existsSync(tarball)
  ? createHash('sha256').update(readFileSync(tarball)).digest('hex')
  : '';
console.log(`[release] tarball: ${tarball}`);
console.log(`[release] sha256 : ${sha}`);
console.log('[release] next: review the diff, commit, tag the release, then publish manually (the script never publishes)');
