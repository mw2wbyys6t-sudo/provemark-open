#!/usr/bin/env node
/**
 * Install provemark-dsh into a DeepSeek Harness profile.
 *
 * What the host needs in order to mount the skill:
 *   1. the package resolvable as `provemark-dsh` from the profile directory
 *      (node's resolution from `<profile>/package.json` is what the bundle's
 *      `!!js` expression calls), and
 *   2. `provemark-dsh` listed in `dsh.profile.bundles`, so the loader applies
 *      the package's `cordis.patch.yml`.
 *
 * Default strategy: link `<profile>/node_modules/provemark-dsh` at this package
 * (junction on Windows, directory symlink elsewhere), then patch the profile
 * manifest. `--pnpm` delegates both steps to the profile's own package manager
 * (also updates its lockfile) when a pnpm is available. `--copy` copies instead
 * of linking, for read-only or cross-volume targets.
 *
 *   node scripts/install.mjs                       # default profile (desktop / auto)
 *   node scripts/install.mjs --profile web
 *   node scripts/install.mjs --pnpm
 *   node scripts/install.mjs --check
 */
import { existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, symlinkSync, copyFileSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { pythonStatus } from '../lib/python.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = resolve(HERE, '..');
const NAME = JSON.parse(readFileSync(join(PACKAGE_ROOT, 'package.json'), 'utf8')).name;

const argv = process.argv.slice(2);
const flag = (name) => argv.includes(name);
const value = (name) => {
  const index = argv.indexOf(name);
  return index === -1 ? null : argv[index + 1];
};

const dshHome = resolve(value('--dsh-home') ?? process.env.DSH_HOME ?? join(homedir(), '.dsh'));
const profilesRoot = join(dshHome, 'profiles');

function fail(message, hint) {
  console.error(`[install] ${message}`);
  if (hint) console.error(`[install] ${hint}`);
  process.exit(2);
}

function listProfiles() {
  try {
    return readdirSync(profilesRoot, { withFileTypes: true })
      .filter((entry) => entry.isDirectory() && existsSync(join(profilesRoot, entry.name, 'package.json')))
      .map((entry) => entry.name);
  } catch {
    return [];
  }
}

function pickProfile() {
  const explicit = value('--profile');
  if (explicit) {
    const dir = join(profilesRoot, explicit);
    if (!existsSync(join(dir, 'package.json'))) fail(`profile "${explicit}" not found at ${dir}`);
    return { name: explicit, dir };
  }
  const profiles = listProfiles();
  if (profiles.length === 0) fail(`no DSH profile under ${profilesRoot}`, 'pass --profile <name> or --dsh-home <dir>');
  const preferred = profiles.includes('desktop') ? 'desktop' : profiles.length === 1 ? profiles[0] : null;
  if (preferred === null) {
    fail(`several profiles exist (${profiles.join(', ')}), and none is named "desktop"`, 'pass --profile <name>');
  }
  return { name: preferred, dir: join(profilesRoot, preferred) };
}

function readProfileManifest(dir) {
  const file = join(dir, 'package.json');
  try {
    // Windows tooling (PowerShell 5.1 `Set-Content -Encoding utf8`) writes a
    // BOM, which JSON.parse rejects; a manifest a human edited must not make the
    // installer fail with "not valid JSON".
    const text = readFileSync(file, 'utf8').replace(/^\uFEFF/, '');
    return { file, manifest: JSON.parse(text) };
  } catch (error) {
    fail(`cannot read ${file}: ${error.message}`);
  }
}

function isOurLink(target) {
  try {
    return realpathSync(target) === realpathSync(PACKAGE_ROOT);
  } catch {
    return false;
  }
}

function linkPackage(profileDir, { copy, force }) {
  const target = join(profileDir, 'node_modules', NAME);
  mkdirSync(join(profileDir, 'node_modules'), { recursive: true });
  if (existsSync(target) || isSymlink(target)) {
    if (isSymlink(target) && isOurLink(target)) return { target, action: 'reused' };
    if (isOurCopy(target)) {
      // Re-running the installer is a normal thing to do (upgrade, retry); a
      // previous copy is ours, so refresh it instead of demanding --force.
      rmSync(target, { recursive: true, force: true });
      if (!copy) {
        const type = process.platform === 'win32' ? 'junction' : 'dir';
        symlinkSync(PACKAGE_ROOT, target, type);
        return { target, action: `relinked (${type})` };
      }
      cpRecursive(PACKAGE_ROOT, target);
      return { target, action: 'refreshed (copy)' };
    }
    if (!force) fail(`${target} already exists and is not this package`, 'pass --force to replace it');
    rmSync(target, { recursive: true, force: true });
  }
  if (copy) {
    rmSync(target, { recursive: true, force: true });
    cpRecursive(PACKAGE_ROOT, target);
    return { target, action: 'copied' };
  }
  const type = process.platform === 'win32' ? 'junction' : 'dir';
  symlinkSync(PACKAGE_ROOT, target, type);
  return { target, action: `linked (${type})` };
}

function isOurCopy(target) {
  try {
    const manifest = JSON.parse(readFileSync(join(target, 'package.json'), 'utf8'));
    return manifest.name === NAME;
  } catch {
    return false;
  }
}

function isSymlink(path) {
  try {
    return lstatSync(path).isSymbolicLink();
  } catch {
    return false;
  }
}

function cpRecursive(from, to) {
  const skip = new Set(['node_modules', '.git', '__pycache__']);
  mkdirSync(to, { recursive: true });
  for (const entry of readdirSync(from, { withFileTypes: true })) {
    if (skip.has(entry.name)) continue;
    const src = join(from, entry.name);
    const dst = join(to, entry.name);
    if (entry.isDirectory()) cpRecursive(src, dst);
    else copyFileSync(src, dst);
  }
}

function patchManifest(dir, { dryRun }) {
  const { file, manifest } = readProfileManifest(dir);
  const before = JSON.stringify(manifest, null, 2);
  manifest.dependencies ??= {};
  // pnpm reads this spec itself; forward slashes survive JSON, PowerShell and
  // pnpm's own path parsing on every platform, backslashes do not always.
  const spec = `link:${PACKAGE_ROOT.replaceAll('\\', '/')}`;
  const dependencyChanged = manifest.dependencies[NAME] !== spec;
  manifest.dependencies[NAME] = spec;

  manifest.dsh ??= {};
  manifest.dsh.profile ??= {};
  const bundles = Array.isArray(manifest.dsh.profile.bundles) ? manifest.dsh.profile.bundles : [];
  const bundleChanged = !bundles.includes(NAME);
  if (bundleChanged) bundles.push(NAME);
  manifest.dsh.profile.bundles = bundles;

  const after = JSON.stringify(manifest, null, 2);
  if (before === after) return { changed: false, file };
  if (dryRun) return { changed: true, file, dryRun: true };
  const backup = `${file}.provemark-backup`;
  if (!existsSync(backup)) writeFileSync(backup, `${before}\n`);
  writeFileSync(file, `${after}\n`);
  return { changed: true, file, dependencyChanged, bundleChanged };
}

function findPnpm() {
  const candidates = [];
  const runtimes = join(dshHome, 'dsh-runtimes');
  try {
    for (const entry of readdirSync(runtimes, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      candidates.push(join(runtimes, entry.name, 'dependencies', 'pnpm', 'bin', 'pnpm.cjs'));
    }
  } catch {
    /* no bundled pnpm next to this DSH home */
  }
  return candidates.find((candidate) => existsSync(candidate)) ?? null;
}

function verify(profileDir) {
  const problems = [];
  const manifestPath = join(profileDir, 'package.json');
  let resolved;
  try {
    resolved = createRequire(manifestPath).resolve(`${NAME}/package.json`);
  } catch (error) {
    problems.push(`node cannot resolve "${NAME}" from ${profileDir}: ${error.message}`);
  }
  const skillFile = join(PACKAGE_ROOT, 'skills', 'provemark', 'SKILL.md');
  if (!existsSync(skillFile)) problems.push(`missing ${skillFile} (skill bundle incomplete)`);
  const initPy = join(PACKAGE_ROOT, 'python', 'provemark', '__init__.py');
  if (!existsSync(initPy)) problems.push(`missing ${initPy} (run scripts/sync-vendor.mjs)`);
  const patchFile = join(PACKAGE_ROOT, 'cordis.patch.yml');
  if (!existsSync(patchFile)) {
    problems.push(`missing ${patchFile}`);
  } else {
    const patch = readFileSync(patchFile, 'utf8');
    if (!/id:\s*provemark-guard\b/.test(patch)) problems.push('cordis.patch.yml has no provemark-guard row (no always-on guardrail)');
    if (!/provemark-skill-filesystem/.test(patch)) problems.push('cordis.patch.yml has no skill provider row');
  }
  for (const module of ['index.js', 'python.js', 'scan.js', 'format.js', 'config.js']) {
    if (!existsSync(join(PACKAGE_ROOT, 'lib', module))) problems.push(`missing lib/${module}`);
  }

  const { manifest } = readProfileManifest(profileDir);
  const bundles = manifest.dsh?.profile?.bundles ?? [];
  if (!Array.isArray(bundles) || !bundles.includes(NAME)) problems.push(`"${NAME}" is not in dsh.profile.bundles`);

  // Activation marker written by the plugin on every load. Its absence means
  // the running process never mounted the guardrail (usually: booted before
  // this package was installed, or the row is disabled).
  const marker = join(tmpdir(), 'provemark-dsh-loaded.json');
  let loaded = null;
  if (existsSync(marker)) {
    try {
      loaded = JSON.parse(readFileSync(marker, 'utf8'));
    } catch {
      loaded = null;
    }
  }

  return { resolved, problems, loaded };
}

const profile = pickProfile();
const dryRun = flag('--dry-run');

if (flag('--check')) {
  const { resolved, problems, loaded } = verify(profile.dir);
  console.log(`[install] dsh home : ${dshHome}`);
  console.log(`[install] profile  : ${profile.name} (${profile.dir})`);
  console.log(`[install] package  : ${PACKAGE_ROOT}`);
  console.log(`[install] resolves : ${resolved ?? '(no)'}`);
  const python = pythonStatus({ refresh: true });
  console.log(
    `[install] scanner  : ${
      python.ready
        ? `Python ${python.version} (${python.cmd})`
        : 'no Python 3.11+ found — install Python or set PROVEMARK_PYTHON=<path>; the guardrail cannot scan without it'
    }`,
  );
  console.log(
    `[install] last load: ${
      loaded
        ? `${loaded.at} (pid ${loaded.pid}, v${loaded.version}, autoScan=${loaded.config?.autoScan ?? loaded.autoScan}, autoFix=${loaded.config?.autoFix ?? loaded.autoFix}; marker is machine-wide)`
        : 'never in a running host — restart DeepSeek Harness to mount the guardrail'
    }`,
  );
  if (problems.length === 0) {
    console.log('[install] state    : OK');
    process.exit(0);
  }
  for (const problem of problems) console.error(`[install] problem  : ${problem}`);
  process.exit(1);
}

console.log(`[install] profile ${profile.name} (${profile.dir})`);
console.log(`[install] package ${PACKAGE_ROOT}`);

const usePnpm = flag('--pnpm');

if (dryRun) {
  // Dry run must not touch the profile at all: report the plan, then check the
  // package's own prerequisites (skill file, vendored scanner, patch row).
  const { manifest } = readProfileManifest(profile.dir);
  const spec = `link:${PACKAGE_ROOT.replaceAll('\\', '/')}`;
  const bundles = Array.isArray(manifest.dsh?.profile?.bundles) ? manifest.dsh.profile.bundles : [];
  console.log(`[install] would set dependencies["${NAME}"] = "${spec}"`);
  console.log(`[install] would ${bundles.includes(NAME) ? 'keep' : 'append'} "${NAME}" in dsh.profile.bundles`);
  console.log(`[install] would ${usePnpm ? 'run pnpm add' : `link node_modules/${NAME}`}`);
  const prerequisites = [
    [join(PACKAGE_ROOT, 'skills', 'provemark', 'SKILL.md'), 'skill file'],
    [join(PACKAGE_ROOT, 'python', 'provemark', '__init__.py'), 'vendored scanner'],
    [join(PACKAGE_ROOT, 'cordis.patch.yml'), 'bundle patch'],
    [join(PACKAGE_ROOT, 'bin', 'provemark.mjs'), 'launcher'],
  ].filter(([file]) => !existsSync(file));
  for (const [file, label] of prerequisites) console.error(`[install] problem: missing ${label}: ${file}`);
  if (prerequisites.length > 0) process.exit(1);
  console.log('[install] dry run complete, nothing written');
  process.exit(0);
}

let action = 'manifest-only';
if (usePnpm) {
  const pnpm = findPnpm();
  if (pnpm === null) fail('--pnpm requested but no bundled pnpm found', 'drop --pnpm to link directly');
  console.log(`[install] pnpm add ${NAME}@link:${PACKAGE_ROOT}`);
  const result = spawnSync(process.execPath, [pnpm, 'add', `${NAME}@link:${PACKAGE_ROOT}`], {
    cwd: profile.dir,
    stdio: 'inherit',
    windowsHide: false,
  });
  if (result.error) fail(`pnpm failed to start: ${result.error.message}`);
  if (result.status !== 0) fail(`pnpm add exited ${result.status}`);
  action = 'pnpm-add';
} else {
  const linked = linkPackage(profile.dir, { copy: flag('--copy'), force: flag('--force') });
  action = linked.action;
  if (!dryRun) console.log(`[install] node_modules/${NAME}: ${linked.action}`);
}

const patch = patchManifest(profile.dir, { dryRun });
console.log(`[install] ${relative(profile.dir, patch.file)}: ${patch.changed ? (dryRun ? 'would change' : 'updated') : 'unchanged'}`);
if (patch.changed && !patch.dryRun && existsSync(`${patch.file}.provemark-backup`)) {
  console.log(`[install] backup: ${relative(profile.dir, `${patch.file}.provemark-backup`)}`);
}

const { resolved, problems } = verify(profile.dir);
console.log(`[install] resolves ${resolved ?? '(no)'}`);
if (problems.length > 0) {
  for (const problem of problems) console.error(`[install] problem: ${problem}`);
  process.exit(1);
}

console.log('');
console.log('[install] done. Restart DeepSeek Harness (plugins load at boot), then the skill "provemark" is available.');
console.log('[install] verify later with: node scripts/install.mjs --check');
if (action !== 'pnpm-add') {
  console.log('[install] note: the profile lockfile was not touched. If the host later runs a pnpm');
  console.log('[install]       install, it will record the link: spec itself.');
}
