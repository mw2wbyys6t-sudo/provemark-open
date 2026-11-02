#!/usr/bin/env node
/**
 * Remove provemark-dsh from a DeepSeek Harness profile.
 *
 *   node scripts/uninstall.mjs                  # default profile
 *   node scripts/uninstall.mjs --profile web
 *   node scripts/uninstall.mjs --dry-run
 *
 * Reverses what install.mjs wrote: the `dsh.profile.bundles` row, the
 * `dependencies` entry, and `node_modules/provemark-dsh` (only when it points at
 * this package). The managed source tree is never deleted.
 */
import { existsSync, lstatSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = resolve(HERE, '..');
const NAME = JSON.parse(readFileSync(join(PACKAGE_ROOT, 'package.json'), 'utf8')).name;

const argv = process.argv.slice(2);
const value = (name) => {
  const index = argv.indexOf(name);
  return index === -1 ? null : argv[index + 1];
};
const dryRun = argv.includes('--dry-run');

const dshHome = resolve(value('--dsh-home') ?? process.env.DSH_HOME ?? join(homedir(), '.dsh'));
const profilesRoot = join(dshHome, 'profiles');

function fail(message, hint) {
  console.error(`[uninstall] ${message}`);
  if (hint) console.error(`[uninstall] ${hint}`);
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

const explicit = value('--profile');
const profiles = listProfiles();
const profile = explicit ?? (profiles.includes('desktop') ? 'desktop' : profiles.length === 1 ? profiles[0] : null);
if (profile === null) fail(`cannot pick a profile from: ${profiles.join(', ') || '(none)'}`, 'pass --profile <name>');
const profileDir = join(profilesRoot, profile);
if (!existsSync(join(profileDir, 'package.json'))) fail(`profile "${profile}" not found at ${profileDir}`);

const manifestFile = join(profileDir, 'package.json');
// Strip a BOM: PowerShell 5.1 `Set-Content -Encoding utf8` adds one and
// JSON.parse (correctly) refuses it.
const manifest = JSON.parse(readFileSync(manifestFile, 'utf8').replace(/^\uFEFF/, ''));
const before = JSON.stringify(manifest, null, 2);

let touched = false;
if (manifest.dependencies && Object.hasOwn(manifest.dependencies, NAME)) {
  delete manifest.dependencies[NAME];
  touched = true;
  console.log(`[uninstall] dependencies.${NAME}: removed`);
}
const bundles = manifest.dsh?.profile?.bundles;
if (Array.isArray(bundles) && bundles.includes(NAME)) {
  manifest.dsh.profile.bundles = bundles.filter((entry) => entry !== NAME);
  touched = true;
  console.log('[uninstall] dsh.profile.bundles: removed');
}

if (touched && !dryRun) writeFileSync(manifestFile, `${JSON.stringify(manifest, null, 2)}\n`);
else if (!touched) console.log('[uninstall] manifest: nothing to remove');

const link = join(profileDir, 'node_modules', NAME);
let removeLink = false;
try {
  const real = realpathSync(link);
  removeLink = real === realpathSync(PACKAGE_ROOT);
} catch {
  removeLink = false;
}
if (removeLink) {
  if (dryRun) console.log(`[uninstall] would remove ${link}`);
  else {
    rmSync(link, { recursive: true, force: true });
    console.log(`[uninstall] removed ${link}`);
  }
} else if (lstatExists(link)) {
  console.error(`[uninstall] left ${link} in place: it is not a link to ${PACKAGE_ROOT}`);
}

console.log('[uninstall] done. Restart DeepSeek Harness; the "provemark" skill disappears.');
console.log('[uninstall] the plugin source tree is untouched.');

function lstatExists(path) {
  try {
    lstatSync(path);
    return true;
  } catch {
    return false;
  }
}
