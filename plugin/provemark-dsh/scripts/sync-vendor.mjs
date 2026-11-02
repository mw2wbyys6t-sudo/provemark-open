#!/usr/bin/env node
/**
 * Refresh `python/provemark` from the authoritative scanner checkout.
 *
 * The plugin vendors the scanner so a DSH user does not need `pip install`.
 * That copy must never drift silently: after changing anything under the repo's
 * `provemark/`, run this script and commit both sides together.
 *
 *   node scripts/sync-vendor.mjs                 # from the repo that contains this plugin
 *   node scripts/sync-vendor.mjs --from D:\src   # explicit scanner root
 *   node scripts/sync-vendor.mjs --check         # exit 1 when the copy is stale
 */
import { cpSync, existsSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = resolve(HERE, '..');
const VENDORED = join(PACKAGE_ROOT, 'python', 'provemark');

const argv = process.argv.slice(2);
const checkOnly = argv.includes('--check');
const fromIndex = argv.indexOf('--from');
const fromFlag = fromIndex === -1 ? null : argv[fromIndex + 1];
const sourceRoot = resolve(fromFlag ?? resolve(PACKAGE_ROOT, '..', '..'));
const source = join(sourceRoot, 'provemark');

if (!existsSync(join(source, '__init__.py'))) {
  console.error(`[sync-vendor] no scanner at ${source}${fromFlag ? '' : ' — pass --from <repo root>'}`);
  process.exit(2);
}

const SKIP = new Set(['__pycache__', '.mypy_cache', '.pytest_cache']);

function walk(root, prefix = '') {
  const files = [];
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    if (SKIP.has(entry.name)) continue;
    const rel = join(prefix, entry.name);
    const full = join(root, entry.name);
    if (entry.isDirectory()) files.push(...walk(full, rel));
    else if (entry.name.endsWith('.pyc')) continue;
    else files.push(rel);
  }
  return files.sort();
}

const sourceFiles = walk(source);

if (checkOnly) {
  const stale = [];
  for (const rel of sourceFiles) {
    const vendored = join(VENDORED, rel);
    if (!existsSync(vendored)) {
      stale.push(`missing: ${rel}`);
      continue;
    }
    const a = statSync(join(source, rel));
    const b = statSync(vendored);
    if (a.size !== b.size || readFileSync(join(source, rel)).compare(readFileSync(vendored)) !== 0) {
      stale.push(`differs: ${rel}`);
    }
  }
  if (stale.length === 0) {
    console.log(`[sync-vendor] up to date (${sourceFiles.length} files)`);
    process.exit(0);
  }
  console.error(`[sync-vendor] vendored copy is stale (${stale.length} file(s)):`);
  for (const line of stale.slice(0, 20)) console.error(`  ${line}`);
  if (stale.length > 20) console.error(`  … ${stale.length - 20} more`);
  console.error('[sync-vendor] run: node scripts/sync-vendor.mjs');
  process.exit(1);
}

rmSync(VENDORED, { recursive: true, force: true });
cpSync(source, VENDORED, {
  recursive: true,
  filter: (path) => {
    const base = path.split(/[\\/]/).pop();
    return !SKIP.has(base) && !base.endsWith('.pyc');
  },
});

// Record which scanner version this copy holds, for humans reading the package.
// The path is stored relative to the package so a published tarball does not
// leak the maintainer's checkout location.
const initPy = readFileSync(join(VENDORED, '__init__.py'), 'utf8');
const version = /__version__\s*=\s*["']([^"']+)/.exec(initPy)?.[1] ?? 'unknown';
writeFileSync(
  join(VENDORED, 'VENDORED.json'),
  `${JSON.stringify(
    {
      source: relative(PACKAGE_ROOT, source).split(/[\\/]/).join('/'),
      version,
      syncedAt: new Date().toISOString(),
      files: sourceFiles.length,
    },
    null,
    2,
  )}\n`,
);

console.log(`[sync-vendor] copied ${sourceFiles.length} files from ${source}`);
console.log(`[sync-vendor] scanner version: ${version}`);
