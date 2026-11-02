#!/usr/bin/env node
/**
 * Static checks for this plugin package — no host, no network, no scanning.
 *
 *   node scripts/validate.mjs
 *
 * Catches the failures that would otherwise surface as "the guardrail never
 * loaded" or "the host boots but the tools are missing": a dangling
 * `main`/`bin`, a patch the loader cannot read, a SKILL.md without usable
 * frontmatter, references the skill mentions but does not ship, and a vendored
 * scanner that is incomplete or out of step with its recorded version.
 */
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const problems = [];
const notes = [];

function check(condition, message) {
  if (!condition) problems.push(message);
}

function readJson(rel) {
  const file = join(ROOT, rel);
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch (error) {
    problems.push(`${rel}: ${error.message}`);
    return null;
  }
}

// ---------------------------------------------------------------- package.json
const pkg = readJson('package.json');
if (pkg !== null) {
  check(pkg.name === 'provemark-dsh', `package.json name should be "provemark-dsh", got ${JSON.stringify(pkg.name)}`);
  check(/^\d+\.\d+\.\d+/.test(pkg.version ?? ''), 'package.json needs a semver version');
  check(pkg.type === 'module', 'package.json type must be "module" (the loader imports this package)');
  check(typeof pkg.main === 'string' && existsSync(join(ROOT, pkg.main)), `package.json main not found: ${pkg.main}`);
  const binValues = Object.values(pkg.bin ?? {});
  check(binValues.length > 0, 'package.json needs a bin entry for the launcher');
  for (const bin of binValues) check(existsSync(join(ROOT, bin)), `package.json bin not found: ${bin}`);
  const patch = pkg.dsh?.bundle?.patch;
  check(typeof patch === 'string', 'package.json dsh.bundle.patch is missing');
  if (typeof patch === 'string') check(existsSync(join(ROOT, patch)), `bundle patch not found: ${patch}`);
  for (const required of ['lib', 'bin', 'cordis.patch.yml', 'skills', 'python', 'scripts']) {
    check((pkg.files ?? []).includes(required), `package.json files[] should ship "${required}"`);
  }
}

// -------------------------------------------------------------- cordis patch
const patchFile = join(ROOT, pkg?.dsh?.bundle?.patch ?? 'cordis.patch.yml');
if (existsSync(patchFile)) {
  const text = readFileSync(patchFile, 'utf8');
  check(/^- insert:/m.test(text), 'cordis.patch.yml must open with a top-level "- insert:" row');
  // Row 1: the always-on guardrail plugin.
  check(/id:\s*provemark-guard\b/.test(text), 'cordis.patch.yml needs the provemark-guard row');
  check(/name:\s*'provemark-dsh'/.test(text), 'the guardrail row must load this package');
  check(/autoScan:/.test(text), 'the guardrail row should ship its default config (autoScan)');
  // Row 2: the skill provider.
  check(/id:\s*provemark-skill-filesystem/.test(text), 'cordis.patch.yml needs the provemark-skill-filesystem row id');
  check(/@deepseek-ai\/dsh-skill-filesystem/.test(text), 'cordis.patch.yml must mount @deepseek-ai/dsh-skill-filesystem');
  check(/providerName:\s*provemark-plugin/.test(text), 'cordis.patch.yml needs providerName: provemark-plugin');
  check(/bundledSkillDir:/.test(text), 'cordis.patch.yml needs bundledSkillDir');
  check(/provemark-dsh\/package\.json/.test(text), 'bundledSkillDir must resolve via the provemark-dsh package identity');
  check(/!!js/.test(text), 'bundledSkillDir must be a !!js expression resolved from baseUrl, not a hard-coded path');
  check(!/[A-Za-z]:\\/.test(text), 'cordis.patch.yml must not hard-code a local Windows path');
  try {
    const yaml = createRequire(import.meta.url)('js-yaml');
    const stubbed = text.replace(/!!js[\s\S]*$/m, '"__expr__"');
    const doc = yaml.load(stubbed);
    const rows = doc?.[0]?.insert ?? [];
    check(Array.isArray(rows) && rows.length === 2, 'cordis.patch.yml should insert exactly two rows');
    check(rows[0]?.id === 'provemark-guard' && rows[0]?.name === 'provemark-dsh', 'first row must be the guardrail plugin');
    check(rows[1]?.name === '@deepseek-ai/dsh-skill-filesystem', 'second row must mount the skill filesystem');
    notes.push('yaml: parsed with js-yaml');
  } catch {
    notes.push('yaml: js-yaml unavailable, structural checks only');
  }
}

// ------------------------------------------------------------- host entrypoint
const entry = join(ROOT, pkg?.main ?? 'lib/index.js');
if (existsSync(entry)) {
  const text = readFileSync(entry, 'utf8');
  check(/export function apply\s*\(/.test(text), 'lib/index.js must export apply(ctx, config)');
  check(/export const name\s*=/.test(text), 'lib/index.js should export its plugin name');
  check(!/export default/.test(text), 'do not mix export forms: use apply() only, no default export');
  check(!/from ['"]@deepseek-ai\//.test(text), 'lib/index.js must not statically import host packages (load them dynamically)');
  notes.push('entry: apply() only, no static host imports');
}
for (const module of ['config.js', 'format.js', 'python.js', 'scan.js']) {
  check(existsSync(join(ROOT, 'lib', module)), `lib/${module} is missing`);
}

// ------------------------------------------------------------------ SKILL.md
const skillFile = join(ROOT, 'skills', 'provemark', 'SKILL.md');
if (!existsSync(skillFile)) {
  problems.push('skills/provemark/SKILL.md is missing');
} else {
  const text = readFileSync(skillFile, 'utf8');
  const front = /^---\r?\n([\s\S]*?)\r?\n---\r?\n/.exec(text);
  check(front !== null, 'SKILL.md needs YAML frontmatter');
  if (front) {
    const block = front[1];
    check(/^name:\s*provemark\s*$/m.test(block), 'SKILL.md frontmatter name must be "provemark"');
    const description = /^description:\s*(.+)$/m.exec(block)?.[1] ?? '';
    check(description.replace(/^["']|["']$/g, '').length >= 120, 'SKILL.md description is too short to route on');
    check(/扫描/.test(description), 'SKILL.md description should carry the Chinese trigger wording');
    check(/audit|vulnerabilit|license/i.test(description), 'SKILL.md description should carry English trigger keywords too');
  }
  for (const match of text.matchAll(/references\/([\w.-]+\.md)/g)) {
    check(existsSync(join(ROOT, 'skills', 'provemark', 'references', match[1])), `SKILL.md references ${match[1]} but it does not exist`);
  }
  check(/provemark_guard/.test(text), 'SKILL.md should tell the model about the provemark_guard tool');
  notes.push('skill: guardrail tools documented');
}

// ------------------------------------------------------------- vendored python
const vendored = join(ROOT, 'python', 'provemark');
for (const required of ['__init__.py', 'cli.py', 'engine.py', 'score.py', 'report', 'rules', 'scanners']) {
  check(existsSync(join(vendored, required)), `python/provemark/${required} is missing`);
}
if (existsSync(join(vendored, '__init__.py'))) {
  const version = /__version__\s*=\s*["']([^"']+)/.exec(readFileSync(join(vendored, '__init__.py'), 'utf8'))?.[1];
  const recorded = existsSync(join(vendored, 'VENDORED.json'))
    ? JSON.parse(readFileSync(join(vendored, 'VENDORED.json'), 'utf8')).version
    : null;
  check(version !== undefined, 'vendored scanner has no __version__');
  check(recorded === version, `vendored scanner version ${version} does not match VENDORED.json (${recorded}) — run scripts/sync-vendor.mjs`);
  notes.push(`python: provemark ${version}`);
}

// -------------------------------------------------------------------- scripts
for (const script of ['install.mjs', 'uninstall.mjs', 'sync-vendor.mjs', 'validate.mjs', 'selftest.mjs']) {
  check(existsSync(join(ROOT, 'scripts', script)), `scripts/${script} is missing`);
}

// --------------------------------------------------------------------- report
for (const note of notes) console.log(`[validate] ok   ${note}`);
if (problems.length === 0) {
  console.log('[validate] pass');
  process.exit(0);
}
for (const problem of problems) console.error(`[validate] fail ${problem}`);
process.exit(1);
