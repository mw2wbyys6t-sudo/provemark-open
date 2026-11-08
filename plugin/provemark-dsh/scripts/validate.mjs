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
import { existsSync, readFileSync, statSync } from 'node:fs';
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
  // Ecosystem manifest: the DSH plugin manager gates on `dsh.engines.dsh` before
  // installing/activating, so that declaration is what keeps an incompatible host
  // from landing a half-working install.
  check(
    /^[\^~>=<]*\s*\d+\.\d+\.\d+/.test(String(pkg.dsh?.engines?.dsh ?? '')),
    'package.json dsh.engines.dsh is missing (the plugin manager cannot gate host compatibility without it)',
  );
  const releases = pkg.dsh?.compatibility?.dshReleases ?? {};
  check(Object.keys(releases).length > 0, 'package.json dsh.compatibility.dshReleases is missing (state which host versions were verified)');
  for (const [version, status] of Object.entries(releases)) {
    check(['compatible', 'incompatible', 'unknown'].includes(status), `dsh.compatibility.dshReleases["${version}"] must be compatible|incompatible|unknown`);
  }
  // The package installs nothing: the scanner is vendored under python/ and the
  // host supplies @deepseek-ai/dsh-tools at runtime through a dynamic import.
  // A dependency creeping into these sections would silently break the
  // "no pip install / no npm install" promise users rely on.
  for (const section of ['dependencies', 'optionalDependencies']) {
    check(
      Object.keys(pkg[section] ?? {}).length === 0,
      `package.json ${section} must stay empty — the scanner is vendored and the host tools API is resolved at runtime`,
    );
  }
  check(pkg.license === 'Apache-2.0', 'package.json license should stay Apache-2.0 (matches LICENSE)');
  notes.push('manifest: dsh.engines.dsh + dshReleases + zero installed deps');
}

// ------------------------------------------------------- display metadata
// Plugin Manager and Settings read the icon and the locale files WITHOUT
// activating the plugin, so a broken image or a missing meta.title shows up as
// blank artwork and untranslated rows in the UI — never as a runtime error.
const iconRel = typeof pkg?.icon === 'string' ? pkg.icon : typeof pkg?.exports?.['./icon'] === 'string' ? pkg.exports['./icon'] : null;
if (iconRel === null) {
  problems.push('package.json needs an icon: declare top-level "icon" (or export "./icon")');
} else {
  const clean = iconRel.replace(/^\.\//, '');
  const iconFile = join(ROOT, clean);
  check(!/^([A-Za-z]:|[\\/])/.test(clean), `icon path must be relative and inside the package: ${iconRel}`);
  check(/\.(svg|png|jpe?g|webp)$/i.test(clean), `icon must be svg/png/jpeg/webp, got ${iconRel}`);
  if (!existsSync(iconFile)) {
    problems.push(`icon not found: ${iconRel}`);
  } else {
    const bytes = statSync(iconFile).size;
    check(bytes > 0 && bytes <= 256 * 1024, `icon must be 1 byte..256 KiB, got ${bytes}`);
    if (clean.endsWith('.svg')) {
      const svg = readFileSync(iconFile, 'utf8');
      check(/^<svg[\s>]/.test(svg.trim()), 'icon.svg must start with a root <svg> element');
      check(/xmlns="http:\/\/www\.w3\.org\/2000\/svg"/.test(svg), 'icon.svg needs the SVG xmlns namespace');
      check(/viewBox="0 0 \d+ \d+"/.test(svg), 'icon.svg needs a square viewBox so it scales in every slot');
      check(!/<script|foreignObject|javascript:/i.test(svg), 'icon.svg must not carry scripts, foreignObject or javascript: URLs');
      check(!/(?:href|src)\s*=\s*["'](?:https?:)?\/\//i.test(svg), 'icon.svg must not reference remote resources');
    }
    check(
      (pkg.files ?? []).some((entry) => entry === clean || entry === iconRel),
      `package.json files[] must ship the icon (${clean})`,
    );
    notes.push(`icon: ${clean} (${bytes} bytes)`);
  }
}
check(
  typeof pkg?.exports?.['./locale/*.json'] === 'string',
  'package.json must export "./locale/*.json" so the Plugin Manager can read titles without activating',
);
for (const language of ['en', 'zh']) {
  const file = join(ROOT, 'locale', `${language}.json`);
  if (!existsSync(file)) {
    problems.push(`locale/${language}.json is missing`);
    continue;
  }
  let meta = null;
  try {
    meta = JSON.parse(readFileSync(file, 'utf8'))?.meta ?? null;
  } catch (error) {
    problems.push(`locale/${language}.json: ${error.message}`);
    continue;
  }
  check(typeof meta?.title === 'string' && meta.title.trim().length > 0, `locale/${language}.json needs meta.title`);
  check(
    typeof meta?.description === 'string' && meta.description.trim().length >= 40,
    `locale/${language}.json needs a meta.description that actually describes the plugin`,
  );
}
check((pkg.files ?? []).includes('locale/*.json'), 'package.json files[] must ship locale/*.json');
notes.push('locale: en + zh meta.title/description');

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
    if (pkg) {
      check(
        block.includes(`version: "${pkg.version}"`),
        `SKILL.md metadata.version must match package.json (${pkg.version}) — run scripts/release.mjs so the four version anchors stay in step`,
      );
    }
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
