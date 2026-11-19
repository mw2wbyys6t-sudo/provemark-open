#!/usr/bin/env node
/**
 * Audit the shipped knowledge (`skills/provemark/**`) against the code.
 *
 * The skill is the plugin's knowledge layer; if it cites a rule id that does not
 * exist, a command the CLI does not accept, a parameter no tool declares, or a
 * count that drifted, the model following it will be confidently wrong. This
 * script guards that class of rot: every mechanically checkable claim is checked,
 * and CI runs it.
 *
 *   node scripts/audit-skill.mjs           # human report, exit 1 on drift
 *   node scripts/audit-skill.mjs --json    # machine readable
 *
 * Rule ids / category / ecosystem counts come from the Python scanner itself
 * (spawned once). Without a Python interpreter those three checks are skipped
 * with a note instead of silently passing.
 */
import { spawnSync } from 'node:child_process';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const PACKAGE_ROOT = resolve(HERE, '..');
const REPO_ROOT = resolve(PACKAGE_ROOT, '..', '..');
const SKILL_ROOT = join(PACKAGE_ROOT, 'skills', 'provemark');
const PY_SRC = join(REPO_ROOT, 'provemark');
const ENTRY = join(PACKAGE_ROOT, 'lib', 'index.js');
const json = process.argv.includes('--json');

const problems = [];
const notes = [];

const read = (file) => readFileSync(file, 'utf8');
const unique = (values) => [...new Set(values)];

function listDocs(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...listDocs(full));
    else if (entry.name.endsWith('.md')) out.push(full);
  }
  return out;
}

// ------------------------------------------------------------ python truth
const PROBE = [
  'import argparse, json',
  'from provemark.rules.catalog import catalog',
  'from provemark.models import CATEGORIES',
  'from provemark import ecosystems',
  'from provemark.cli import build_parser',
  'parser = build_parser()',
  'subcommands, flags = [], set()',
  'for action in parser._actions:',
  '    flags.update(action.option_strings or [])',
  '    if isinstance(action, argparse._SubParsersAction):',
  '        subcommands = sorted(action.choices)',
  '        for sub in action.choices.values():',
  '            for sub_action in sub._actions:',
  '                flags.update(sub_action.option_strings or [])',
  'print(json.dumps({',
  '  "rules": sorted(catalog()),',
  '  "categories": sorted(CATEGORIES),',
  '  "ecosystems": sorted(ecosystems.ECOSYSTEMS),',
  '  "subcommands": subcommands,',
  '  "flags": sorted(flags),',
  '}))',
].join('\n');

function pythonTruth() {
  const interpreters = [process.env.PROVEMARK_PYTHON, process.execPath && null, 'python', 'python3', 'py'].filter(Boolean);
  for (const candidate of interpreters) {
    const args = candidate === 'py' ? ['-3', '-c', PROBE] : ['-c', PROBE];
    const result = spawnSync(candidate, args, {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      timeout: 60_000,
      windowsHide: true,
      env: { ...process.env, PYTHONIOENCODING: 'utf-8', PYTHONUTF8: '1' },
    });
    if (result.error || result.status !== 0) continue;
    try {
      const parsed = JSON.parse(String(result.stdout ?? '').trim());
      if (Array.isArray(parsed.rules) && parsed.rules.length > 0) return parsed;
    } catch {
      /* try the next interpreter */
    }
  }
  return null;
}

const truth = pythonTruth();
if (truth === null) {
  notes.push('python unavailable: rule ids and the rule/category/ecosystem counts were NOT verified');
}

// ------------------------------------------------------------ static truth
// Fallback only: when a Python interpreter is available the authoritative
// subcommand/flag list comes from the real argparse tree (see pythonTruth).
const cliText = read(join(PY_SRC, 'cli.py'));
const staticSubcommands = unique([...cliText.matchAll(/sub\.add_parser\(\s*"([a-z][a-z-]*)"/g)].map((match) => match[1]));
const staticFlags = unique([...cliText.matchAll(/["'](--[a-z][a-z-]+)["']/g)].map((match) => match[1]));
const subcommands = truth?.subcommands?.length ? truth.subcommands : staticSubcommands;
const cliFlags = truth?.flags?.length ? truth.flags : staticFlags;

const entryText = read(ENTRY);
const toolParams = {};
for (const match of entryText.matchAll(/name: '(provemark_\w+)'/g)) {
  const start = match.index + match[0].length;
  const tail = entryText.slice(start, start + 8000);
  const block = /parameters: \{([\s\S]*?)\n          \},/.exec(tail)?.[1] ?? '';
  toolParams[match[1]] = unique([...block.matchAll(/^\s+([a-zA-Z_]+): \{/gm)].map((item) => item[1]));
}

const playbooks = readdirSync(join(SKILL_ROOT, 'references')).filter(
  (name) => name.endsWith('-playbook.md') || name === 'maintenance-discipline.md' || name === 'ai-collaboration.md',
).length;

// Flags that belong to the other launchers the docs legitimately mention.
const WRAPPER_FLAGS = new Set(['--pm-info']);
const INSTALL_FLAGS = new Set(['--profile', '--check', '--copy', '--dry-run', '--json', '--force', '--uninstall']);

notes.push(`cli: ${subcommands.length} subcommands, ${cliFlags.length} flags`);
notes.push(`tools: ${Object.entries(toolParams).map(([name, params]) => `${name}(${params.length})`).join(', ')}`);
notes.push(`playbooks: ${playbooks}`);
if (truth) {
  notes.push(`python: ${truth.rules.length} rules, ${truth.categories.length} categories, ${truth.ecosystems.length} ecosystems`);
}

// ------------------------------------------------------------------- checks
const RULE_ID = /\b(?:AI|DEP|FOS|HYG|LIC|PII|SCP|SEC|SUP|VUL)-\d{3}\b/g;
const CLI_CALL = /provemark(?:\.mjs)?["']?\s+([a-z][a-z-]+)/g;
const FLAG = /(?<![\w-])(--[a-z][a-z-]+)/g;
const TOOL = /\bprovemark_(?:guard|scan|progress)\b/g;
// Lines that invoke a different tool in the same fence are not claims about our CLI.
const OTHER_TOOL = /\b(pip|uv|poetry|npm|pnpm|yarn|fossa|git|gh|docker|curl|.\binstall\.mjs|.\brelease\.mjs|.\bsync-vendor\.mjs|.\bselftest\.mjs|.\bvalidate\.mjs|.\bdoctor\.mjs)/;

const docs = listDocs(SKILL_ROOT);
const checked = { docs: docs.length, ruleRefs: 0, cliRefs: 0, flagRefs: 0, toolParams: 0 };

for (const file of docs) {
  const rel = relative(REPO_ROOT, file).replaceAll('\\', '/');
  const text = read(file);
  // The YAML frontmatter is metadata, not prose: `name: provemark` followed by
  // `description:` must not be mistaken for a `provemark description` command.
  const body = text.replace(/^---\r?\n[\s\S]*?\r?\n---\r?\n/, '');

  for (const rule of unique(body.match(RULE_ID) ?? [])) {
    if (!truth) continue;
    checked.ruleRefs += 1;
    if (!truth.rules.includes(rule)) problems.push(`${rel}: cites rule ${rule}, which the scanner does not implement`);
  }

  for (const match of body.matchAll(CLI_CALL)) {
    const command = match[1];
    if (WRAPPER_FLAGS.has(`--${command}`)) continue;
    checked.cliRefs += 1;
    if (!subcommands.includes(command)) problems.push(`${rel}: runs \`provemark ${command}\`, which is not a subcommand`);
  }

  for (const line of body.split('\n')) {
    if (!line.includes('provemark')) continue;
    if (OTHER_TOOL.test(line) && !line.includes('provemark.mjs')) continue;
    for (const flag of unique(line.match(FLAG) ?? [])) {
      checked.flagRefs += 1;
      if (cliFlags.includes(flag) || WRAPPER_FLAGS.has(flag) || INSTALL_FLAGS.has(flag)) continue;
      problems.push(`${rel}: documents ${flag} on a provemark command; no subcommand accepts it`);
    }
  }

  for (const claim of body.matchAll(/(\d+)\s*条规则/g)) {
    if (truth && Number(claim[1]) !== truth.rules.length) {
      problems.push(`${rel}: claims ${claim[1]} rules, the scanner implements ${truth.rules.length}`);
    }
  }
  for (const claim of body.matchAll(/(?<![\d\-–~—])(\d+)\s*个维度/g)) {
    if (truth && Number(claim[1]) !== truth.categories.length) {
      problems.push(`${rel}: claims ${claim[1]} categories, models.py defines ${truth.categories.length}`);
    }
  }
  for (const claim of body.matchAll(/(\d+)\s*个生态/g)) {
    if (truth && Number(claim[1]) !== truth.ecosystems.length) {
      problems.push(`${rel}: claims ${claim[1]} ecosystems, ecosystems.py defines ${truth.ecosystems.length}`);
    }
  }
  for (const claim of body.matchAll(/(?<![\d\-–~—])(\d+)\s*本[^，。\n]{0,8}手册/g)) {
    if (Number(claim[1]) !== playbooks) {
      problems.push(`${rel}: claims ${claim[1]} playbooks, references/ ships ${playbooks}`);
    }
  }
  for (const tool of unique(body.match(TOOL) ?? [])) {
    if (!(tool in toolParams)) problems.push(`${rel}: mentions ${tool}, which the plugin does not register`);
  }
}

// Parameter names documented for each tool must exist in that tool's schema.
try {
  const toolsText = read(join(SKILL_ROOT, 'references', 'tools.md'));
  for (const section of toolsText.split(/^### /m).slice(1)) {
    const tool = /`(provemark_\w+)`/.exec(section)?.[1];
    if (!tool || !(tool in toolParams)) continue;
    for (const row of section.matchAll(/^\|\s*`([a-zA-Z_]+)`\s*\|/gm)) {
      checked.toolParams += 1;
      if (!toolParams[tool].includes(row[1])) {
        problems.push(`references/tools.md: ${tool} has no parameter "${row[1]}"`);
      }
    }
  }
} catch {
  problems.push('references/tools.md is missing');
}

if (json) {
  console.log(JSON.stringify({ ok: problems.length === 0, checked, playbooks, truth: truth ?? null, problems, notes }, null, 2));
} else {
  for (const note of notes) console.log(`[audit] ${note}`);
  console.log(
    `[audit] checked ${checked.docs} docs: ${checked.ruleRefs} rule refs, ${checked.cliRefs} commands, ` +
      `${checked.flagRefs} flags, ${checked.toolParams} tool params`,
  );
  if (problems.length === 0) console.log('[audit] pass');
  else for (const problem of problems) console.error(`[audit] fail ${problem}`);
}
process.exit(problems.length === 0 ? 0 : 1);
