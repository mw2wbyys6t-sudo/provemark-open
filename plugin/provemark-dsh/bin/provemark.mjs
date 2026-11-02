#!/usr/bin/env node
/**
 * provemark-dsh CLI launcher — runs the bundled scanner with a Python the host
 * already has. Used by the skill's copy-paste recipes and by CI; the in-process
 * guardrail (lib/index.js) calls the same scanner through lib/python.js.
 *
 *   node bin/provemark.mjs scan . --offline
 *   node bin/provemark.mjs --pm-info      # resolution diagnostics, no scan
 */
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { formatVersion, PACKAGE_ROOT, PYTHON_ROOT, resolvePython, scannerEnv, scannerPresent } from '../lib/python.js';

const argv = process.argv.slice(2);
if (argv[0] === '--') argv.shift();

function note(message) {
  process.stderr.write(`[provemark-dsh] ${message}\n`);
}

const resolution = resolvePython();

if (argv[0] === '--pm-info') {
  const info = {
    package: 'provemark-dsh',
    packageRoot: PACKAGE_ROOT,
    skillRoot: join(PACKAGE_ROOT, 'skills'),
    pythonRoot: PYTHON_ROOT,
    requires: 'python 3.11+',
    scannerPresent: scannerPresent(),
    python:
      resolution.python === null
        ? null
        : {
            cmd: resolution.python.cmd,
            prefix: resolution.python.prefix,
            version: formatVersion(resolution.python.version),
          },
    probed: resolution.tried,
  };
  process.stdout.write(`${JSON.stringify(info, null, 2)}\n`);
  process.exit(0);
}

if (!existsSync(join(PYTHON_ROOT, 'provemark', '__init__.py'))) {
  note(`bundled scanner missing at ${join(PYTHON_ROOT, 'provemark')} — reinstall the provemark-dsh package`);
  process.exit(2);
}

if (resolution.python === null) {
  note('no Python 3.11+ interpreter found.');
  note('install Python 3.11+ (or the DeepSeek Harness runtime), then retry.');
  note('or point PROVEMARK_PYTHON at an interpreter, e.g. PROVEMARK_PYTHON=C:\\Python312\\python.exe');
  for (const attempt of resolution.tried) {
    note(`  tried: ${attempt.cmd} ${attempt.prefix.join(' ')} -> ${attempt.ok ? `python ${attempt.version} (too old)` : 'not runnable'}`);
  }
  process.exit(2);
}

const child = spawnSync(
  resolution.python.cmd,
  [...resolution.python.prefix, '-P', '-B', '-m', 'provemark', ...argv],
  { stdio: 'inherit', env: scannerEnv(), windowsHide: false },
);

if (child.error) {
  note(`failed to start ${resolution.python.cmd}: ${child.error.message}`);
  process.exit(2);
}
if (child.signal) {
  process.kill(process.pid, child.signal);
  process.exit(1);
}
process.exit(child.status ?? 2);
