/**
 * provemark-dsh — always-on repository guardrail for DeepSeek Harness.
 *
 * Three contributions, weakest mechanism that suffices:
 *  1. a static system-prompt section with the rules the scanner enforces
 *     (so the model writes safer code instead of being corrected afterwards);
 *  2. a dynamic per-agent context block carrying the last scan of this
 *     workspace, refreshed by background scans after tool activity;
 *  3. two native tools — `provemark_guard` (fast, offline) and
 *     `provemark_scan` (reports / specific scanners / CI-gate parity).
 *
 * Every registration is optional and wrapped: a missing service, a missing
 * Python, or a host API that moved must degrade to "no guardrail", never to a
 * failed boot.
 */
import { writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import {
  resolveRoot,
  scan,
  applySafeFixes,
  cachedScan,
  rememberScan,
  verdictOf,
  findBySeverity,
  createBaseline,
  compareToBaseline,
  describeTrend,
} from './scan.js';
import { normalizeConfig } from './config.js';
import { pythonStatus, scannerPresent } from './python.js';
import { loadBaseline, saveBaseline } from './baseline-store.js';
import { GUARDRAILS, SECTION_NAME, CONTEXT_NAME, stateText, toolText } from './format.js';

export const name = 'provemark-guard';
export const VERSION = '0.6.2';

const MAX_SESSIONS = 64;

export function apply(ctx, rawConfig) {
  const settings = normalizeConfig(rawConfig);
  const diag = {
    startedAt: new Date().toISOString(),
    stages: {},
    tools: [],
    warnings: [],
    scans: 0,
    lastScan: null,
  };
  const markerFile = process.env.PROVEMARK_DSH_MARKER || join(tmpdir(), 'provemark-dsh-loaded.json');

  function flushMarker() {
    try {
      writeFileSync(
        markerFile,
        `${JSON.stringify(
          {
            at: new Date().toISOString(),
            pid: process.pid,
            version: VERSION,
            node: process.version,
            config: {
              autoScan: settings.autoScan,
              offline: settings.offline,
              autoFix: settings.autoFix,
              persistBaseline: settings.persistBaseline,
            },
            diag,
          },
          null,
          2,
        )}\n`,
        'utf8',
      );
    } catch {
      /* diagnostics must never block activation */
    }
  }

  flushMarker();
  if (!settings.enabled) {
    log(ctx, settings, 'disabled by config');
    return;
  }

  // ---------------------------------------------------------------- health
  // "Can this plugin scan at all?" is the first thing a user needs to know.
  // Probe off the activation path (Python discovery spawns processes) and keep
  // a one-minute cache so a host that fixes Python starts working without a
  // restart, without paying the probe cost on every prompt.
  const health = { python: null, pythonVersion: null, scanner: null, checkedAt: 0 };
  function refreshHealth() {
    try {
      const status = pythonStatus();
      health.python = status.ready;
      health.pythonVersion = status.version;
      health.scanner = scannerPresent();
      health.checkedAt = Date.now();
      diag.python = status.ready ? status.version : 'missing';
      diag.scanner = health.scanner;
      flushMarker();
      if (!status.ready) {
        log(ctx, settings, 'Python 3.11+ not found: scanning stays unavailable until PROVEMARK_PYTHON is set', 'warn');
      } else if (!health.scanner) {
        log(ctx, settings, 'bundled scanner directory is missing; reinstall the plugin', 'warn');
      }
    } catch (error) {
      health.python = null;
      log(ctx, settings, `health probe failed: ${String(error?.message ?? error)}`, 'warn');
    }
  }
  setTimeout(refreshHealth, 0).unref?.();

  let defineTool = null;
  // The host resolves `@deepseek-ai/dsh-tools` for loaded plugins. Two fallbacks
  // exist because a plugin that is *linked* (not pnpm-installed) has no peer
  // resolution of its own: the env override for offline self-tests, and the
  // Electron resources path, which the Host process can import through its own
  // asar-aware loader. Every attempt is recorded in the activation marker.
  const toolsReady = (async () => {
    const candidates = [];
    if (process.env.PROVEMARK_DSH_TOOLS_MODULE) candidates.push(process.env.PROVEMARK_DSH_TOOLS_MODULE);
    candidates.push('@deepseek-ai/dsh-tools');
    if (process.resourcesPath) {
      candidates.push(
        pathToFileURL(join(process.resourcesPath, 'app.asar', 'dsh', 'node_modules', '@deepseek-ai', 'dsh-tools', 'lib', 'index.js')).href,
      );
      candidates.push(
        pathToFileURL(join(process.resourcesPath, 'app.asar.unpacked', 'dsh', 'node_modules', '@deepseek-ai', 'dsh-tools', 'lib', 'index.js')).href,
      );
    }
    const errors = [];
    for (const specifier of candidates) {
      try {
        const mod = await import(specifier);
        const found = mod.defineTool ?? mod.default?.defineTool ?? null;
        if (typeof found === 'function') {
          defineTool = found;
          diag.stages.toolsImport = `ok: ${specifier}`;
          flushMarker();
          return;
        }
        errors.push(`${specifier}: no defineTool export`);
      } catch (error) {
        errors.push(`${specifier}: ${String(error?.code ?? error?.message ?? error)}`);
      }
    }
    diag.stages.toolsImport = `failed: ${errors.join(' | ')}`;
    log(ctx, settings, `tool API unavailable, running prompt-only: ${diag.stages.toolsImport}`, 'warn');
  })();

  /** sessionId → { root, lastAt, lastSummary, agent, notifiedAt } */
  const sessions = new Map();
  /** roots currently being scanned (background). */
  const busy = new Set();
  /** roots marked stale by tool activity. */
  const dirty = new Set();
  /**
   * Session ratchet: the first scan of a workspace in this process is frozen as
   * the baseline. A legacy repo may start messy — that is allowed. What must not
   * happen is "AI kept patching and the project got worse", and that is exactly
   * what comparing every later scan against this snapshot makes visible.
   */
  const baselines = new Map();
  const timers = new Set();
  let workingDirectory = null;
  let lastRoot = null;
  // Root of the most recently rendered session. Explicit `path` arguments must
  // never become the default for later calls: one tool call on a scratch repo
  // would otherwise redirect every "scan the workspace" request after it.
  let sessionRoot = null;

  function log(context, config, message, level = 'info') {
    if (diag.warnings.length < 30) diag.warnings.push(`${level}: ${message}`);
    flushMarker();
    if (!config.logPrefix) return;
    try {
      context?.logger?.[level]?.(`${config.logPrefix} ${message}`);
    } catch {
      /* logging must never fail a hook */
    }
  }

  function setTimer(fn, ms) {
    const handle = setTimeout(() => {
      timers.delete(handle);
      try {
        fn();
      } catch (error) {
        log(ctx, settings, `timer failed: ${String(error?.message ?? error)}`, 'warn');
      }
    }, ms);
    handle.unref?.();
    timers.add(handle);
    return handle;
  }

  function directoryOf(agent) {
    if (!agent?.session || workingDirectory === null) return null;
    try {
      return workingDirectory.get(agent.session);
    } catch {
      return null;
    }
  }

  function workspaceFor(agent) {
    const fromConfig = settings.workspace;
    if (fromConfig) {
      const resolved = resolveRoot(fromConfig);
      if (resolved.root) return resolved.root;
    }
    const fromSession = directoryOf(agent);
    if (fromSession) {
      const resolved = resolveRoot(fromSession);
      if (resolved.root) return resolved.root;
    }
    if (sessionRoot) return sessionRoot;
    if (lastRoot) return lastRoot;
    return null;
  }

  function sessionState(agent) {
    const id = agent?.session?.id ?? '__global__';
    let entry = sessions.get(id);
    if (!entry) {
      entry = {
        lastAt: 0,
        lastSummary: null,
        lastError: null,
        lastMode: '',
        agent: null,
        notifiedAt: 0,
        changes: 0,
        lastChangeAt: 0,
        scans: 0,
        blocking: 0,
        changeTimer: null,
      };
      sessions.set(id, entry);
      if (sessions.size > MAX_SESSIONS) {
        const oldest = [...sessions.entries()].filter(([key]) => key !== id).sort((a, b) => a[1].lastAt - b[1].lastAt)[0];
        if (oldest) sessions.delete(oldest[0]);
      }
    }
    if (agent) entry.agent = agent;
    return entry;
  }

  // ---------------------------------------------------------------- background
  function compareWithBaseline(root, summary, { reset = false } = {}) {
    if (reset) {
      const baseline = createBaseline(summary);
      baselines.set(root, baseline);
      if (settings.persistBaseline) saveBaseline(root, baseline);
      return null;
    }
    let baseline = baselines.get(root);
    if (!baseline && settings.persistBaseline) baseline = loadBaseline(root);
    if (!baseline) {
      baseline = createBaseline(summary);
      baselines.set(root, baseline);
      if (settings.persistBaseline) saveBaseline(root, baseline);
      diag.baseline = { root, source: settings.persistBaseline ? 'new-persisted' : 'new-memory' };
      return null;
    }
    baselines.set(root, baseline);
    diag.baseline = { root, source: baseline.persisted ? 'persisted' : 'memory' };
    return compareToBaseline(baseline, summary);
  }

  function scheduleScan(agent, { reason, force = false } = {}) {
    if (!settings.autoScan) return;
    const state = sessionState(agent);
    const root = workspaceFor(agent);
    if (!root) return;
    lastRoot = root;
    const now = Date.now();
    const entry = cachedScan(root);
    // After tool activity the workspace is dirty, so refresh on the short
    // interval; on an idle session fall back to a 5-minute refresh so a long
    // conversation does not rescan the same tree over and over. A change-driven
    // rescan uses its own floor (`changeMinRescanMs`) so a 50-call coding burst
    // still produces at most a handful of scans.
    const idleInterval = Math.max(settings.autoScanIntervalMs, 300_000);
    const interval =
      reason === 'change'
        ? settings.changeMinRescanMs
        : dirty.has(root)
          ? settings.autoScanIntervalMs
          : idleInterval;
    const fresh = entry && now - entry.at < interval && !force;
    if (fresh || busy.has(root)) return;

    busy.add(root);
    state.lastMode = settings.offline ? '离线' : '联网';
    void scan({
      root,
      offline: settings.offline,
      timeoutMs: settings.timeoutMs,
      maxFindings: settings.maxFindings,
      only: settings.scanOnly,
    })
      .then((outcome) => {
        const at = Date.now();
        const previous = entry?.summary ?? state.lastSummary ?? null;
        if (!outcome.ok) {
          state.lastAt = at;
          state.lastError = outcome.error;
          state.lastSummary = null;
          rememberScan(root, { at, ok: false, error: outcome.error, summary: null, root, mode: settings.lastMode ?? state.lastMode });
          log(ctx, settings, `background scan failed for ${root}: ${outcome.error}`, 'warn');
          return;
        }
        const summary = outcome.summary;
        state.lastAt = at;
        state.lastError = null;
        state.lastSummary = summary;
        state.lastMode = settings.offline ? '离线' : '联网';
        rememberScan(root, { at, ok: true, summary, root, durationMs: outcome.durationMs, mode: state.lastMode });
        dirty.delete(root);
        state.scans = (state.scans ?? 0) + 1;
        if (summary.counts.critical + summary.counts.high > 0) state.blocking = (state.blocking ?? 0) + 1;
        state.delta = compareWithBaseline(root, summary);
        diag.scans += 1;
        diag.lastScan = { at, ok: true, root, score: summary.score, grade: summary.grade };
        flushMarker();
        maybeNotify(agent, state, previous, summary, root);
      })
      .catch((error) => {
        state.lastError = String(error?.message ?? error);
        log(ctx, settings, `background scan crashed: ${state.lastError}`, 'warn');
      })
      .finally(() => busy.delete(root));
  }

  function maybeNotify(agent, state, previous, summary, root) {
    if (!settings.injectOnNewRisk) return;
    const risky = findBySeverity(summary, settings.injectMinSeverity);
    if (risky.length === 0) return;
    const previousPrinters = previous?.fingerprints ?? new Set();
    const fresh = risky.filter((finding) => !finding.fingerprint || !previousPrinters.has(finding.fingerprint));
    if (fresh.length === 0) return;
    const now = Date.now();
    if (now - state.notifiedAt < 10 * 60_000) return;
    const target = agent ?? state.agent;
    if (!target?.inject || !target?.ctx?.fiber) {
      // An agent that already went away cannot receive a notice; the state
      // block still carries the result on the next step.
      return;
    }
    state.notifiedAt = now;
    const lines = [
      `Provemark 守卫：${root} 的后台扫描发现 ${fresh.length} 条新的高优先级问题（分数 ${summary.score ?? '—'}/100 ${summary.grade}）。`,
      ...fresh.slice(0, 3).map((finding) => `- [${finding.severity}] ${finding.rule} ${finding.title}${finding.path ? ` ${finding.path}:${finding.line}` : ''}`),
      '处理建议：先修这些再继续；如果只是测试夹具或误报，说明原因，不要用 ignore 掩盖。',
    ];
    setTimer(() => {
      try {
        target.inject({ content: [{ type: 'text', text: lines.join('\n') }], source: { kind: 'provemark' } });
      } catch (error) {
        log(ctx, settings, `could not queue the risk notice: ${String(error?.message ?? error)}`, 'warn');
      }
    }, 0);
  }

  // ------------------------------------------------------------------- context
  ctx.on('session/event', (session, event) => {
    try {
      if (!settings.autoScan || !event || typeof event !== 'object') return;
      const type = String(event.type ?? '');
      if (type !== 'tool/result' && type !== 'user/message') return;
      const state = sessions.get(session?.id ?? '__global__');
      if (!state) return;
      state.dirty = true;
      if (type === 'tool/result') {
        // Every tool result may have touched the workspace; count it so the
        // context block can say "the conclusion below predates N tool calls".
        state.changes = (state.changes ?? 0) + 1;
        state.lastChangeAt = Date.now();
        dirty.add(state.root ?? '__unknown__');
      }
      const agent = state.agent ?? null;
      if (!agent) return;
      if (type === 'tool/result' && settings.scanOnChange) {
        // One scan per burst of editing: debounce so ten file writes still cost
        // one scan, and let it fire even inside the normal interval.
        if (state.changeTimer) {
          clearTimeout(state.changeTimer);
          timers.delete(state.changeTimer);
        }
        state.changeTimer = setTimer(() => {
          state.changeTimer = null;
          scheduleScan(agent, { reason: 'change' });
        }, settings.changeDebounceMs);
      } else {
        scheduleScan(agent, { reason: type });
      }
    } catch (error) {
      log(ctx, settings, `session event hook failed: ${String(error?.message ?? error)}`, 'warn');
    }
  });

  ctx.inject(['workingDirectory'], (sctx) => {
    workingDirectory = sctx.workingDirectory ?? null;
  });

  ctx.inject(['systemPrompt'], (sctx) => {
    const prompt = sctx.systemPrompt;
    if (!prompt) return;
    try {
      const disposeSection = prompt.section({
        name: SECTION_NAME,
        order: 620,
        interpolate: false,
        text: GUARDRAILS,
      });
      sctx.effect(() => () => {
        try {
          disposeSection?.();
        } catch {
          /* already gone */
        }
      }, 'provemark: guardrail section');
      diag.stages.section = 'ok';
      flushMarker();
    } catch (error) {
      log(ctx, settings, `could not add the guardrail section: ${String(error?.message ?? error)}`, 'warn');
    }

    try {
      const disposeContext = prompt.context({
        name: CONTEXT_NAME,
        order: 901,
        required: false,
        interpolate: false,
        text: (context) => {
          try {
            const agent = context?.agent ?? null;
            if (agent) {
              const state = sessionState(agent);
              state.root = workspaceFor(agent) ?? state.root;
              sessionRoot = state.root ?? sessionRoot;
              // A host that installed Python after boot should recover without a
              // restart; a minute-old "missing" verdict is stale enough to retry.
              if (health.checkedAt === 0 || Date.now() - health.checkedAt > 60_000) refreshHealth();
              const toolsDown = !/^ok:/.test(String(diag.stages.toolsRegistration ?? ''));
              scheduleScan(agent, { reason: 'context' });
              return stateText({
                root: state.root ?? null,
                summary: state.lastSummary,
                error: state.lastError,
                scannedAt: state.lastAt ? new Date(state.lastAt).toISOString() : null,
                mode: state.lastMode || (settings.offline ? '离线' : '联网'),
                cached: Boolean(cachedScan(state.root ?? '') && !busy.has(state.root ?? '')),
                stale: Boolean(state.lastChangeAt && state.lastChangeAt > state.lastAt),
                trendText: describeTrend(state.delta),
                scanning: Boolean(state.root && busy.has(state.root)),
                health: {
                  python: health.python,
                  pythonVersion: health.pythonVersion,
                  scanner: health.scanner,
                  tools: toolsDown ? false : true,
                },
                ledger: {
                  changes: state.changes ?? 0,
                  scans: state.scans ?? 0,
                  blocking: state.blocking ?? 0,
                },
              });
            }
          } catch (error) {
            log(ctx, settings, `state context failed: ${String(error?.message ?? error)}`, 'warn');
          }
          return '';
        },
      });
      sctx.effect(() => () => {
        try {
          disposeContext?.();
        } catch {
          /* already gone */
        }
      }, 'provemark: workspace state context');
      diag.stages.context = 'ok';
      flushMarker();
    } catch (error) {
      log(ctx, settings, `could not add the state context: ${String(error?.message ?? error)}`, 'warn');
    }
  });

  // --------------------------------------------------------------------- tools
  ctx.inject(['tools'], (sctx) => {
    void toolsReady.then(() => {
      if (defineTool === null) return;
      const tools = sctx.tools;
      if (!tools?.register) return;
      const disposers = [];
      const register = (definition, label) => {
        try {
          sctx.effect(() => {
            const dispose = tools.register(definition);
            diag.tools.push(definition.name);
            diag.stages.toolsRegistration = `ok: ${diag.tools.join(', ')}`;
            flushMarker();
            return () => {
              try {
                dispose?.();
              } catch {
                /* already disposed */
              }
            };
          }, label);
        } catch (error) {
          diag.stages.toolsRegistration = `failed: ${String(error?.message ?? error)}`;
          log(ctx, settings, `could not register ${label}: ${String(error?.message ?? error)}`, 'warn');
        }
      };

      register(
        defineTool({
          name: 'provemark_guard',
          description:
            'Run Provemark, the local repository risk scanner, over a workspace and return a compact verdict: score/grade, severity counts, top findings with file:line and the fix (CWE/OWASP mapped for code vulnerabilities), plus which findings the safe fixer can clear. Online by default (OSV vulnerabilities + deps.dev licenses), safe to call after edits and before claiming work is done. Covers application vulnerabilities (SQL/command injection, template injection, path traversal, SSRF, unsafe deserialization, XSS, weak crypto/hash/random, disabled TLS or JWT verification, XXE, C buffer functions, GitHub Actions script injection, privileged containers), license combination conflicts, known-vulnerable dependencies, leaked credentials, PII, AI-code risks (hallucinated imports, swallowed exceptions, eval), supply chain and repo hygiene.',
          parameters: {
            path: { type: 'string', description: 'Workspace or repository root to scan. Defaults to the session working directory.' },
            only: { type: 'string', description: 'Comma-separated scanners: repo, secrets, pii, security, ai, dependency, license, supply, fossa. Default: all.' },
            autoFix: { type: 'string', description: 'off | preview | apply. apply creates missing LICENSE/.gitignore/SECURITY.md/CI only, never edits business code. Default from plugin config (preview).' },
            offline: { type: 'boolean', description: 'Skip OSV/deps.dev queries. Default: plugin config (false → online, OSV + deps.dev).' },
            maxFindings: { type: 'number', description: 'How many findings to return. Default 5, max 20.' },
            fresh: { type: 'boolean', description: 'Ignore the cached result and rescan now.' },
            resetBaseline: { type: 'boolean', description: 'Treat the current result as the new baseline (use after intentionally accepting the current state; otherwise the first baseline of this workspace is kept across restarts).' },
          },
          output: {
            schema: {
              type: 'object',
              additionalProperties: false,
              properties: {
                root: { type: 'string' },
                verdict: { type: 'string' },
                score: { type: 'number' },
                grade: { type: 'string' },
                reliable: { type: 'boolean' },
                counts: {
                  type: 'object',
                  additionalProperties: false,
                  properties: {
                    critical: { type: 'number' },
                    high: { type: 'number' },
                    medium: { type: 'number' },
                    low: { type: 'number' },
                    info: { type: 'number' },
                  },
                },
                findings: {
                  type: 'array',
                  items: {
                    type: 'object',
                    additionalProperties: false,
                    properties: {
                      rule: { type: 'string' },
                      severity: { type: 'string' },
                      title: { type: 'string' },
                      path: { type: 'string' },
                      line: { type: 'number' },
                      cwe: { type: 'string' },
                      owasp: { type: 'string' },
                      confidence: { type: 'number' },
                      remediation: { type: 'string' },
                      fingerprint: { type: 'string' },
                      autoFixable: { type: 'boolean' },
                    },
                  },
                },
                autoFixable: { type: 'array', items: { type: 'string' } },
                notes: { type: 'array', items: { type: 'string' } },
                message: { type: 'string' },
                durationMs: { type: 'number' },
                cached: { type: 'boolean' },
                baselineScore: { type: 'number' },
                newFindings: { type: 'number' },
                fixedFindings: { type: 'number' },
                trend: { type: 'string' },
              },
            },
            render: (_args, value) => [{ type: 'text', text: toolText(value) }],
          },
          async execute(args, exec) {
            return runGuard(args ?? {}, exec);
          },
        }),
        'provemark: guard tool',
      );

      register(
        defineTool({
          name: 'provemark_scan',
          description:
            'Run the Provemark CLI with full control and optionally write a report: html (single offline file), markdown (paste into a PR), sarif (GitHub Code Scanning) or json. Use for user-facing reports, a single dimension (--only pii/license/...), SBOM cross-checks, CI-gate parity (--fail-on), or generating a repair brief for a coding agent (--ai-prompt).',
          parameters: {
            path: { type: 'string', description: 'Repository root. Defaults to the session working directory.' },
            format: { type: 'string', description: 'json | html | markdown | sarif. Default markdown.' },
            output: { type: 'string', description: 'Report path (absolute, or relative to the scanned root). Parent directories are created.' },
            only: { type: 'string', description: 'Comma-separated scanners to run.' },
            skip: { type: 'string', description: 'Comma-separated scanners to skip.' },
            offline: { type: 'boolean', description: 'Skip network lookups.' },
            failOn: { type: 'string', description: 'none | low | medium | high | critical — exit code 1 when reached.' },
            aiPrompt: { type: 'string', description: 'Write an agent-readable repair brief to this path.' },
            sbom: { type: 'string', description: 'Cross-check a CycloneDX/SPDX JSON SBOM file.' },
            verbose: { type: 'boolean', description: 'Include every finding in the console output.' },
          },
          output: {
            schema: {
              type: 'object',
              additionalProperties: false,
              properties: {
                root: { type: 'string' },
                reportPath: { type: 'string' },
                exitCode: { type: 'number' },
                verdict: { type: 'string' },
                score: { type: 'number' },
                grade: { type: 'string' },
                message: { type: 'string' },
              },
            },
            render: (_args, value) => [{ type: 'text', text: value.message }],
          },
          async execute(args, exec) {
            return runScan(args ?? {}, exec);
          },
        }),
        'provemark: scan tool',
      );
    });
  });

  // ------------------------------------------------------------------- helpers
  function guardedRoot(args, exec) {
    const candidate = typeof args.path === 'string' && args.path.trim() !== '' ? args.path : null;
    if (candidate !== null) return resolveRoot(candidate);
    // A tool call knows which agent invoked it: prefer that agent's working
    // directory over "the most recently rendered session", which is wrong when
    // two sessions run against different workspaces.
    const agent = exec?.agent ?? null;
    if (agent) {
      const fromAgent = directoryOf(agent);
      if (fromAgent) {
        const resolved = resolveRoot(fromAgent);
        if (resolved.root) return resolved;
      }
    }
    const fallback = settings.workspace || sessionRoot || lastRoot || process.cwd();
    return resolveRoot(fallback);
  }

  async function runGuard(args, exec) {
    const startedAt = Date.now();
    const { root, error } = guardedRoot(args, exec);
    if (root === null) {
      return {
        root: '',
        verdict: 'error',
        score: 0,
        grade: '',
        reliable: false,
        counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        findings: [],
        autoFixable: [],
        notes: [],
        message: `无法扫描：${error}`,
        durationMs: Date.now() - startedAt,
        cached: false,
        baselineScore: 0,
        newFindings: 0,
        fixedFindings: 0,
        trend: '',
      };
    }

    const only = typeof args.only === 'string' ? args.only.trim() : '';
    const offline = args.offline ?? settings.offline;
    const scope = `${only}|${offline ? 'offline' : 'online'}`;
    const cached = !args.fresh && cachedScan(root, scope);
    const cachedFresh = cached && cached.ok && Date.now() - cached.at < settings.cacheTtlMs;
    let outcome;
    if (cachedFresh) {
      outcome = { ok: true, root, summary: cached.summary, durationMs: 0, cached: true };
    } else {
      outcome = await scan({
        root,
        offline,
        timeoutMs: settings.toolTimeoutMs,
        maxFindings: clamp(args.maxFindings ?? settings.maxFindings, 1, 20),
        only,
        signal: exec?.signal,
      });
      if (outcome.ok) {
        rememberScan(
          root,
          {
            at: Date.now(),
            ok: true,
            summary: outcome.summary,
            root,
            durationMs: outcome.durationMs,
            mode: offline ? '离线' : '联网',
          },
          scope,
        );
      }
    }

    if (!outcome.ok) {
      return {
        root,
        verdict: 'error',
        score: 0,
        grade: '',
        reliable: false,
        counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        findings: [],
        autoFixable: [],
        notes: [],
        message: outcome.error,
        durationMs: Date.now() - startedAt,
        cached: false,
        baselineScore: 0,
        newFindings: 0,
        fixedFindings: 0,
        trend: '',
      };
    }

    const summary = outcome.summary;
    let finalSummary = summary;
    const autoFixMode = normalizeAutoFix(args.autoFix ?? settings.autoFix);
    let message = '';
    if (autoFixMode === 'apply' && summary.autoFixable.length > 0) {
      const fixed = await applySafeFixes({ root, timeoutMs: settings.toolTimeoutMs, signal: exec?.signal });
      const again = await scan({
        root,
        offline,
        timeoutMs: settings.toolTimeoutMs,
        maxFindings: settings.maxFindings,
        signal: exec?.signal,
      });
      if (again.ok) {
        finalSummary = again.summary;
        const entry = { at: Date.now(), ok: true, summary: again.summary, root, durationMs: again.durationMs, mode: offline ? '离线' : '联网' };
        rememberScan(root, entry);
        rememberScan(root, entry, scope);
      }
      message = fixed.ok
        ? `已执行安全修复（只新增文件，不改业务代码）：\n${fixed.output || '(无输出)'}\n修复后请重新调用 provemark_guard 确认。`
        : `安全修复失败（exit ${fixed.code}）：${fixed.stderr || fixed.output}`;
    } else if (autoFixMode === 'preview' && summary.autoFixable.length > 0) {
      message = `这些项可以由安全修复器补齐（只新增文件）：${[...new Set(summary.autoFixable)].join('、')}。需要时用 provemark_guard(autoFix="apply")。`;
    }

    // The ratchet: compare this answer with the first scan of the same root.
    const resetBaseline = Boolean(args.resetBaseline);
    const trend = compareWithBaseline(root, finalSummary, { reset: resetBaseline });
    const trendText = resetBaseline
      ? '已把当前结果设为新基线（后续改动与此比较）。'
      : describeTrend(trend);

    let verdict = verdictOf(finalSummary);
    if (trend && trend.newCount > 0) {
      if (['critical', 'high'].includes(trend.worstNewSeverity)) verdict = 'blocking';
      else if (verdict === 'clean') verdict = 'warn';
    }

    const state = sessionState(null);
    state.lastAt = Date.now();
    state.lastSummary = finalSummary;
    state.lastError = null;
    state.lastMode = offline ? '离线' : '联网';
    state.delta = trend;

    const notes = [...finalSummary.notes];
    if (only) {
      notes.push(`本次只运行了 ${only} 扫描器，分数只反映这些维度——不能当作整仓结论。`);
    }
    if (typeof args.autoFix === 'string' && !['off', 'preview', 'apply'].includes(args.autoFix)) {
      notes.push(`autoFix="${args.autoFix}" 不是合法值，已按 ${autoFixMode} 处理（off | preview | apply）。`);
    }

    return {
      root,
      verdict,
      score: finalSummary.score ?? 0,
      grade: finalSummary.grade ?? '',
      reliable: finalSummary.reliable,
      counts: finalSummary.counts,
      findings: finalSummary.top.map((finding) => ({
        rule: finding.rule,
        severity: finding.severity,
        title: finding.title,
        path: finding.path,
        line: finding.line,
        cwe: finding.cwe ?? '',
        owasp: finding.owasp ?? '',
        confidence: Number(finding.confidence ?? 0),
        remediation: finding.remediation,
        fingerprint: finding.fingerprint,
        autoFixable: Boolean(finding.autoFixable),
      })),
      autoFixable: finalSummary.autoFixable,
      notes,
      message,
      durationMs: Date.now() - startedAt,
      cached: Boolean(outcome.cached),
      baselineScore: trend?.baselineScore ?? 0,
      newFindings: trend?.newCount ?? 0,
      fixedFindings: trend?.fixedCount ?? 0,
      trend: trendText,
    };
  }

  async function runScan(args, exec) {
    const { root, error } = guardedRoot(args, exec);
    if (root === null) {
      return { root: '', reportPath: '', exitCode: 2, verdict: 'error', score: 0, grade: '', message: `无法扫描：${error}` };
    }
    const requestedFormat = typeof args.format === 'string' ? args.format.trim() : '';
    const format = ['json', 'html', 'markdown', 'sarif'].includes(requestedFormat) ? requestedFormat : 'markdown';
    const formatNote = requestedFormat && requestedFormat !== format ? `format="${requestedFormat}" 不支持，已用 markdown。` : '';
    const cliArgs = ['scan', root, '-f', format, '--no-color'];
    if (args.offline) cliArgs.push('--offline');
    if (typeof args.only === 'string' && args.only.trim()) cliArgs.push('--only', args.only.trim());
    if (typeof args.skip === 'string' && args.skip.trim()) cliArgs.push('--skip', args.skip.trim());
    if (typeof args.failOn === 'string' && args.failOn.trim()) cliArgs.push('--fail-on', args.failOn.trim());
    if (typeof args.sbom === 'string' && args.sbom.trim()) cliArgs.push('--sbom', args.sbom.trim());
    if (args.verbose) cliArgs.push('--verbose');

    const { mkdirSync } = await import('node:fs');
    const { dirname, isAbsolute, resolve: resolvePath } = await import('node:path');
    // Relative report/repair paths belong to the scanned repository, not to the
    // Host's process.cwd(): the model says "reports/scan.md" meaning the repo.
    const resolveOutput = (requested) => (isAbsolute(requested) ? requested : resolvePath(root, requested));

    let reportPath = '';
    if (typeof args.output === 'string' && args.output.trim()) {
      reportPath = resolveOutput(args.output.trim());
      try {
        mkdirSync(dirname(reportPath), { recursive: true });
      } catch (mkdirError) {
        return {
          root,
          reportPath: '',
          exitCode: 2,
          verdict: 'error',
          score: 0,
          grade: '',
          message: `无法创建报告目录：${String(mkdirError?.message ?? mkdirError)}`,
        };
      }
      cliArgs.push('-o', reportPath);
    }

    let promptPath = '';
    if (typeof args.aiPrompt === 'string' && args.aiPrompt.trim()) {
      promptPath = resolveOutput(args.aiPrompt.trim());
      try {
        mkdirSync(dirname(promptPath), { recursive: true });
      } catch (mkdirError) {
        return {
          root,
          reportPath,
          exitCode: 2,
          verdict: 'error',
          score: 0,
          grade: '',
          message: `无法创建修复指令目录：${String(mkdirError?.message ?? mkdirError)}`,
        };
      }
      cliArgs.push('--ai-prompt', promptPath);
    }

    // With nowhere to write the document, a human-readable format would be
    // thrown away on stdout and the tool would report nothing useful. Fall back
    // to JSON so the receipt can still state the score and severity counts.
    const silentDowngrade = !reportPath && format !== 'json';
    if (silentDowngrade) {
      const formatIndex = cliArgs.indexOf('-f') + 1;
      cliArgs[formatIndex] = 'json';
    }

    const outcome = await import('./python.js').then((mod) => mod.runProvemark(cliArgs, { timeoutMs: settings.toolTimeoutMs, signal: exec?.signal }));
    if (outcome.timedOut) {
      return { root, reportPath, exitCode: 2, verdict: 'error', score: 0, grade: '', message: `扫描超时（${Math.round(settings.toolTimeoutMs / 1000)}s）。` };
    }
    const stdout = String(outcome.stdout ?? '').trim();
    const stderr = String(outcome.stderr ?? '').trim();
    const gate = outcome.code === 1;
    // A report body belongs in the report file, not in the model's context: the
    // tool returns a short receipt plus the findings summary the CLI prints on
    // stderr. `output=` is how a caller asks for the full document.
    let receipt = '';
    if ((format === 'json' || silentDowngrade) && stdout) {
      try {
        const parsed = JSON.parse(stdout);
        const counts = parsed?.score?.counts ?? {};
        receipt = `分数 ${parsed?.score?.total ?? '—'}/${parsed?.score?.grade ?? '—'} · ` +
          `致命 ${counts.critical ?? 0} / 高危 ${counts.high ?? 0} / 中危 ${counts.medium ?? 0} · ` +
          `${(parsed?.findings ?? []).length} 条问题`;
      } catch {
        receipt = '';
      }
    }
    // The report body stays out of the model's context: `stderr` carries the
    // CLI receipt, and a caller who wants the document passes `output=`.
    const tail = stderr.slice(-600);
    const message = [
      gate
        ? `门禁命中（fail-on=${args.failOn ?? '策略默认'}），退出码 1。`
        : outcome.code === 0
          ? '扫描完成，门禁通过（退出码 0）。'
          : `扫描失败（退出码 ${outcome.code}）。`,
      formatNote,
      silentDowngrade ? `未指定 output：已用 JSON 摘要代替 ${format} 报告（需要报告就传 output=…）。` : '',
      reportPath
        ? `报告：${reportPath}`
        : format === 'json'
          ? '报告：未落盘（需要完整 JSON 就传 output=…）'
          : '报告：未落盘——报告正文没有塞进上下文；需要的话传 output=… 写入文件后再读。',
      promptPath ? `修复指令：${promptPath}` : '',
      receipt,
      tail ? `输出：\n${tail}` : '',
    ]
      .filter(Boolean)
      .join('\n');
    return {
      root,
      reportPath,
      exitCode: outcome.code,
      verdict: outcome.code === 0 ? 'clean' : gate ? 'blocking' : 'error',
      score: 0,
      grade: '',
      message,
    };
  }

  ctx.effect(() => () => {
    // Unload must not leave debounce/notice timers pointing at a disposed ctx.
    for (const handle of timers) {
      try {
        clearTimeout(handle);
      } catch {
        /* already cleared */
      }
    }
    timers.clear();
  }, 'provemark: timers');

  log(ctx, settings, `guardrail active (autoScan=${settings.autoScan}, offline=${settings.offline}, autoFix=${settings.autoFix})`);
}

function clamp(value, min, max) {
  const number = Number(value);
  if (!Number.isFinite(number)) return min;
  return Math.min(max, Math.max(min, Math.round(number)));
}

function normalizeAutoFix(value) {
  return ['off', 'preview', 'apply'].includes(value) ? value : 'preview';
}

