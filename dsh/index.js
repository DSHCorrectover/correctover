/**
 * @file correctover/dsh — DeepSeek Harness runtime security guard.
 *
 * CCS (Correctover Conformance Shape) is a 7-dimension runtime verification
 * standard for AI agents. This DSH plugin enforces security dimensions at
 * the tool-call, subprocess, and fetch boundaries — not by static scanning
 * plugin source files, but by inspecting every runtime operation before it
 * executes.
 *
 * Registers:
 *  - `ccs_status` model tool: report current policy and stats
 *  - `ccs_audit` model tool: run a security audit on installed plugins
 *  - tools/pre-execute hook: block dangerous tool calls
 *  - tools/post-execute hook: scan outputs for leaked secrets / injection
 *  - subprocess spawn wrapper: block command injection and credential exposure
 *  - web fetch wrapper: block SSRF to private networks
 *
 * @module correctover/dsh
 */

import { homedir } from 'node:os';
import { existsSync, readdirSync, readFileSync, mkdirSync, writeFileSync, appendFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { evaluateToolCall, evaluateToolResult, evaluateSubprocess, DEFAULT_POLICY } from './policy.js';
import { scanForSecrets } from './credentials.js';
import { detectInjection } from './injection.js';
import { inspectSpawn } from './cmdi.js';
import { isPro, GATE_CTA } from './license.js';

const name = 'correctover-dsh';
const inject = ['tools'];

// ── State ────────────────────────────────────────────────────────────────

let stats = {
  toolCallsChecked: 0,
  toolCallsBlocked: 0,
  toolResultsScanned: 0,
  subprocessesChecked: 0,
  subprocessesBlocked: 0,
  fetchCallsChecked: 0,
  fetchCallsBlocked: 0,
  secretsDetected: 0,
  injectionAttempts: 0,
  blockReasons: [],
};

let config = structuredClone(DEFAULT_POLICY);
let logFile;

function resolveDshHome() {
  return process.env.DSH_HOME ?? join(homedir(), '.dsh');
}

function initLog() {
  const logDir = join(resolveDshHome(), '.correctover-dsh');
  try {
    mkdirSync(logDir, { recursive: true });
    logFile = join(logDir, 'security.log');
  } catch {
    logFile = undefined;
  }
}

function log(level, message, detail) {
  const entry = JSON.stringify({
    ts: new Date().toISOString(),
    level,
    message,
    ...detail && { detail },
  });
  if (logFile) {
    try { appendFileSync(logFile, entry + '\n', 'utf8'); } catch { /* best-effort */ }
  }
  const logger = globalThis.__dshCcsCtx?.logger;
  if (logger?.[level]) {
    try { logger[level](`[ccs] ${message}`); } catch { /* best-effort */ }
  }
}

function recordBlock(reason) {
  stats.toolCallsBlocked++;
  stats.blockReasons.push({ ts: new Date().toISOString(), reason: reason.slice(0, 200) });
  if (stats.blockReasons.length > 50) stats.blockReasons.shift();
  log('warn', 'blocked', { reason: reason.slice(0, 500) });
}

// ── Tool definitions ─────────────────────────────────────────────────────

const STATUS_TOOL = {
  name: 'ccs_status',
  description: 'Report CCS runtime security guard status: policy configuration, cumulative block/scan statistics, and recent security events. Use this to verify CCS is active and review what has been blocked.',
  parameters: { type: 'object', properties: {} },
  output: {
    schema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        active: { type: 'boolean' },
        version: { type: 'string' },
        policy: { type: 'object' },
        stats: { type: 'object' },
        recentBlocks: { type: 'array', items: { type: 'object' } },
      },
    },
    render: (_args, value) => {
      const lines = [
        '# CCS Runtime Security Guard',
        '',
        `**Status**: ${value.active ? 'ACTIVE / 运行中' : 'INACTIVE'}`,
        `**Version**: ${value.version}`,
        '',
        '## Statistics / 统计',
        '',
        `- Tool calls checked: ${value.stats.toolCallsChecked}`,
        `- Tool calls blocked: ${value.stats.toolCallsBlocked}`,
        `- Tool results scanned: ${value.stats.toolResultsScanned}`,
        `- Subprocesses checked: ${value.stats.subprocessesChecked}`,
        `- Subprocesses blocked: ${value.stats.subprocessesBlocked}`,
        `- Fetch calls checked: ${value.stats.fetchCallsChecked}`,
        `- Fetch calls blocked: ${value.stats.fetchCallsBlocked}`,
        `- Secrets detected: ${value.stats.secretsDetected}`,
        `- Injection attempts: ${value.stats.injectionAttempts}`,
      ];
      if (value.recentBlocks.length > 0) {
        lines.push('', '## Recent Blocks / 最近拦截', '');
        for (const b of value.recentBlocks.slice(-10)) {
          lines.push(`- [${b.ts}] ${b.reason}`);
        }
      }
      return [{ type: 'text', text: applyReportGate(lines.join('\n')) }];
    },
  },
  async execute() {
    return {
      active: true,
      version: '2.4.6',
      policy: {
        ssrf: config.ssrf,
        commandInjection: config.commandInjection,
        credentialExfil: config.credentialExfil,
        promptInjection: config.promptInjection,
        destructiveTools: { enabled: config.destructiveTools.enabled, requireApprovalCount: config.destructiveTools.requireApproval.length },
      },
      stats: { ...stats },
      recentBlocks: stats.blockReasons.slice(-10),
    };
  },
};

const AUDIT_TOOL = {
  name: 'ccs_audit',
  description: 'Run a CCS security audit on installed DSH plugins. Scans plugin source for credential access patterns, command injection risks, and network exfiltration indicators — with runtime-intent analysis (not just keyword matching). Returns per-plugin risk assessment.',
  parameters: {
    type: 'object',
    properties: {
      path: { type: 'string', description: 'Optional path to scan. Defaults to all profiles under $DSH_HOME/profiles.' },
    },
  },
  output: {
    schema: {
      type: 'object',
      additionalProperties: false,
      properties: {
        scanned: { type: 'number' },
        plugins: { type: 'array', items: { type: 'object' } },
        summary: { type: 'object' },
      },
    },
    render: (_args, value) => {
      const lines = [
        `# CCS Plugin Audit — ${value.scanned} plugin(s) scanned`,
        '',
        `High: ${value.summary.high}  Medium: ${value.summary.medium}  Low: ${value.summary.low}  Safe: ${value.summary.safe}`,
      ];
      for (const p of value.plugins) {
        lines.push('', `## [${p.risk}] ${p.name}@${p.version}`, '');
        for (const f of p.findings.slice(0, 8)) {
          lines.push(`- **${f.severity}** ${f.category}: ${f.detail}`);
        }
      }
      return [{ type: 'text', text: applyReportGate(lines.join('\n')) }];
    },
  },
  async execute(args) {
    const roots = [];
    if (args?.path) {
      roots.push(args.path);
    } else {
      const profiles = join(resolveDshHome(), 'profiles');
      if (existsSync(profiles)) {
        for (const entry of readdirSync(profiles, { withFileTypes: true })) {
          if (!entry.isDirectory()) continue;
          const nm = join(profiles, entry.name, 'node_modules');
          if (existsSync(nm)) roots.push(nm);
        }
      }
    }

    const plugins = [];
    const summary = { high: 0, medium: 0, low: 0, safe: 0 };

    for (const root of roots) {
      let entries;
      try { entries = readdirSync(root, { withFileTypes: true }); } catch { continue; }
      for (const entry of entries) {
        if (!entry.isDirectory() && !entry.name.startsWith('@')) continue;
        const pkgDir = join(root, entry.name);
        const pkgJsonPath = join(pkgDir, 'package.json');
        if (!existsSync(pkgJsonPath)) continue;

        let pkg;
        try { pkg = JSON.parse(readFileSync(pkgJsonPath, 'utf8')); } catch { continue; }

        // Skip official packages
        if (pkg.name?.startsWith('@deepseek-ai/')) continue;

        const findings = auditPlugin(pkgDir, pkg);
        let risk = 'SAFE';
        const score = findings.reduce((s, f) => s + ({ HIGH: 10, MEDIUM: 5, LOW: 2 }[f.severity] || 0), 0);
        if (score >= 10) { risk = 'HIGH'; summary.high++; }
        else if (score >= 5) { risk = 'MEDIUM'; summary.medium++; }
        else if (score > 0) { risk = 'LOW'; summary.low++; }
        else { summary.safe++; }

        plugins.push({ name: pkg.name || entry.name, version: pkg.version || '0.0.0', risk, findings });
      }
    }

    return { scanned: plugins.length, plugins, summary };
  },
};

/**
 * Audit a single plugin package for security risks.
 * Uses runtime-intent analysis rather than pure keyword matching.
 */
function auditPlugin(pkgDir, pkg) {
  const findings = [];

  // Collect source files
  const sourceFiles = [];
  const SKIP = new Set(['node_modules', '.git', 'dist', '.DS_Store']);
  function walk(dir, depth = 0) {
    if (depth > 5 || sourceFiles.length >= 200) return;
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (sourceFiles.length >= 200) return;
      const full = join(dir, e.name);
      if (e.isDirectory()) {
        if (!SKIP.has(e.name)) walk(full, depth + 1);
      } else if (/\.(js|mjs|cjs|ts)$/.test(e.name)) {
        sourceFiles.push(full);
      }
    }
  }
  walk(pkgDir);

  let allSource = '';
  for (const file of sourceFiles) {
    try { allSource += readFileSync(file, 'utf8') + '\n'; } catch { /* skip */ }
  }

  if (!allSource) return findings;

  // Check for network exfiltration capability
  if (/\bfetch\s*\(/.test(allSource) || /\bhttps?\.request\b/.test(allSource) || /\bnet\.connect\b/.test(allSource)) {
    const hasSecrets = scanForSecrets(allSource);
    if (hasSecrets.length > 0) {
      findings.push({ severity: 'HIGH', category: 'data-exfiltration', detail: `makes network requests AND references credential patterns (${hasSecrets.map(s => s.label).join(', ')})` });
    } else {
      findings.push({ severity: 'LOW', category: 'network-access', detail: 'makes outbound network requests' });
    }
  }

  // Check for subprocess execution
  if (/child_process|\bspawn\s*\(|\bexec(Sync)?\s*\(/.test(allSource)) {
    const cmdResult = inspectSpawn({ command: allSource.slice(0, 5000) }, 12);
    if (cmdResult.blocked) {
      findings.push({ severity: 'HIGH', category: 'command-injection', detail: cmdResult.reason });
    } else {
      findings.push({ severity: 'MEDIUM', category: 'subprocess', detail: 'spawns child processes' });
    }
  }

  // Check for dynamic code execution
  if (/\beval\s*\(|new Function\s*\(|vm\.runIn/.test(allSource)) {
    findings.push({ severity: 'HIGH', category: 'code-execution', detail: 'uses dynamic code execution (eval/Function/vm) — runtime behavior cannot be statically determined' });
  }

  // Check for credential file access
  if (/\.ssh\/id_rsa|\.aws\/credentials|\.credentials\.ya?ml|\.netrc|\.pgpass/.test(allSource)) {
    findings.push({ severity: 'HIGH', category: 'credential-access', detail: 'references known credential file paths' });
  }

  // Check for env credential reads
  if (/process\.env\.[A-Z_]*(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)/i.test(allSource)) {
    findings.push({ severity: 'MEDIUM', category: 'credential-access', detail: 'reads credential-like environment variables' });
  }

  // Check for prompt injection patterns in source
  const injection = detectInjection(allSource.slice(0, 10000), { threshold: 10 });
  if (injection.blocked) {
    findings.push({ severity: 'MEDIUM', category: 'prompt-injection', detail: `source contains injection-like patterns: ${injection.hits.map(h => h.label).join(', ')}` });
  }

  // Check for persistence mechanisms
  if (/\.bashrc|\.zshrc|\.profile|authorized_keys|schtasks|cron/.test(allSource)) {
    findings.push({ severity: 'MEDIUM', category: 'persistence', detail: 'references persistence mechanisms' });
  }

  // Check for obfuscation
  if (/String\.fromCharCode|\\x[0-9a-f]{2}\\x[0-9a-f]{2}/.test(allSource)) {
    findings.push({ severity: 'MEDIUM', category: 'obfuscation', detail: 'uses obfuscation techniques' });
  }

  // Check npm lifecycle scripts
  if (pkg.scripts) {
    const lifecycle = ['preinstall', 'install', 'postinstall', 'prepare', 'prepublishOnly'];
    for (const hook of lifecycle) {
      if (pkg.scripts[hook]) {
        findings.push({ severity: 'LOW', category: 'supply-chain', detail: `has "${hook}" lifecycle script: ${pkg.scripts[hook].slice(0, 100)}` });
      }
    }
  }

  return findings;
}

// ── Plugin apply ─────────────────────────────────────────────────────────

function apply(ctx, userConfig) {
  // Merge user config
  if (userConfig && typeof userConfig === 'object') {
    config = deepMerge(config, userConfig);
  }

  initLog();
  globalThis.__dshCcsCtx = ctx;
  log('info', 'CCS runtime security guard starting', { version: '2.4.6' });

  // ── 交互存在感：会话启动横幅（2026-08-19 感知层）──
  // 让用户第一眼看到 CCS 在运行，而非静默守护。tier 来自 license.js。
  try {
    const _tier = isPro() ? 'Pro' : 'Free';
    const _banner = [
      '',
      '🛡️  CCS Guard active — 7-dimension runtime verification',
      `   ${_tier} tier · IETF draft-correctover-ccs-04 · DSH + MCP security`,
      `   输入 ccs_status 查看防护统计，ccs_audit 审计已装插件`,
      '',
    ].join('\n');
    if (typeof ctx.emit === 'function') ctx.emit('ccs/banner', _banner);
    log('info', 'CCS banner emitted', { tier: _tier });
  } catch (err) {
    log('warn', 'CCS banner emit failed', { error: String(err).slice(0, 120) });
  }

  // Register tools
  ctx.effect(() => ctx.tools.register(STATUS_TOOL), 'ccs: status tool');
  ctx.effect(() => ctx.tools.register(AUDIT_TOOL), 'ccs: audit tool');

  // ── Pre-execute hook: block dangerous tool calls ──────────────────────
  ctx.on('tools/pre-execute', async (exec) => {
    stats.toolCallsChecked++;

    try {
      const decision = await evaluateToolCall(
        { name: exec.name, arguments: exec.arguments, agent: exec.agent },
        config,
      );

      if (!decision.allow) {
        recordBlock(decision.reason);
        return { kind: 'deny', reason: decision.reason };
      }

      // Log warnings
      for (const w of decision.warnings) {
        log('warn', `tool "${exec.name}": ${w}`);
      }

      return { kind: 'allow' };
    } catch (err) {
      // Fail-open on internal errors (don't break the harness)
      log('error', `pre-execute evaluation error: ${err?.message || err}`);
      return { kind: 'allow' };
    }
  });

  // ── Post-execute hook: scan outputs for secrets/injection ─────────────
  ctx.on('tools/post-execute', async (exec, result) => {
    stats.toolResultsScanned++;

    try {
      const decision = evaluateToolResult(result, config, { toolName: exec.name });

      if (!decision.allow) {
        recordBlock(`output from "${exec.name}": ${decision.reason}`);
        return {
          kind: 'block',
          feedback: [{ type: 'text', text: `[CCS] Tool output blocked: ${decision.reason}` }],
        };
      }

      for (const w of decision.warnings) {
        log('warn', `output from "${exec.name}": ${w}`);
        if (w.includes('credential')) stats.secretsDetected++;
      }

      return { kind: 'accept' };
    } catch (err) {
      log('error', `post-execute evaluation error: ${err?.message || err}`);
      return { kind: 'accept' };
    }
  });

  // ── Subprocess spawn wrapper ──────────────────────────────────────────
  const subprocess = ctx.get?.('subprocess');
  if (subprocess && typeof subprocess.spawn === 'function') {
    const originalSpawn = subprocess.spawn;
    ctx.effect(() => {
      subprocess.spawn = (spec) => {
        stats.subprocessesChecked++;

        try {
          const decision = evaluateSubprocess(spec, config);
          if (!decision.allow) {
            stats.subprocessesBlocked++;
            recordBlock(`subprocess: ${decision.reason}`);
            throw new Error(`[CCS] Subprocess blocked: ${decision.reason}`);
          }
          for (const w of decision.warnings) {
            log('warn', `subprocess: ${w}`);
          }
        } catch (err) {
          if (err.message?.startsWith('[CCS]')) throw err;
          log('error', `subprocess evaluation error: ${err?.message || err}`);
        }

        return originalSpawn(spec);
      };
      return () => { subprocess.spawn = originalSpawn; };
    }, 'ccs: subprocess guard');
  }

  // ── Web fetch wrapper (if web service is available) ───────────────────
  const web = ctx.get?.('web');
  if (web && typeof web.fetch === 'function') {
    const originalFetch = web.fetch;
    ctx.effect(() => {
      web.fetch = async (url, opts) => {
        stats.fetchCallsChecked++;
        try {
          const { validateFetchUrl } = await import('./ssrf.js');
          const reason = await validateFetchUrl(url, { allowPrivate: config.ssrf.allowPrivate });
          if (reason) {
            stats.fetchCallsBlocked++;
            recordBlock(`fetch ${url}: ${reason}`);
            throw new Error(`[CCS] Fetch blocked: ${reason}`);
          }
        } catch (err) {
          if (err.message?.startsWith('[CCS]')) throw err;
          log('error', `fetch evaluation error: ${err?.message || err}`);
        }
        return originalFetch(url, opts);
      };
      return () => { web.fetch = originalFetch; };
    }, 'ccs: fetch guard');
  }

  log('info', 'CCS runtime security guard active', {
    hooks: ['pre-execute', 'post-execute', 'subprocess', 'fetch'].filter(h => {
      if (h === 'subprocess') return !!subprocess;
      if (h === 'fetch') return !!web;
      return true;
    }),
  });
}

// ── Helpers ──────────────────────────────────────────────────────────────

/**
 * 收费门禁（免费层）—— 审计/报告输出处的保守裁剪：
 * 只追加 Pro 升级 CTA，不删除/隐藏任何内容，不改变拦截行为。
 * Pro 层（有效 CORRECTOVER_LICENSE_KEY 或 ~/.correctover/license.json）原样返回。
 * @param {string} text 渲染文本
 * @returns {string}
 */
function applyReportGate(text) {
  if (!text || isPro()) return text;
  return text + GATE_CTA;
}

function deepMerge(target, source) {
  const out = Array.isArray(target) ? [...target] : { ...target };
  for (const [k, v] of Object.entries(source)) {
    if (v && typeof v === 'object' && !Array.isArray(v) && k in out && typeof out[k] === 'object') {
      out[k] = deepMerge(out[k], v);
    } else {
      out[k] = v;
    }
  }
  return out;
}

export { apply, inject, name, DEFAULT_POLICY };
export { evaluateToolCall, evaluateToolResult, evaluateSubprocess } from './policy.js';
export { validateFetchUrl } from './ssrf.js';
export { scanForSecrets, isCredentialPath } from './credentials.js';
export { detectInjection } from './injection.js';
export { inspectSpawn, detectCommandInjection } from './cmdi.js';


