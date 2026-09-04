/**
 * correctover/guardrail - Framework-agnostic runtime security guardrail system
 * CCS reference implementation
 */
const crypto = require('crypto');

function canonicalJson(obj, seen = new WeakSet()) {
  if (obj === null || obj === undefined) return 'null';
  if (typeof obj !== 'object') return JSON.stringify(obj);
  if (seen.has(obj)) return '"__circular__"';
  seen.add(obj);
  if (Array.isArray(obj)) return '[' + obj.map(v => canonicalJson(v, seen)).join(',') + ']';
  const sorted = Object.keys(obj).sort();
  return '{' + sorted.map(k => JSON.stringify(k) + ':' + canonicalJson(obj[k], seen)).join(',') + '}';
}

function computeDecisionId(claims, expiresAt = null) {
  const preimage = { ...claims };
  if (expiresAt !== null) preimage._expires_at = expiresAt;
  return crypto.createHash('sha256').update(canonicalJson(preimage)).digest('hex');
}

class GuardrailDecisionV1 {
  constructor(decisionId, authorized, claims, expiresAt = null) {
    this.decisionId = decisionId;
    this.authorized = authorized;
    this.claims = claims;
    this.expiresAt = expiresAt;
  }
  isExpired() { return this.expiresAt !== null && Date.now()/1000 > this.expiresAt; }
  verifyIntegrity() { return this.decisionId === computeDecisionId(this.claims, this.expiresAt); }
  toDict() { return { decision_id: this.decisionId, authorized: this.authorized, claims: this.claims, expires_at: this.expiresAt }; }
}

class ActionEnvelopeV1 {
  constructor(decisionId, toolResultDigest, executedAt, durationMs) {
    this.decisionId = decisionId;
    this.toolResultDigest = toolResultDigest;
    this.executedAt = executedAt;
    this.durationMs = durationMs;
  }
  static digestResult(result) {
    const raw = result !== null && result !== undefined ? canonicalJson(result) : '';
    return crypto.createHash('sha256').update(raw).digest('hex');
  }
  toDict() { return { decision_id: this.decisionId, tool_result_digest: this.toolResultDigest, executed_at: this.executedAt, duration_ms: this.durationMs }; }
}

class ToolCallContext {
  constructor(toolName, toolArgs = {}, agentId = 'unknown', metadata = {}) {
    this.toolName = toolName; this.toolArgs = toolArgs; this.agentId = agentId; this.metadata = metadata;
  }
}

class GuardrailProvider {
  authorize(context) { throw new Error('Must implement authorize()'); }
}

class AllowAllGuardrailProvider extends GuardrailProvider {
  authorize(context) {
    const claims = { provider: 'AllowAllGuardrailProvider', tool_name: context.toolName, agent_id: context.agentId };
    return new GuardrailDecisionV1(computeDecisionId(claims), true, claims);
  }
}

class DenyAllGuardrailProvider extends GuardrailProvider {
  authorize(context) {
    const claims = { provider: 'DenyAllGuardrailProvider', tool_name: context.toolName, reason: 'deny-all safety lock active' };
    return new GuardrailDecisionV1(computeDecisionId(claims), false, claims);
  }
}

class ToolListGuardrailProvider extends GuardrailProvider {
  constructor(opts = {}) { this.allowedTools = opts.allowedTools || null; this.deniedTools = new Set(opts.deniedTools || []); }
  authorize(context) {
    const claims = { provider: 'ToolListGuardrailProvider', tool_name: context.toolName, agent_id: context.agentId };
    if (this.allowedTools !== null) {
      const authorized = this.allowedTools.has(context.toolName);
      claims.policy = 'allowlist'; claims.allowed_tools = [...this.allowedTools].sort();
      return new GuardrailDecisionV1(computeDecisionId(claims), authorized, claims);
    }
    if (this.deniedTools.has(context.toolName)) {
      claims.policy = 'denylist'; claims.denied_tools = [...this.deniedTools].sort();
      return new GuardrailDecisionV1(computeDecisionId(claims), false, claims);
    }
    claims.policy = 'default-allow';
    return new GuardrailDecisionV1(computeDecisionId(claims), true, claims);
  }
}

const CKG_PREDICATES = new Set(['tool_name_in', 'tool_name_not_in', 'agent_id_in', 'param_matches', 'has_param', 'no_param']);

class CKGGuardrailProvider extends GuardrailProvider {
  constructor() { super(); this._constraints = []; }
  addConstraint(predicate, opts) {
    if (!CKG_PREDICATES.has(predicate)) throw new Error(`CKGGuardrailProvider: unknown predicate "${predicate}"`);
    this._constraints.push({ predicate, ...opts });
    return this;
  }
  authorize(context) {
    const claims = { provider: 'CKGGuardrailProvider', tool_name: context.toolName, agent_id: context.agentId };
    let satisfied = true, failedPredicate = null;
    for (const c of this._constraints) {
      switch (c.predicate) {
        case 'tool_name_in': if (!c.tools?.has(context.toolName)) { satisfied=false; failedPredicate=c.predicate; } break;
        case 'tool_name_not_in': if (c.tools?.has(context.toolName)) { satisfied=false; failedPredicate=c.predicate; } break;
        case 'agent_id_in': if (!c.agents?.has(context.agentId)) { satisfied=false; failedPredicate=c.predicate; } break;
        case 'param_matches': if (context.toolArgs[c.name] !== c.value) { satisfied=false; failedPredicate=c.predicate; } break;
        case 'has_param': if (!Object.prototype.hasOwnProperty.call(context.toolArgs, c.name)) { satisfied=false; failedPredicate=c.predicate; } break;
        case 'no_param': if (Object.prototype.hasOwnProperty.call(context.toolArgs, c.name)) { satisfied=false; failedPredicate=c.predicate; } break;
      }
    }
    if (!satisfied) claims.failed_predicate = failedPredicate;
    claims.constraints_count = this._constraints.length;
    return new GuardrailDecisionV1(computeDecisionId(claims), satisfied, claims);
  }
}

class EnvProtectionProvider extends GuardrailProvider {
  constructor(extraPatterns = []) {
    super(); this.extraPatterns = extraPatterns;
    this.DANGEROUS = {
      env_vars: ['API_KEY','API_SECRET','SECRET_KEY','PRIVATE_KEY','ACCESS_TOKEN','AUTH_TOKEN','DB_PASSWORD','DATABASE_URL','AWS_SECRET','AWS_ACCESS_KEY','GITHUB_TOKEN','OPENAI_API_KEY','ANTHROPIC_API_KEY'],
      // 2026-08-19 改造：移除 ${ / env / echo $ 泛模式（模板字符串/普通文档被误伤），改具体命令形态
      env_commands: ['os.environ', 'process.env', 'getenv(', 'printenv ', 'env -i', 'env |', 'env >', 'set >', 'echo $HOME', 'echo $PATH', 'echo $SECRET', 'export SECRET', 'unset '],
      file_paths: ['.env','.env.local','.env.production','credentials.json','service-account.json'],
    };
  }
  authorize(context) {
    const claims = { provider: 'EnvProtectionProvider', tool_name: context.toolName, agent_id: context.agentId };
    const argsStr = canonicalJson(context.toolArgs).toLowerCase();
    const matched = [];
    for (const [cat, pats] of Object.entries(this.DANGEROUS)) {
      for (const p of pats) { if (argsStr.includes(p.toLowerCase())) matched.push(`${cat}:${p}`); }
    }
    for (const p of this.extraPatterns) { if (argsStr.includes(p.toLowerCase())) matched.push(`custom:${p}`); }
    if (matched.length > 0) {
      claims.matched_patterns = matched; claims.reason = 'Environment variable access attempt detected';
      return new GuardrailDecisionV1(computeDecisionId(claims), false, claims);
    }
    claims.reason = 'No environment variable access detected';
    return new GuardrailDecisionV1(computeDecisionId(claims), true, claims);
  }
}

class CompositeGuardrailProvider extends GuardrailProvider {
  constructor(providers, mode = 'AND') {
    super();
    if (mode !== 'AND' && mode !== 'OR') throw new Error(`mode must be AND or OR, got ${mode}`);
    this.providers = providers; this.mode = mode;
  }
  authorize(context) {
    const results = this.providers.map(p => p.authorize(context));
    const authorized = this.mode === 'AND' ? results.every(d => d.authorized) : results.some(d => d.authorized);
    const claims = {
      provider: 'CompositeGuardrailProvider', mode: this.mode,
      tool_name: context.toolName, agent_id: context.agentId,
      sub_decisions: results.map(d => d.decisionId),
      sub_providers: results.map(d => d.claims.provider || 'unknown'),
    };
    return new GuardrailDecisionV1(computeDecisionId(claims), authorized, claims);
  }
}

class AuditTrail {
  constructor() { this._decisions = {}; this._envelopes = {}; }
  recordDecision(d) { this._decisions[d.decisionId] = d; }
  recordEnvelope(e) { this._envelopes[e.decisionId] = e; }
  getDecision(id) { return this._decisions[id]; }
  getEnvelope(id) { return this._envelopes[id]; }
  getAllDecisions() { return Object.values(this._decisions); }
  getAllEnvelopes() { return Object.values(this._envelopes); }
  clear() { this._decisions = {}; this._envelopes = {}; }
  get decisionCount() { return Object.keys(this._decisions).length; }
  get envelopeCount() { return Object.keys(this._envelopes).length; }
  verifyAll() { return Object.values(this._decisions).every(d => d.verifyIntegrity()); }
  export() { return { decisions: Object.values(this._decisions).map(d=>d.toDict()), envelopes: Object.values(this._envelopes).map(e=>e.toDict()), verified: this.verifyAll() }; }
}

class GuardrailContext {
  constructor(provider, trail = null, onDeny = null) {
    this.provider = provider; this.trail = trail || new AuditTrail(); this.onDeny = onDeny;
  }
  authorize(context) {
    const decision = this.provider.authorize(context);
    this.trail.recordDecision(decision);
    if (!decision.authorized && this.onDeny) this.onDeny(decision);
    return decision;
  }
  afterToolCall(decision, result, startTime) {
    // startTime 单位为秒；误传毫秒(>1e12)自动换算（2026-08-19 修复）
    let startSec = startTime;
    if (startTime > 1e12) startSec = startTime / 1000;
    const durationMs = (Date.now()/1000 - startSec) * 1000;
    const envelope = new ActionEnvelopeV1(decision.decisionId, ActionEnvelopeV1.digestResult(result), Date.now()/1000, durationMs);
    this.trail.recordEnvelope(envelope);
    return envelope;
  }
}

function makeGuardrailHook(provider, trail = null, onDeny = null) {
  const ctx = new GuardrailContext(provider, trail, onDeny);
  const hook = function(toolName, toolArgs = {}, agentId = 'unknown', ...rest) {
    const context = new ToolCallContext(toolName, toolArgs, agentId);
    const decision = ctx.authorize(context);
    if (!decision.authorized) return false;
    return null;
  };
  hook._guardrailContext = ctx;
  return hook;
}

function detectMissingGuardrail(agents) {
  const findings = [];
  for (const agent of agents) {
    const name = agent.role || agent.name || agent.id || 'unknown';
    const hasHooks = agent._beforeToolCallHooks || agent.beforeToolCall || agent._guardrails || agent.guardrailProvider;
    if (!hasHooks) {
      findings.push({ severity:'CRITICAL', pattern:'AS-GUARDRAIL-MISS-001', agent:name, message:`Agent '${name}' has no registered GuardrailProvider`, remediation:'Register a GuardrailProvider via makeGuardrailHook()', ccs_ref:'https://correctover.com/ccs' });
    }
  }
  return findings;
}

class MCPSecurityValidator {
  static DANGEROUS_COMMANDS = ['rm -rf','curl | sh','wget | bash','eval(','exec(','os.system','subprocess.call'];
  static SENSITIVE_ENV_PATTERNS = ['API_KEY','SECRET','TOKEN','PASSWORD','PRIVATE_KEY','CREDENTIALS','AUTH'];

  static validateToolDefinition(toolDef) {
    const issues = [];
    const impl = String(toolDef.implementation || '');
    for (const cmd of MCPSecurityValidator.DANGEROUS_COMMANDS) {
      // 2026-08-19：删除 CVE 错映射（CVE-2026-42271 实为 LiteLLM 漏洞）
      if (impl.includes(cmd)) issues.push({ severity:'CRITICAL', type:'command_injection', pattern:cmd });
    }
    const envSection = JSON.stringify(toolDef.env || {});
    for (const pattern of MCPSecurityValidator.SENSITIVE_ENV_PATTERNS) {
      // 2026-08-19：删除 CVE 错映射（CVE-2026-12957 实为 Amazon Q 扩展漏洞）
      if (envSection.toUpperCase().includes(pattern)) issues.push({ severity:'HIGH', type:'env_exposure', pattern });
    }
    return { safe: issues.length === 0, issues, tool_name: toolDef.name || 'unknown' };
  }

  static validateMcpConfig(config) {
    const issues = [];
    const transport = config.transport || 'stdio';
    if (transport === 'stdio' && config.env && Object.keys(config.env).length > 0) {
      issues.push({ severity:'HIGH', type:'stdio_env_exposure', message:'stdio transport with env variables - risk of leakage', remediation:'Use env_isolation or switch to sse/http transport' });
    }
    for (const tool of (config.tools || [])) {
      issues.push(...MCPSecurityValidator.validateToolDefinition(tool).issues);
    }
    return { safe: issues.length === 0, issues, config_name: config.name || 'unknown' };
  }
}

module.exports = {
  canonicalJson, computeDecisionId,
  GuardrailDecisionV1, ActionEnvelopeV1, ToolCallContext,
  GuardrailProvider, AllowAllGuardrailProvider, DenyAllGuardrailProvider,
  ToolListGuardrailProvider, CKGGuardrailProvider, EnvProtectionProvider,
  CompositeGuardrailProvider, AuditTrail, GuardrailContext,
  makeGuardrailHook, detectMissingGuardrail, MCPSecurityValidator,
};
