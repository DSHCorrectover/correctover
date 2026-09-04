/**
 * Correctover v2.4.6 - AI Agent Runtime Assurance
 * CCS (Conformance Protocol for Agentic Runtime Systems) reference implementation
 */
const crypto = require('crypto');

// CCS Validator (existing)
class ValidationResult {
  constructor(isValid, errors = [], warnings = [], traceId = null) {
    this.isValid = isValid; this.errors = errors; this.warnings = warnings;
    this.traceId = traceId; this.validatedAt = new Date().toISOString();
  }
}
class CCSValidator {
  constructor(options = {}) {
    this.required = new Set(options.required || []);
    this.supported = new Set(options.supported || []);
    this.forbidden = new Set(options.forbidden || []);
    this.enableIntegrity = options.enableIntegrity || false;
    this.integrityKey = options.integrityKey || 'default-key';
  }
  validate(output, traceId = null) {
    const errors = [], warnings = [];
    const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
    for (const f of this.required) { if (!has(output, f)) errors.push(`Missing required field: ${f}`); }
    for (const f of this.forbidden) { if (has(output, f)) errors.push(`Forbidden field present: ${f}`); }
    const allAllowed = new Set([...this.required, ...this.supported]);
    for (const f of Object.keys(output)) { if (!allAllowed.has(f) && !this.forbidden.has(f)) warnings.push(`Unexpected field: ${f}`); }
    if (this.enableIntegrity) {
      const stored = output.integrity_hash || null;
      const computed = this._computeIntegrity(output);
      if (stored === null) warnings.push('No integrity hash in output');
      else if (stored !== computed) errors.push('Integrity hash mismatch');
    }
    return new ValidationResult(errors.length === 0, errors, warnings, traceId);
  }
  _computeIntegrity(output) {
    const filtered = {};
    for (const [k,v] of Object.entries(output)) { if (k !== 'integrity_hash') filtered[k] = v; }
    // 2026-08-19：复用 canonicalJson 规范化（嵌套键序不再影响哈希）
    return crypto.createHmac('sha256', this.integrityKey).update(canonicalJson(filtered)).digest('hex');
  }
  addIntegrityHash(output) {
    const copy = { ...output };
    copy.integrity_hash = this._computeIntegrity(copy);
    return copy;
  }
}

// Guardrail module
const guardrail = require('./guardrail');
const { canonicalJson } = guardrail;

module.exports = {
  CCSValidator, ValidationResult,
  ...guardrail,
};
