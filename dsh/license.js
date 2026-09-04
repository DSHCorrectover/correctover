/**
 * correctover/dsh — 收费门禁 / License gate (freemium hook model, v2.0 HARDENED).
 *
 * Node 移植版，与 Python 参考实现逐字节一致：
 *   D:\Deepseek工作区\war-room\audit\clones\runtime-guard\correctover_agent\license.py
 *
 * COV- 密钥格式：COV-{product}-{hmac_12}{rand_24}{ts_hex}
 *   - hmac_12: HMAC-SHA256(derived_key, product + ":" + ts_hex) 前 12 个 hex 字符
 *   - rand_24: 24 个 hex 随机字符
 *   - ts_hex : unix 时间戳的 hex（365 天过期检查）
 *
 * 密钥派生算法（与 Python 侧 server.py 一致，签名密钥不以明文出现在源码中）：
 *   parts = ["correctover","runtime","guard","signing","key","v2","2026"]
 *   raw = 拼接每个 part 的旋转版本：rotate right by (i % len(part))，
 *         即 p[-shift:] + p[:-shift]，其中 shift = i % len(p)
 *   key = sha256(raw).digest()
 *
 * 模块系统桥：本文件位于 "type": "module" 包（dsh/）内，运行时以 ESM 加载
 * （下方 export 语句生效）；同时保留 CommonJS 兼容桥 —— 当文件被拷贝到 CJS
 * 上下文或经 CJS 打包器处理（module 存在）时，module.exports 生效，与
 * Python 侧引用形态一致。
 *
 * 状态文件：~/.correctover/license.json，带反篡改哈希（_integrity）。
 */

import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { homedir } from 'node:os';
import { join, dirname } from 'node:path';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';

// ── 常量 ────────────────────────────────────────────────────────────────

/** 签名密钥派生组分（与 Python 侧逐字节一致，无明文完整密钥）。 */
const SIGNING_PARTS = ['correctover', 'runtime', 'guard', 'signing', 'key', 'v2', '2026'];

/** 默认产品标识（DSH 插件主产品，与 server.py PRODUCTS["correctover-dsh"] 一致）。
 *  2026-08-19 P0 修复：原 correctover-runtime-guard 是 runtime-guard 的产品；
 *  本文件是 DSH 插件（correctover 主包），必须用 correctover-dsh，
 *  否则 checkout 签发的密钥验证不过 → 用户付费却永远免费。 */
const DEFAULT_PRODUCT = 'correctover-dsh';

/** 状态文件路径：~/.correctover/license.json。 */
const STATE_FILE = join(homedir(), '.correctover', 'license.json');

/** 状态完整性哈希前缀（与 Python _state_integrity_hash 一致）。 */
const STATE_INTEGRITY_PREFIX = 'correctover-state-integrity-v2:';

const KEY_VERSION = 'v2';
const LICENSE_DAYS = 365 * 86400; // 过期窗口：365 天
const FREE_FIX_PREVIEW = 2;       // 免费层可见的修复建议条数
const COV_TAIL_MIN = 44;          // 12 hmac + 24 rand + 8 ts_hex

/**
 * 免费层门禁 CTA（任务规格原文，policy.js 拦截说明追加用）。
 * 首/尾换行与规格反引号块一致。
 */
export const GATE_CTA = '\n🔒 修复建议已锁定。升级 Pro 解锁全部修复 + 审计报告：https://correctover.com/checkout\n';

// ── 密钥派生（与 Python _derive_signing_key 逐字节一致）─────────────────

/**
 * 派生 COV- 密钥签名密钥。
 * Python 对照：
 *   raw = b""
 *   for i, p in enumerate(parts):
 *       shift = i % max(len(p), 1)
 *       rotated = p[-shift:] + p[:-shift] if shift else p
 *       raw += rotated
 *   return hashlib.sha256(raw).digest()
 * @returns {Buffer} 32 字节签名密钥
 */
export function _deriveSigningKey() {
  let raw = Buffer.alloc(0);
  for (let i = 0; i < SIGNING_PARTS.length; i++) {
    const p = Buffer.from(SIGNING_PARTS[i], 'utf8');
    const shift = i % Math.max(p.length, 1);
    let rotated;
    if (shift === 0) {
      rotated = p;
    } else {
      // rotate right by shift: p[-shift:] + p[:-shift]
      rotated = Buffer.concat([p.subarray(p.length - shift), p.subarray(0, p.length - shift)]);
    }
    raw = Buffer.concat([raw, rotated]);
  }
  return createHash('sha256').update(raw).digest();
}

const SIGNING_KEY = _deriveSigningKey();

// ── 状态文件（带反篡改哈希）─────────────────────────────────────────────

/**
 * Python json.dumps(obj, sort_keys=True) 的等价实现（默认分隔符 ', ' ': '）。
 * 用于 _integrity 哈希，保证与 Python 侧对同一状态文件的计算一致。
 * 注：JS 无 int/float 区分，整数值浮点（如恰逢整秒的时间戳）是已知边界，
 * 模块自身写入/校验自洽；跨语言共享时由任一侧写入后即锁定该形态。
 */
function sortedJsonDumps(value) {
  function escapeString(s) {
    let out = '';
    for (const ch of s) {
      const code = ch.codePointAt(0);
      if (code < 0x20 || code === 0x7f) {
        out += `\\u${code.toString(16).padStart(4, '0')}`;
      } else if (code > 0x7e) {
        if (code > 0xffff) {
          const c = code - 0x10000;
          const hi = 0xd800 + (c >> 10);
          const lo = 0xdc00 + (c & 0x3ff);
          out += `\\u${hi.toString(16).padStart(4, '0')}\\u${lo.toString(16).padStart(4, '0')}`;
        } else {
          out += `\\u${code.toString(16).padStart(4, '0')}`;
        }
      } else if (ch === '"') {
        out += '\\"';
      } else if (ch === '\\') {
        out += '\\\\';
      } else {
        out += ch;
      }
    }
    return out;
  }
  function stringify(v) {
    if (v === null || v === undefined) return 'null';
    if (typeof v === 'number') {
      if (!Number.isFinite(v)) return 'null';
      return String(v);
    }
    if (typeof v === 'boolean') return v ? 'true' : 'false';
    if (typeof v === 'string') return `"${escapeString(v)}"`;
    if (Array.isArray(v)) return `[${v.map(stringify).join(', ')}]`;
    if (typeof v === 'object') {
      const keys = Object.keys(v).sort();
      return `{${keys.map((k) => `"${escapeString(k)}": ${stringify(v[k])}`).join(', ')}}`;
    }
    return 'null';
  }
  return stringify(value);
}

/**
 * 计算状态文件完整性哈希（与 Python _state_integrity_hash 一致）：
 * sha256("correctover-state-integrity-v2:" + content)[:16]
 */
function stateIntegrityHash(content) {
  return createHash('sha256')
    .update(Buffer.from(STATE_INTEGRITY_PREFIX + content, 'utf8'))
    .digest('hex')
    .slice(0, 16);
}

function defaultState() {
  return {
    products: {},
    license_key: null,
    installed_at: Date.now() / 1000,
    scan_history: [],
    key_version: KEY_VERSION,
  };
}

/**
 * 读取状态文件（每次调用实时读取，带反篡改校验）。
 * 长驻进程（DSH 插件）场景下，用户通过 CLI 写入密钥/文件被篡改时，
 * checkLicense 立即可见，无需重启。读取是只读操作，无副作用。
 */
function loadState() {
  try {
    if (existsSync(STATE_FILE)) {
      const data = JSON.parse(readFileSync(STATE_FILE, 'utf8'));
      const storedHash = data._integrity;
      delete data._integrity;
      if (storedHash) {
        const expected = stateIntegrityHash(sortedJsonDumps(data));
        if (storedHash !== expected) return defaultState(); // 反篡改校验失败 → 回退默认
      }
      return data;
    }
  } catch {
    /* 损坏/不可读 → 默认状态 */
  }
  return defaultState();
}

// ── 密钥验证（与 Python _verify_cov_key 一致）───────────────────────────

/**
 * 验证 COV- 密钥：HMAC-SHA256 签名 + 365 天过期 + 产品匹配。
 * @param {string} key  COV-{product}-{hmac12}{rand24}{ts_hex}
 * @param {string} [product] 期望产品；缺省用 DEFAULT_PRODUCT
 */
function verifyCovKey(key, product) {
  const parts = key.split('-');
  if (parts.length < 3 || parts[0] !== 'COV') return false;

  const tail = parts[parts.length - 1];
  if (tail.length < COV_TAIL_MIN) return false;

  const hmacSegment = tail.slice(0, 12);
  const tsHex = tail.slice(-8);

  const ts = parseInt(tsHex, 16);
  if (!Number.isFinite(ts) || ts <= 0) return false;

  // 过期检查：365 天
  if (Date.now() / 1000 - ts > LICENSE_DAYS) return false;

  const productCode = parts.slice(1, -1).join('-');
  if (product && productCode !== product) return false;

  const message = `${productCode}:${tsHex}`;
  const expected = createHmac('sha256', SIGNING_KEY).update(message, 'utf8').digest('hex').slice(0, 12);

  const a = Buffer.from(hmacSegment, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b); // 恒定时间比较
}

/**
 * 验证许可证密钥（对外 API）。
 * 支持 COV- 格式（任务规格）；CV-/NB- 等其他格式不在本次范围，一律拒绝。
 * @param {string} key
 * @param {string} [product]
 * @returns {boolean}
 */
export function verifyLicenseKey(key, product = DEFAULT_PRODUCT) {
  if (!key || typeof key !== 'string' || key.length < 20) return false;
  if (key.startsWith('COV-')) return verifyCovKey(key, product);
  return false;
}

// ── 许可状态 ────────────────────────────────────────────────────────────

/**
 * 检查许可状态，返回 tier 与能力（与 Python check_license 结构一致）。
 * 优先级：环境变量 CORRECTOVER_LICENSE_KEY 亦被接受。
 * @param {string} [product]
 */
export function checkLicense(product = DEFAULT_PRODUCT) {
  const licenseKey =
    loadState().license_key || process.env.CORRECTOVER_LICENSE_KEY || null;

  if (licenseKey && verifyLicenseKey(licenseKey, product)) {
    return {
      tier: 'pro',
      can_scan: true,
      can_fix: true,
      can_report: true,
      can_heal: true,
      can_history: true,
      fix_preview: Infinity,
      license_key: licenseKey.length > 8 ? `${licenseKey.slice(0, 8)}...` : null,
    };
  }

  return {
    tier: 'free',
    can_scan: true,
    can_fix: false,
    can_report: false,
    can_heal: false,
    can_history: false,
    fix_preview: FREE_FIX_PREVIEW,
    license_key: null,
  };
}

/** 快速检查：是否有效 Pro 许可。 */
export function isPro(product) {
  return checkLicense(product).tier === 'pro';
}

// ── 设置密钥 ────────────────────────────────────────────────────────────

/**
 * 设置并验证许可证密钥；有效则写入 ~/.correctover/license.json（带反篡改哈希）。
 * @param {string} key
 * @param {string} [product]
 * @returns {boolean} 是否有效并已保存
 */
export function setLicenseKey(key, product = DEFAULT_PRODUCT) {
  if (!verifyLicenseKey(key, product)) return false;
  const state = loadState();
  state.license_key = key;
  state.activated_at = Date.now() / 1000;
  const copy = { ...state };
  delete copy._integrity;
  state._integrity = stateIntegrityHash(sortedJsonDumps(copy));
  try {
    mkdirSync(dirname(STATE_FILE), { recursive: true });
    writeFileSync(STATE_FILE, JSON.stringify(state, null, 2), 'utf8');
  } catch {
    /* 持久化失败不致命 */
  }
  return true;
}

// ── 修复建议 CTA ────────────────────────────────────────────────────────

/**
 * 生成修复建议门禁 CTA（免费层显示，Pro 层返回空串）。
 * @param {number} hiddenCount 被锁定的修复建议条数
 * @param {number} totalCount  总风险/修复建议条数
 * @returns {string}
 */
export function getFixCta(hiddenCount, totalCount) {
  if (isPro()) return '';
  const hidden = Number(hiddenCount) || 0;
  const total = Number(totalCount) || 0;
  const shown = Math.max(total - hidden, 0);
  const bar = '━'.repeat(55);
  const lines = [
    `\n${bar}`,
    `🔒 ${hidden} 条修复建议已锁定。升级 Pro 解锁全部修复 + 审计报告：https://correctover.com/checkout`,
  ];
  if (total > 0) {
    lines.push(`   共发现 ${total} 个风险，免费层仅可见 ${shown} 条修复建议。`);
  }
  lines.push(
    '',
    '🛡️ 升级 Pro 解锁：',
    `   ✓ 全部修复建议（${total} 项）`,
    '   ✓ 自动修复（84.1% 问题自动解决）',
    '   ✓ HTML/PDF 审计报告',
    '   ✓ 扫描历史与追踪',
    bar,
    '   → https://correctover.com/checkout',
    '   → export CORRECTOVER_LICENSE_KEY=<your-key>',
    bar,
  );
  return lines.join('\n');
}

// ── 模块系统桥 ──────────────────────────────────────────────────────────

const api = { checkLicense, isPro, getFixCta, setLicenseKey, verifyLicenseKey };

// CommonJS 兼容桥：本文件在 "type": "module" 包内以 ESM 加载时，
// typeof module === 'undefined'，此分支不执行；被拷贝到 CJS 上下文或经
// CJS 打包器转换（module 存在）时，module.exports 生效。
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { checkLicense, isPro, getFixCta, setLicenseKey, verifyLicenseKey };
}

export default api;
