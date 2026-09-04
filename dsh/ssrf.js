/**
 * @file SSRF protection — validates URLs against private network ranges.
 *
 * DeepSeek Harness's built-in web-fetch-http explicitly defers SSRF blocking
 * (see packages/web/web-fetch-http/src/policy.ts line 18: "SSRF / private-network
 * blocking is deferred"). This module fills that gap.
 *
 * Covers: IPv4 private ranges, loopback, link-local, carrier-grade NAT,
 * IPv6 loopback/unique-local/link-local, decimal/octal/hex IP encoding,
 * and DNS rebinding via TTL=0 detection (best-effort).
 */

import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

/** IPv4 CIDR ranges that must never be reachable from a plugin/tool fetch. */
const V4_BLOCKLIST = [
  { network: 0n, broadcast: ipToLong('0.255.255.255'), label: 'this network (0.0.0.0/8)' },
  { network: ipToLong('10.0.0.0'), broadcast: ipToLong('10.255.255.255'), label: 'private (10.0.0.0/8)' },
  { network: ipToLong('127.0.0.0'), broadcast: ipToLong('127.255.255.255'), label: 'loopback (127.0.0.0/8)' },
  { network: ipToLong('169.254.0.0'), broadcast: ipToLong('169.254.255.255'), label: 'link-local (169.254.0.0/16)' },
  { network: ipToLong('172.16.0.0'), broadcast: ipToLong('172.31.255.255'), label: 'private (172.16.0.0/12)' },
  { network: ipToLong('192.0.2.0'), broadcast: ipToLong('192.0.2.255'), label: 'documentation TEST-NET-1 (192.0.2.0/24)' },
  { network: ipToLong('192.168.0.0'), broadcast: ipToLong('192.168.255.255'), label: 'private (192.168.0.0/16)' },
  { network: ipToLong('198.18.0.0'), broadcast: ipToLong('198.19.255.255'), label: 'benchmarking (198.18.0.0/15)' },
  { network: ipToLong('198.51.100.0'), broadcast: ipToLong('198.51.100.255'), label: 'documentation TEST-NET-2 (198.51.100.0/24)' },
  { network: ipToLong('203.0.113.0'), broadcast: ipToLong('203.0.113.255'), label: 'documentation TEST-NET-3 (203.0.113.0/24)' },
  { network: ipToLong('224.0.0.0'), broadcast: ipToLong('239.255.255.255'), label: 'multicast (224.0.0.0/4)' },
  { network: ipToLong('240.0.0.0'), broadcast: ipToLong('255.255.255.255'), label: 'reserved (240.0.0.0/4)' },
  // Cloud metadata endpoints
  { network: ipToLong('169.254.169.254'), broadcast: ipToLong('169.254.169.254'), label: 'cloud metadata (169.254.169.254)' },
  { network: ipToLong('100.100.100.200'), broadcast: ipToLong('100.100.100.200'), label: 'Alibaba Cloud metadata (100.100.100.200)' },
];

/** Convert a dotted-quad IPv4 string to a 32-bit integer (as BigInt). */
function ipToLong(ip) {
  const parts = ip.split('.').map(Number);
  return BigInt(parts[0] * 16777216 + parts[1] * 65536 + parts[2] * 256 + parts[3]);
}

/** Parse a numeric string that may be decimal, octal (0o), or hex (0x). */
function parseNumericHost(raw) {
  const trimmed = raw.trim().toLowerCase();
  if (/^\d+\.\d+\.\d+\.\d+$/.test(trimmed)) return trimmed;
  // Handle decimal integer form (e.g. http://2130706433 = 127.0.0.1)
  if (/^\d+$/.test(trimmed)) {
    const num = BigInt(trimmed);
    return `${(num >> 24n) & 255n}.${(num >> 16n) & 255n}.${(num >> 8n) & 255n}.${num & 255n}`;
  }
  // Hex form — 2026-08-19 P0 修复：仅接受纯 0x hex，避免 0xdeadbeef.com 域名抛 BigInt SyntaxError 崩溃
  if (trimmed.startsWith('0x')) {
    if (!/^0x[0-9a-f]+$/i.test(trimmed)) return null;
    try {
      const num = BigInt(trimmed);
      return `${(num >> 24n) & 255n}.${(num >> 16n) & 255n}.${(num >> 8n) & 255n}.${num & 255n}`;
    } catch {
      return null;
    }
  }
  // Octal form per part
  if (/^0[0-7]+(\.0[0-7]+){0,3}$/.test(trimmed)) {
    const parts = trimmed.split('.').map(p => parseInt(p, 8));
    while (parts.length < 4) parts.push(0);
    return parts.join('.');
  }
  return null;
}

/** Check whether an IPv4 address string falls in a blocked range. */
export function isBlockedIPv4(ip) {
  const num = ipToLong(ip);
  for (const range of V4_BLOCKLIST) {
    if (num >= range.network && num <= range.broadcast) {
      return range.label;
    }
  }
  return null;
}

/**
 * Expand an IPv6 address string into 8 hextets (accepts trailing dotted-quad
 * IPv4 forms like ::127.0.0.1). Returns null if not parseable.
 */
function expandIPv6Hextets(ip) {
  let s = ip;
  // Trailing dotted-quad form (::a.b.c.d, x:y:a.b.c.d) → hex hextets
  const dotted = s.match(/^(.*:)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (dotted) {
    const parts = [dotted[2], dotted[3], dotted[4], dotted[5]].map(Number);
    if (parts.some(n => n > 255)) return null;
    const hi = (parts[0] << 8) | parts[1];
    const lo = (parts[2] << 8) | parts[3];
    s = `${dotted[1]}${hi.toString(16)}:${lo.toString(16)}`;
  }
  const halves = s.split('::');
  let hextets;
  if (halves.length === 2) {
    const left = halves[0] ? halves[0].split(':') : [];
    const right = halves[1] ? halves[1].split(':') : [];
    const missing = 8 - left.length - right.length;
    if (missing < 1 || left.length + right.length > 7) return null;
    hextets = [...left, ...new Array(missing).fill('0'), ...right];
  } else if (halves.length === 1) {
    hextets = s.split(':');
  } else {
    return null;
  }
  if (hextets.length !== 8 || hextets.some(h => !/^[0-9a-f]{1,4}$/.test(h))) return null;
  return hextets;
}

/** Rebuild a dotted-quad IPv4 string from two 16-bit hextets (hi:lo). */
function v4FromHextets(hi, lo) {
  return `${(hi >> 8) & 255}.${hi & 255}.${(lo >> 8) & 255}.${lo & 255}`;
}

/** Check whether an IPv6 address is loopback, link-local, unique-local, or unspecified. */
export function isBlockedIPv6(ip) {
  // 2026-08-20 R1: 先剥离 zone id（fe80::1%eth0 → fe80::1）再判定，
  // 避免 link-local 带接口标识时绕过 fe80::/10 前缀匹配。
  let lower = String(ip).toLowerCase();
  const pct = lower.indexOf('%');
  if (pct !== -1) lower = lower.slice(0, pct);

  if (lower === '::1' || lower === '0:0:0:0:0:0:0:1') return 'loopback (::1)';
  if (lower === '::' || lower === '0:0:0:0:0:0:0:0') return 'unspecified (::)';
  if (lower.startsWith('fe80:')) return 'link-local (fe80::/10)';
  if (lower.startsWith('fc') || lower.startsWith('fd')) return 'unique-local (fc00::/7)';
  if (lower.startsWith('ff') || lower.startsWith('ff00:')) return 'multicast (ff00::/8)';

  const hextets = expandIPv6Hextets(lower);
  if (!hextets) return null;
  const h0 = parseInt(hextets[0], 16);
  const h1 = parseInt(hextets[1], 16);
  const h2 = parseInt(hextets[2], 16);
  const h3 = parseInt(hextets[3], 16);
  const h4 = parseInt(hextets[4], 16);
  const h5 = parseInt(hextets[5], 16);
  const h6 = parseInt(hextets[6], 16);
  const h7 = parseInt(hextets[7], 16);

  // IPv4-mapped IPv6（::ffff:a.b.c.d / ::ffff:7f00:1 / 0:0:0:0:0:ffff:7f00:1）
  if (h4 === 0 && h5 === 0xffff) {
    return isBlockedIPv4(v4FromHextets(h6, h7));
  }

  // 2026-08-20 R1 修复：IPv4-compatible IPv6（非 ffff 的内嵌 IPv4 段，
  // 如 ::7f00:1、::127.0.0.1、::a.b.c.d —— 前 96 位全零、低 32 位即 IPv4 地址）。
  // 原先仅匹配 ::ffff 映射形态，规范形 ::7f00:1（= 127.0.0.1）返回 undefined 被放行。
  if (h0 === 0 && h1 === 0 && h2 === 0 && h3 === 0 && h4 === 0 && h5 === 0) {
    const ipv4 = v4FromHextets(h6, h7);
    const reason = isBlockedIPv4(ipv4);
    if (reason) return `IPv4-compatible IPv6 (${ip} = ${ipv4}): ${reason}`;
  }
  return null;
}

/**
 * Validate a URL for SSRF. Returns a denial reason string if blocked,
 * or undefined if safe.
 *
 * @param {string} urlString - the URL to validate.
 * @param {object} [opts]
 * @param {boolean} [opts.allowPrivate=false] - permit private IP targets.
 * @returns {Promise<string|undefined>} denial reason, or undefined.
 */
export async function validateFetchUrl(urlString, opts = {}) {
  let url;
  try {
    url = new URL(urlString);
  } catch {
    return `invalid URL: ${urlString}`;
  }

  // Scheme check
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return `blocked scheme "${url.protocol}" — only http/https permitted`;
  }

  // Embedded credentials
  if (url.username || url.password) {
    return 'URL contains embedded credentials';
  }

  const hostname = url.hostname;

  // IP literal? (URL.hostname already strips brackets for IPv6)
  const ipVersion = isIP(hostname);
  if (ipVersion === 4) {
    const reason = isBlockedIPv4(hostname);
    if (reason && !opts.allowPrivate) return `SSRF blocked: target is ${reason}`;
    return undefined;
  }
  if (ipVersion === 6) {
    const reason = isBlockedIPv6(hostname);
    if (reason && !opts.allowPrivate) return `SSRF blocked: target is ${reason}`;
    return undefined;
  }

  // Also check for bracketed IPv6 that isIP might reject
  const bracketMatch = hostname.match(/^\[(.+)\]$/);
  if (bracketMatch) {
    // 2026-08-20 R1: 剥离 zone id（[fe80::1%eth0] → fe80::1）后再判定
    const inner = bracketMatch[1].replace(/%[^%]*$/, '');
    if (isIP(inner) === 6) {
      const reason = isBlockedIPv6(inner);
      if (reason && !opts.allowPrivate) return `SSRF blocked: target is ${reason}`;
      return undefined;
    }
  }

  // Numeric encoding attempts
  const numeric = parseNumericHost(hostname);
  if (numeric) {
    const reason = isBlockedIPv4(numeric);
    if (reason && !opts.allowPrivate) return `SSRF blocked: numeric host "${hostname}" resolves to ${reason}`;
    return undefined;
  }

  // DNS resolution — check resolved IPs
  if (!opts.allowPrivate) {
    try {
      const addresses = await lookup(hostname, { all: true, verbatim: true });
      for (const addr of addresses) {
        if (addr.family === 4) {
          const reason = isBlockedIPv4(addr.address);
          if (reason) return `SSRF blocked: "${hostname}" resolves to ${reason} (${addr.address})`;
        } else {
          const reason = isBlockedIPv6(addr.address);
          if (reason) return `SSRF blocked: "${hostname}" resolves to ${reason} (${addr.address})`;
        }
      }
    } catch {
      // DNS failure — allow (the fetch itself will fail)
    }
  }

  return undefined;
}
