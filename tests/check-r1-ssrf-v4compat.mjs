#!/usr/bin/env node
/**
 * R1 验证：IPv4-compatible IPv6（非 ffff 内嵌 IPv4 段）SSRF 绕过修复
 *  - 攻击：::7f00:1 (=127.0.0.1)、::a00:1 (=10.0.0.1)、zone-id link-local 必须拦截
 *  - 良性：公网 IPv4-compatible（::8.8.8.8）、普通公网 URL 必须放行
 * 运行: node tests/check-r1-ssrf-v4compat.mjs
 */
import { validateFetchUrl, isBlockedIPv6 } from '../dsh/ssrf.js';

let failed = 0;
const t = (id, name, cond, extra = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'} ${id} ${name}${extra ? ' | ' + extra : ''}`);
  if (!cond) failed++;
};

// —— 攻击拦截（修复前这些全部 ALLOW）——
const attacks = [
  ['http://[::7f00:1]/', 'IPv4-compat ::7f00:1 (=127.0.0.1)'],
  ['http://[::127.0.0.1]/', 'IPv4-compat ::127.0.0.1 dotted form'],
  ['http://[::a00:1]/', 'IPv4-compat ::a00:1 (=10.0.0.1)'],
  ['http://[::ffff:7f00:1]/', 'IPv4-mapped hex (回归，仍拦截)'],
];
for (const [u, n] of attacks) {
  const r = await validateFetchUrl(u);
  t('R1a', n, !!r, r || 'ALLOW');
}

// zone id：直接调用 isBlockedIPv6（URL 解析器在 Node 22 拒绝 zone-id 主机名，防御层校验）
t('R1b', 'isBlockedIPv6(fe80::1%eth0) 剥离 zone id 判 link-local', isBlockedIPv6('fe80::1%eth0') === 'link-local (fe80::/10)', isBlockedIPv6('fe80::1%eth0'));
t('R1b2', 'isBlockedIPv6(::7f00:1%eth0) 剥离 zone id 后仍拦截', !!isBlockedIPv6('::7f00:1%eth0'), isBlockedIPv6('::7f00:1%eth0'));

// —— 良性放行 ——
t('R1c', '公网 IPv4-compat ::8.8.8.8 放行', !(await validateFetchUrl('http://[::8.8.8.8]/')));
t('R1d', '公网 URL https://example.com/ 放行', !(await validateFetchUrl('https://example.com/')));
t('R1e', '普通 IPv6 2001:db8::1 放行', !(await validateFetchUrl('http://[2001:db8::1]/')));

console.log(failed === 0 ? '\nR1: 全部通过' : `\nR1: ${failed} 项失败`);
process.exit(failed ? 1 : 0);
