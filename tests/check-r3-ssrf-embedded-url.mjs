#!/usr/bin/env node
/**
 * R3 验证：SSRF 整串锚定绕过修复 —— 参数串内全局 URL 提取逐个校验
 *  - 攻击：非命令非写入工具参数（text/query 字段）内嵌私有 URL 必须拦截（修复前 allow=true）
 *  - 良性：内嵌公网 URL、无 URL 的正常调用必须放行
 * 运行: node tests/check-r3-ssrf-embedded-url.mjs
 */
import { evaluateToolCall, evaluateSubprocess } from '../dsh/policy.js';

const call = (name, args) => evaluateToolCall({ name, arguments: args }, undefined);

let failed = 0;
const t = (id, name, expectAllow, decision, extra = '') => {
  const ok = expectAllow === decision.allow;
  console.log(`${ok ? 'PASS' : 'FAIL'} ${id} ${name} => ${decision.allow ? 'allow' : 'deny'}${extra ? ' | ' + extra : ''}`);
  if (!ok) failed++;
};

// —— 攻击拦截：text/query 字段内嵌私有 URL（修复前整串锚定不命中 → ALLOW）——
const a1 = await call('web_search', { text: 'the metadata service lives at http://169.254.169.254/latest/meta-data/ check it' });
t('R3a', 'text 字段内嵌云元数据 URL', false, a1, (a1.reason || '').slice(0, 90));

const a2 = await call('agent_tool', { query: 'connect to http://10.0.0.1/admin please' });
t('R3b', 'query 字段内嵌内网 URL', false, a2, (a2.reason || '').slice(0, 90));

const a3 = await call('send_message', { text: 'fetch http://192.168.1.1/config for the payload' });
t('R3c', 'text 字段内嵌 192.168 内网 URL', false, a3, (a3.reason || '').slice(0, 90));

const a4 = await call('web_fetch', { url: 'http://169.254.169.254/latest/meta-data/' });
t('R3d', '整串 URL 锚定（回归，仍拦截）', false, a4, (a4.reason || '').slice(0, 90));

// subprocess argv 内嵌私有 URL（同步路径同样修复）
const s1 = evaluateSubprocess({ argv: ['curl', '-H', 'X-Meta: http://169.254.169.254/latest/meta-data/'] });
t('R3e', 'subprocess argv 内嵌私有 URL', false, s1, (s1.reason || '').slice(0, 90));

// —— 良性放行 ——
const b1 = await call('web_search', { query: 'latest AI news' });
t('R3f', '无 URL 正常调用放行', true, b1);
const b2 = await call('web_fetch', { url: 'https://8.8.8.8/dns', text: 'public resolver' });
t('R3g', '内嵌公网 IP URL 放行', true, b2, (b2.reason || '').slice(0, 60));
const s2 = evaluateSubprocess({ argv: ['curl', 'https://8.8.8.8/dns'] });
t('R3h', 'subprocess 公网 URL 放行', true, s2, (s2.reason || '').slice(0, 60));

console.log(failed === 0 ? '\nR3: 全部通过' : `\nR3: ${failed} 项失败`);
process.exit(failed ? 1 : 0);
