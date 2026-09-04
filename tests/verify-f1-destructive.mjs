// F1 验证：破坏性工具前缀收窄 —— 良性工具放行 / 真破坏工具拦截
import { evaluateToolCall } from '../dsh/index.js';

const call = async (name) => {
  const d = await evaluateToolCall({ name, arguments: {} }, undefined);
  return d.allow ? 'allow' : 'deny';
};

const benign = ['delete_message', 'delete_email', 'delete_file', 'disable_notifications', 'disable_user', 'delete_alert', 'delete_log', 'drop_connection', 'push_notification'];
const destructive = ['delete_record', 'delete_user', 'delete_account', 'delete_database', 'drop_table', 'drop_database', 'truncate_logs', 'destroy_instance', 'terminate_instance', 'revoke_access', 'rm'];

const r = {};
for (const t of benign) r[t] = await call(t);
for (const t of destructive) r[t] = await call(t);

let pass = true;
for (const t of benign) {
  const got = r[t];
  if (got !== 'allow') pass = false;
  console.log(`[${got === 'allow' ? 'OK' : 'FAIL'}] FP-allow : ${t} -> ${got}`);
}
for (const t of destructive) {
  const got = r[t];
  if (got !== 'deny') pass = false;
  console.log(`[${got === 'deny' ? 'OK' : 'FAIL'}] TP-deny  : ${t} -> ${got}`);
}
console.log('F1:', pass ? 'PASS' : 'FAIL');
process.exit(pass ? 0 : 1);
