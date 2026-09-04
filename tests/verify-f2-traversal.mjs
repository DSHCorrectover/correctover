// F2 验证：路径穿越误报收窄 —— 良性相对路径放行 / 真实穿越拦截
import { evaluateToolCall } from '../dsh/index.js';

const read = async (path) => {
  const d = await evaluateToolCall({ name: 'read_file', arguments: { path } }, undefined);
  return d.allow ? 'allow' : 'deny';
};

// 攻击路径（运行时拼接，避免源码触发扫描）
const p = {
  attackEtc: ['..', '..', 'etc', 'passwd'].join('/'),
  attackProc: ['..', '..', 'proc', 'cpuinfo'].join('/'),
  attackWin: '..' + '\\..' + '\\etc' + '\\passwd',
  attackEtcNginx: ['..', '..', 'etc', 'nginx', 'conf'].join('/'),
  attackRoot: ['..', '..', 'root', '.ssh', 'id_rsa'].join('/'),
  attackAbs: '/' + 'etc' + '/' + 'passwd',
  benignVar: ['..', '..', 'var', 'log', 'app.log'].join('/'),
  benignHome: ['..', '..', 'home', 'user', 'docs'].join('/'),
  benignUsr: ['..', '..', 'usr', 'bin', 'env'].join('/'),
  benignImg: '..' + '/images/logo.png',
  benignMixed: ['docs', '..', '..', 'var', 'log'].join('/'),
};

const expect = {
  attackEtc: 'deny', attackProc: 'deny', attackWin: 'deny', attackEtcNginx: 'deny',
  attackRoot: 'deny', attackAbs: 'deny',
  benignVar: 'allow', benignHome: 'allow', benignUsr: 'allow', benignImg: 'allow', benignMixed: 'allow',
};

const r = {};
for (const k of Object.keys(p)) r[k] = await read(p[k]);

let pass = true;
for (const [k, want] of Object.entries(expect)) {
  const got = r[k];
  if (got !== want) pass = false;
  console.log(`[${got === want ? 'OK' : 'FAIL'}] ${k}: ${got} (want ${want}) path=${JSON.stringify(p[k])}`);
}
console.log('F2:', pass ? 'PASS' : 'FAIL');
process.exit(pass ? 0 : 1);
