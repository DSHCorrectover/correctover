/**
 * @file Command injection detection — inspects subprocess argv and shell strings.
 *
 * Detects:
 *  - Shell metacharacter injection (;, |, &&, ||, backticks, $())
 *  - Reverse shell patterns
 *  - Download-and-execute chains (curl|wget | sh, pip install from URL)
 *  - Obfuscated commands (base64 -d | sh, hex encoding)
 *  - Fileless execution (/dev/tcp, /dev/shm)
 */

const DANGEROUS_PATTERNS = [
  // Shell chaining / injection
  // F3 修复（v2.4.6）：收紧表格/文档行误报
  //   - `;`/`&` 链式 + 解释器：保留（真实注入形态：cmd; bash ...）
  //   - `$(` 命令替换 + 解释器：保留；裸 `$ bash`（文档 shell 提示符）不再命中
  //   - 竖线（|）前要求 ≥2 个命令字符：markdown 表格单元 `| Bash |` 不再命中；
  //     pipeOnly 模式另做逐行上下文过滤（排除表格行/中文文档行，见 detectCommandInjection）
  { pattern: /[;&]\s*(?:sh\b|bash\b|zsh\b|dash\b|perl\b|ruby\b|node\b)/i, weight: 5, label: 'shell metachar + interpreter' },
  { pattern: /\$\(\s*(?:sh|bash|zsh|dash|perl|ruby|node)\b/i, weight: 5, label: 'shell metachar + interpreter' },
  { pattern: /[a-z0-9_.\-=]{2,}\s*\|\s*(?:sh\b|bash\b|zsh\b|dash\b|perl\b|ruby\b|node\b)/i, weight: 5, label: 'shell metachar + interpreter (pipe)', pipeOnly: true },
  // 2026-08-19 fix: python removed from generic interpreter list; pipeline/sequence is normal PS workflow,
  // only blocked when piped after a download/exec primitive (see rules below)
  { pattern: /(?:curl|wget|nc\b|ncat|base64|xxd|eval|IEX|iwr|Invoke-WebRequest|Invoke-Expression)\b[^|;]{0,60}\s*[|;]\s*python\b/i, weight: 6, label: 'pipeline to python after download/exec primitive' },
  // F3 修复：管道类模式排除 markdown 表格行/中文文档行（`| bash | zsh |` 表头不再叠加命中）
  { pattern: /[a-z0-9_.\-=]+\s*\|\s*(?:sh|bash|zsh|dash|python|perl|ruby|node)\b/i, weight: 6, label: 'pipe to interpreter', pipeOnly: true },
  // 收紧：反引号内必须包含危险命令特征（文档代码片段 `` `ls` `` 不再命中）
  { pattern: /`[^`]*(?:rm\s|curl\b|wget\b|nc\b|(?:bash|sh|python|perl|ruby|node)\b|base64\b|eval\b|sudo\b|chmod\b|mkfs\b|dd\s)[^`]*`/, weight: 4, label: 'backtick command substitution' },
  // 收紧：$() 内必须包含危险命令词（PowerShell $(Get-Date) / $($_.x) 不再命中）
  { pattern: /\$\((?:rm|curl|wget|nc|bash|sh|python|perl|ruby|sudo|echo|cat|chmod|base64|eval|kill|dd|mkfs)\s/, weight: 4, label: '$() command substitution' },
  { pattern: /;\s*(?:rm|mv|cp|chmod|chown|curl|wget|nc|bash|sh|python|cat|echo)\b/i, weight: 4, label: 'chained dangerous command' },

  // Reverse shells
  { pattern: /(?:bash|sh|zsh)\s+-i\s*>&?\s*\/dev\/(?:tcp|udp)\//i, weight: 7, label: 'reverse shell (/dev/tcp)' },
  { pattern: /nc\b.{0,40}-e\s+(?:sh|bash|bin\/sh)/i, weight: 7, label: 'netcat reverse shell' },
  { pattern: /ncat\b.{0,40}-e\s+(?:sh|bash)/i, weight: 7, label: 'ncat reverse shell' },
  { pattern: /python.{0,60}socket.{0,40}(?:connect|send|recv)/i, weight: 6, label: 'python reverse shell' },

  // Download-and-execute
  { pattern: /(?:curl|wget)\b[^|;]{0,100}\|\s*(?:sh|bash|zsh|python|perl)/i, weight: 6, label: 'download-and-execute', pipeOnly: true },
  { pattern: /(?:curl|wget)\b[^|;]{0,200}(?:-o|--output)[^|;]{0,60}(?:\/tmp|\/dev\/shm|\/var\/tmp)/i, weight: 4, label: 'download to temp (possible staging)' },

  // PowerShell download-and-execute (2026-08-19 修复 TP-4)
  { pattern: /(?:IEX|Invoke-Expression|iex)\b[^\r\n;]{0,120}(?:New-Object\s+Net\.WebClient|DownloadString|DownloadFile|Invoke-WebRequest|Start-BitsTransfer|\biwr\b)/i, weight: 7, label: 'PowerShell download cradle (IEX)' },
  { pattern: /(?:Invoke-WebRequest|\biwr\b)\b[^|;\r\n]{0,120}\s*\|\s*(?:IEX|Invoke-Expression|iex)\b/i, weight: 7, label: 'PowerShell download cradle (iwr|iex)' },
  { pattern: /Start-BitsTransfer\b[^|;\r\n]{0,160}(?:;|\n|\r)\s*(?:IEX|Invoke-Expression|iex)\b/i, weight: 7, label: 'PowerShell download cradle (BITS + IEX)' },
  { pattern: /(?:powershell|pwsh)\b[^\r\n]{0,60}-(?:enc|encodedcommand)\b/i, weight: 7, label: 'PowerShell encoded command' },
  { pattern: /(?:DownloadFile)\s*\([^)]*\)\s*;\s*(?:Start-Process|Invoke-Item|iex|IEX|Invoke-Expression)/i, weight: 7, label: 'PowerShell DownloadFile + execute' },

  // Fileless / memory-only
  { pattern: /\/dev\/(?:tcp|udp)\//i, weight: 5, label: '/dev/tcp or /dev/udp (network socket)' },
  { pattern: /\/dev\/shm\//i, weight: 2, label: '/dev/shm (tmpfs, no disk trace)' },

  // Obfuscation
  { pattern: /base64\s+(?:-d|--decode)\s*\|?\s*(?:sh|bash|python|perl|eval)/i, weight: 6, label: 'base64 decode + execute' },
  { pattern: /xxd\s+-p?\s*-r?\s*\|?\s*(?:sh|bash)/i, weight: 5, label: 'hex decode + execute' },
  { pattern: /\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}/, weight: 3, label: 'hex-encoded characters' },
  { pattern: /\$\{IFS\}/, weight: 4, label: '${IFS} obfuscation' },
  { pattern: /\$\{PATH:[\d:]+}/, weight: 4, label: 'PATH substring obfuscation' },

  // Destructive
  { pattern: /\brm\s+-[rf]+\s+(?:\/|~|\*|\.\.|\/\*|~\/\*)/i, weight: 7, label: 'destructive rm (root/home/glob)' },
  { pattern: /\bmkfs\b/, weight: 7, label: 'mkfs (filesystem format)' },
  { pattern: /\bdd\s+if=\/dev\/(?:zero|random|urandom)\s+of=\/dev\//i, weight: 7, label: 'dd to device' },
  { pattern: /:\(\)\s*{\s*:\s*\|\s*:\s*&\s*};/, weight: 7, label: 'fork bomb' },

  // Persistence
  { pattern: /(?:>>|>)\s*(?:~\/)?\.(?:bashrc|zshrc|profile|bash_profile)/i, weight: 5, label: 'shell profile modification (persistence)' },
  { pattern: /(?:chmod|chown)\s+[0-7]*777/, weight: 2, label: 'chmod 777 (overly permissive)' },

  // Credential theft
  { pattern: /cat\s+(?:~\/)?\.ssh\/id_rsa/, weight: 7, label: 'SSH private key read' },
  { pattern: /cat\s+(?:~\/)?\.aws\/credentials/, weight: 7, label: 'AWS credentials read' },
  { pattern: /(?:env|printenv)\s*\|/, weight: 3, label: 'environment dump piped' },
];

/**
 * F3 修复：剥离 markdown 表格行（`| cell | cell |`）。
 * 表格行是文档内容，`| Bash |`、`| bash | zsh |`、`| 工具 | 平台 |` 等
 * 不应作为管道命令参与计分。
 */
function stripTableRows(text) {
  return text.split('\n').map(line => {
    const t = line.trim();
    if (t.startsWith('|') && (t.match(/\|/g) || []).length >= 2) return '';
    return line;
  }).join('\n');
}

/**
 * F3 修复：管道类模式逐行检测 —— 排除中文文档/注释上下文
 * （如「bash | zsh 对比」这类含中文词的说明行；真实攻击命令为 ASCII）。
 */
function testPipePattern(pattern, text) {
  for (const line of text.split('\n')) {
    if (/[\u4e00-\u9fff]/.test(line)) continue;
    pattern.lastIndex = 0;
    if (pattern.test(line)) return true;
  }
  return false;
}

/**
 * Scan a command string for injection patterns.
 * @param {string} command
 * @param {number} [threshold=8]
 * @returns {{ score: number, hits: Array<{label: string, weight: number}>, blocked: boolean, reason?: string }}
 */
export function detectCommandInjection(command, threshold = 6) {
  if (!command || typeof command !== 'string') return { score: 0, hits: [], blocked: false };

  let score = 0;
  const hits = [];
  const scanText = stripTableRows(command);

  for (const { pattern, weight, label, pipeOnly } of DANGEROUS_PATTERNS) {
    pattern.lastIndex = 0;
    if (pipeOnly ? testPipePattern(pattern, scanText) : pattern.test(scanText)) {
      score += weight;
      hits.push({ label, weight });
    }
  }

  const blocked = score >= threshold;
  return {
    score,
    hits,
    blocked,
    reason: blocked ? `command injection detected (score ${score} ≥ ${threshold}): ${hits.map(h => h.label).join(', ')}` : undefined,
  };
}

/**
 * Inspect a subprocess spawn spec for dangerous commands.
 * @param {object} spec - spawn spec with argv and/or command.
 * @param {number} [threshold]
 * @returns {{ score: number, hits: Array<{label: string, weight: number}>, blocked: boolean, reason?: string }}
 */
export function inspectSpawn(spec, threshold = 6) {
  const argv = Array.isArray(spec?.argv) ? spec.argv : [];
  const command = typeof spec?.command === 'string' ? spec.command : '';
  // Join argv into a string for pattern matching
  const combined = command || argv.join(' ');
  return detectCommandInjection(combined, threshold);
}
