/**
 * @file CCS policy engine — combines all detectors into a unified decision.
 *
 * The 7 CCS dimensions enforced at runtime:
 *  1. Structure  — tool call arguments match declared JSON Schema
 *  2. Schema     — input/output types are well-formed
 *  3. Latency    — call duration within budget (observability only)
 *  4. Cost       — token/API cost within budget (observability only)
 *  5. Identity   — caller and tool identity are known and trusted
 *  6. Integrity  — no prompt injection, no credential exfiltration
 *  7. Security   — no SSRF, command injection, path traversal, destructive ops
 */

import { validateFetchUrl } from './ssrf.js';
import { scanForSecrets, isCredentialPath, scanSubprocessForCredentials } from './credentials.js';
import { detectInjection } from './injection.js';
import { inspectSpawn } from './cmdi.js';
import { isPro, GATE_CTA } from './license.js';

/**
 * 收费门禁（免费层）—— 保守接入点：
 * 不改变任何拦截行为（allow/deny 原样返回），仅在「拦截说明/审计信息」
 * 输出处追加 Pro 升级 CTA。Pro 层（有效 CORRECTOVER_LICENSE_KEY 或
 * ~/.correctover/license.json）返回原样。
 * @param {string} reason 拦截说明
 * @returns {string}
 */
export function applyTierGate(reason) {
  if (!reason || isPro()) return reason;
  return `${reason}${GATE_CTA}`;
}

/** Default policy configuration. */
export const DEFAULT_POLICY = {
  // Dimension 7: Security
  ssrf: { enabled: true, allowPrivate: false },
  commandInjection: {
    enabled: true,
    threshold: 6,
    // 2026-08-19 改造：命令注入只检查「命令执行类工具」——数据工具(write/read/search/web)的参数是内容而非命令。
    // 用户可按需增删工具名（不区分大小写）。条目形态：前缀（向后兼容）、"=精确名"、含 "*" 的通配。
    // 2026-08-20 R5：加入 git/docker/ssh/npm/pip/npx 执行类工具（精确名 + 下划线/连字符通配），
    // 避免 git_* 前缀误伤 gitlab_*/github_* 等 API 工具。
    commandTools: ['pwsh', 'powershell', 'bash', 'sh', 'zsh', 'dash', 'shell', 'terminal', 'subprocess', 'exec', 'spawn', 'run', 'cmd', 'command', 'execute', 'script', 'python', 'node', 'npm', 'npx', 'curl', 'wget',
      '=git', 'git_*', 'git-*',
      '=docker', 'docker_*', 'docker-*',
      '=ssh', 'ssh_*', 'ssh-*',
      '=npm', 'npm_*', 'npm-*',
      '=pip', 'pip_*', 'pip-*',
      '=npx', 'npx_*', 'npx-*'],
  },
  credentialExfil: { enabled: true },
  pathTraversal: { enabled: true, blockedPaths: ['/etc/shadow', '/etc/passwd', '/etc/sudoers'] },
  destructiveTools: {
    enabled: true,
    // 精确匹配清单（2026-08-19 改造）：通用动词 apply/push/merge/deploy 移除，避免误伤良性工具
    requireApproval: [
      'execute_payment', 'pay', 'transfer', 'send_transaction',
      'rm', 'drop', 'truncate', 'destroy', 'shutdown', 'terminate',
      'revoke', 'disable', 'mkfs', 'dd', 'delete',
    ],
  },

  // Dimension 6: Integrity
  promptInjection: { enabled: true, threshold: 6 },

  // Dimension 5: Identity
  requireToolAnnotations: { enabled: false }, // warn-only by default

  // Observability (dimensions 3, 4)
  latencyBudgetMs: 30000,
  costBudgetTokens: 100000,

  // Output scanning
  scanOutput: {
    enabled: true,
    maxScanLength: 100000,
    // 2026-08-19 输出侧工具感知：本地读取默认 warn，外部数据默认 block，未知工具默认 block
    localReadAction: 'warn',   // 'warn' | 'block'
    networkAction: 'block',    // 'warn' | 'block'
    defaultAction: 'block',    // 'warn' | 'block'
  },

  // Allowlist for safe tools (skip deep scanning)
  safeToolAllowlist: [],
};

/**
 * Deep-merge user config with defaults.
 */
function mergeConfig(defaults, user) {
  if (!user) return structuredClone(defaults);
  const out = structuredClone(defaults);
  for (const [k, v] of Object.entries(user)) {
    if (v && typeof v === 'object' && !Array.isArray(v) && k in out && typeof out[k] === 'object') {
      out[k] = mergeConfig(out[k], v);
    } else {
      out[k] = v;
    }
  }
  return out;
}

/**
 * F2 修复（v2.4.6）：相对路径穿越误报收窄。
 * 原实现用「上跳后跟系统目录关键字」的正则直配，误伤面大：
 * 文档/参数里出现指向 var 下日志、usr 下 bin/env、home 下用户目录的
 * 良性相对路径（例如上跳两级再进入 var/log）即被拦。修复：
 *   1) 先归一化解析相对路径（手工解析 .. 段，等价 path.resolve 的根夹取），
 *      再与 blockedPaths / 系统敏感目录精确比对；
 *   2) var/home/usr 移出无条件系统路径集合，仅保留强信号目录
 *      etc/root/proc/sys（上跳指向这些目录仍视为真实穿越）。
 */

/** 强信号系统目录（归一化后命中即拦）：var/home/usr 为良性相对路径常见目标，已移除。 */
const TRAVERSAL_SYSTEM_DIR_RE = /^\/(?:etc|root|proc|sys)(?:\/|$)/;

/**
 * 归一化相对路径：解析 .. 段，并像 path.resolve 一样在根处夹取
 * （上跳两级的 etc/passwd 形态归一化为根下的 etc/passwd；反斜杠形态同样处理）。
 * @param {string} p
 * @returns {string}
 */
function normalizeTraversalPath(p) {
  const parts = String(p).replace(/\\/g, '/').split('/');
  const stack = [];
  for (const part of parts) {
    if (part === '..') {
      if (stack.length > 0 && stack[stack.length - 1] !== '..') stack.pop();
      else stack.push('..');
    } else if (part === '.' || part === '') {
      continue;
    } else {
      stack.push(part);
    }
  }
  while (stack.length > 0 && stack[0] === '..') stack.shift(); // 夹取到根
  return '/' + stack.join('/');
}

/**
 * Check for path traversal in string arguments.
 */
function checkPathTraversal(args, blockedPaths) {
  const findings = [];
  const seen = new WeakSet();

  function walk(val) {
    if (typeof val === 'string') {
      // Directory traversal
      if (val.includes('../') || val.includes('..\\')) {
        // Check if it targets a blocked absolute path
        for (const blocked of blockedPaths) {
          if (val.includes(blocked) || val.endsWith(blocked)) {
            findings.push(`path traversal targeting ${blocked}: ${val.slice(0, 100)}`);
          }
        }
        // F2 修复：归一化后再与强信号系统目录精确比对
        // （上跳指向 var/log、home/user、usr/bin 等良性相对路径不再误报）
        const normalized = normalizeTraversalPath(val);
        if (normalized && TRAVERSAL_SYSTEM_DIR_RE.test(normalized)) {
          findings.push(`directory traversal to system path: ${val.slice(0, 100)}`);
        }
      }
      // Absolute sensitive paths
      if (/^\/(?:etc\/shadow|etc\/passwd|etc\/sudoers|root\/\.ssh)/.test(val)) {
        findings.push(`direct access to sensitive path: ${val}`);
      }
    } else if (val && typeof val === 'object') {
      if (seen.has(val)) return;
      seen.add(val);
      if (Array.isArray(val)) val.forEach(walk);
      else Object.values(val).forEach(walk);
    }
  }

  walk(args);
  return findings;
}

/**
 * F1 修复（v2.4.6）：破坏性工具判定收窄。
 * 过宽前缀 delete_/drop_/terminate_/revoke_/disable_ 误伤良性工具：
 *   delete_message/delete_email/delete_file/disable_notifications 等文档/消息/通知
 *   工具一律要求人工审批 → 改为「高危前缀组合 + 良性白名单」：
 *   - delete_ 前缀保留（delete_record/delete_database 等数据删除必须拦），
 *     但常见的消息/邮件/文件/通知/临时文件删除走良性白名单放行
 *   - drop_ 收窄为数据库对象组合（table/database/db/schema/index/view/column）
 *   - terminate_ 收窄为实例/进程/服务类（instance/ec2/vm/server/process/task/pod/node）
 *   - revoke_ 收窄为访问/凭据类（access/permission/token/key/credential/api_key/role）
 *   - truncate_/destroy_ 全前缀保留（无良性同名工具）
 *   - disable_ 前缀移除（disable_* 多为可逆配置操作，仅精确名 disable 命中）
 */
const DESTRUCTIVE_PREFIX_RE = /^(?:drop_(?:table|database|db|schema|index|view|column)|truncate_|destroy_|terminate_(?:instance|instances|ec2|ecs|vm|server|process|task|pod|node)|revoke_(?:access|permission|permissions|token|key|keys|credential|credentials|api_?key|role)|delete_)/i;

/** 良性工具白名单：即使命中 delete_ 前缀也不要求人工审批。 */
const DESTRUCTIVE_BENIGN_SET = new Set([
  'delete_message', 'delete_email', 'delete_file', 'delete_attachment',
  'delete_notification', 'delete_comment', 'delete_cache', 'delete_temp',
  'delete_log', 'delete_cookie', 'delete_draft', 'delete_history',
  'delete_session', 'delete_bookmark', 'delete_filter', 'delete_alert',
  'delete_reminder', 'delete_snippet', 'delete_media', 'delete_photo',
]);

function isDestructive(toolName, requireApproval) {
  const lower = toolName.toLowerCase();
  if (requireApproval.some(d => lower === d.toLowerCase())) return true;
  if (DESTRUCTIVE_BENIGN_SET.has(lower)) return false;
  if (DESTRUCTIVE_PREFIX_RE.test(lower)) return true;
  return false;
}

/**
 * 2026-08-19 改造：命令执行类工具判定（可配置）。
 * 命令注入检查只对「真正把参数当作命令执行」的工具进行；
 * write/read/edit/search/web 等工具的参数是数据，不做命令注入扫描（消除文档/代码片段误报）。
 *
 * 2026-08-20 R5 扩展：条目支持三种形态（不区分大小写）——
 *  - "=name"   精确匹配工具名（如 "=git" 只匹配 git，不匹配 gitlab_*）
 *  - 含 "*"    通配匹配（如 "git_*" 匹配 git_clone/git_commit；"*exec" 匹配任意以 exec 结尾）
 *  - 其他      前缀匹配（向后兼容，如 "pwsh" 匹配 pwsh/pwsh_run）
 * 此前仅支持前缀匹配，git/docker/ssh 等未列入前缀的执行类工具参数不被 cmdi 覆盖。
 */
function isCommandTool(name, config) {
  const tools = config?.commandInjection?.commandTools || [];
  const lower = name.toLowerCase();
  return tools.some(t => {
    const entry = String(t).toLowerCase();
    if (!entry) return false;
    if (entry.startsWith('=')) return lower === entry.slice(1);
    if (entry.includes('*')) {
      const re = new RegExp('^' + entry.split('*').map(escapeRegExp).join('.*') + '$');
      return re.test(lower);
    }
    return lower.startsWith(entry);
  });
}

/** Escape a string for literal use inside a RegExp. */
function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * 2026-08-19 新增：文件写入类工具判定（工具感知检测）。
 * 写入类工具的参数（路径 + 内容）不做命令注入扫描，但必须做「文件安全」检查：
 * 危险路径（持久化/授权/系统文件）、可执行恶意内容（下载执行/反弹 shell/webshell）、写密钥文件。
 */
const FILE_WRITE_TOOL_RE = /^(?:write|write_file|writefile|fs_write|fs-write|append|append_file|overwrite|save|save_file|put|put_file|update_file|create_file|mkdir|upload)\b/i;
function isFileWriteTool(name) {
  return FILE_WRITE_TOOL_RE.test(name);
}

/** 持久化/授权/系统敏感路径（写入即拦截）。 */
const FILE_WRITE_BLOCKED_PATHS = [
  /(?:^|[\\/])\.?(?:bashrc|zshrc|profile|bash_profile|bash_logout|inputrc)(?:$|\.)/i,
  /authorized_keys\b/i,
  /(?:^|[\\/])\.ssh[\\/]/i,
  /(?:^|[\\/])\.aws[\\/]/i,
  /\.credentials\.ya?ml/i,
  /(?:^|[\\/])\.gnupg[\\/]/i,
  /(?:^|[\\/])\.netrc$/i,
  /(?:^|[\\/])\.pgpass$/i,
  /(?:^|[\\/])\.kube[\\/]/i,
  /\.docker[\\/]config\.json/i,
  /(?:^|[\\/])etc[\\/](?:passwd|shadow|sudoers|group|hosts\.allow|hosts\.deny)$/i,
  /(?:^|[\\/])etc[\\/]cron(?:\.d|tab)?[\\/]/i,
  /(?:^|[\\/])systemd[\\/]system[\\/]/i,
  /(?:^|[\\/])init\.d[\\/]/i,
  /(?:^|[\\/])windows[\\/]system32[\\/]drivers[\\/]etc[\\/]hosts$/i,
  /(?:^|[\\/])ProgramData[\\/].*[\\/]startup[\\/]/i,
  /(?:^|[\\/])AppData[\\/].*(?:Startup|Microsoft[\\/]Windows[\\/]Start Menu)[\\/]/i,
];

/** 写入内容中的恶意可执行特征（下载执行/反弹 shell/webshell/提权）。 */
const FILE_WRITE_MALICIOUS_CONTENT = [
  { re: /(?:curl|wget)\b[^|;\n]{0,100}\|\s*(?:sh|bash|zsh|python|perl)\b/i, label: 'download-and-execute in written file' },
  { re: /(?:bash|sh|zsh)\s+-i\s*>&?\s*\/dev\/(?:tcp|udp)\//i, label: 'reverse shell in written file' },
  { re: /nc\b.{0,40}-e\s+(?:sh|bash|bin\/sh)/i, label: 'netcat reverse shell in written file' },
  { re: /base64\s+(?:-d|--decode)\s*\|?\s*(?:sh|bash|python|perl|eval)/i, label: 'base64 decode+execute in written file' },
  { re: /<\?(?:php|asp)\b[\s\S]{0,200}?(?:system|exec|shell_exec|passthru|eval|assert)\s*\(/i, label: 'webshell (php/asp) in written file' },
  { re: /<\/?(?:script|jsp)[^>]*>[\s\S]{0,100}?(?:ProcessBuilder|Runtime\.getRuntime|exec)\s*\(/i, label: 'webshell (jsp/js) in written file' },
  { re: /:\(\)\s*{\s*:\s*\|\s*:\s*&\s*};/, label: 'fork bomb in written file' },
  { re: /\bmkfs\b/, label: 'mkfs in written file' },
];

/** 文档类扩展名：写入这些文件里的 shell 示例视为文档，不做可执行内容拦截。 */
const DOCUMENTATION_EXT_RE = /\.(?:md|markdown|mdown|mkd|txt|rst|adoc|asciidoc|html?|mdx)$/i;
function isDocumentationFile(path) {
  return !!path && DOCUMENTATION_EXT_RE.test(path);
}

/** 可执行脚本/程序扩展名：即使内容像 markdown，也不允许用围栏代码块绕过。 */
const EXECUTABLE_EXT_RE = /\.(?:sh|bash|zsh|bat|cmd|ps1|psm1|py|js|mjs|cjs|ts|php|pl|rb|exe|com|jar)$/i;
function isExecutableFile(path) {
  return !!path && EXECUTABLE_EXT_RE.test(path);
}

/** 判断某个字符偏移是否位于 markdown 围栏代码块内（``` 或 ~~~）。 */
function isInsideFencedCodeBlock(content, index) {
  const lines = content.split('\n');
  let charIndex = 0;
  let inFence = false;
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('```') || trimmed.startsWith('~~~')) inFence = !inFence;
    if (index >= charIndex && index <= charIndex + line.length) return inFence;
    charIndex += line.length + 1;
  }
  return false;
}

/**
 * 文件写入类工具的文件安全检查（2026-08-19 新增）。
 * 攻击者可能通过 write 工具写入持久化后门/webshell/密钥文件——
 * 这些不是"命令注入"，但同样是真正的攻击面，必须按文件语义检测。
 * @returns {string|null} 拦截理由，或 null 放行。
 */
function checkFileWriteSafety(name, args) {
  // 收集路径与内容参数
  let path = null;
  let content = null;
  const seen = new WeakSet();
  function collect(val) {
    if (val === null || val === undefined) return;
    if (typeof val === 'string') {
      // 路径形态：绝对/相对路径或带扩展名的文件名 → 写入目标
      const pathShaped = (/^[a-zA-Z]:[\\/]|\/|\\\\/.test(val) || val.includes('.'))
        && /(?:^|[\\/])[\w.@-]+(?:\.\w+)?$/.test(val);
      if (path === null && pathShaped) {
        path = val;
      } else if (content === null) {
        // 2026-08-20 R2 修复：去掉 val.length > 40 长度门槛。
        // 原先非键值内容仅当长度 > 40 才记为 content，write 数组形式（路径参数 +
        // 19 字符短载荷）实测 allow=true —— 短载荷经位置参数写入可执行脚本时不扫描。
        // 现在位置参数按 argv 语义（write(path, content)）识别路径/内容，短串同样
        // 参与高危模式扫描（长串仍受下游 content.length < 200000 约束）。
        content = val;
      }
    } else if (val && typeof val === 'object') {
      if (seen.has(val)) return;
      seen.add(val);
      if (Array.isArray(val)) val.forEach(collect);
      else {
        for (const [k, v] of Object.entries(val)) {
          if (/path|file|dest|target|filename|name/i.test(k) && typeof v === 'string') path = path || v;
          else if (/content|data|text|body|value/i.test(k) && typeof v === 'string') content = content || v;
          else collect(v);
        }
      }
    }
  }
  collect(args);

  // 1) 危险路径（持久化/授权/系统文件）
  if (path) {
    for (const re of FILE_WRITE_BLOCKED_PATHS) {
      if (re.test(path)) {
        return `[CCS/Security] tool "${name}" writing to sensitive/persistence path: ${path}`;
      }
    }
  }

  // 2) 恶意可执行内容（下载执行/反弹 shell/webshell/fork bomb）
  // 2026-08-19 FP-1 修复：文档类文件（.md/.txt/.rst 等）或 markdown 围栏代码块内的示例不再误拦
  if (content && content.length < 200000) {
    const docFile = isDocumentationFile(path);
    for (const { re, label } of FILE_WRITE_MALICIOUS_CONTENT) {
      re.lastIndex = 0;
      const match = re.exec(content);
      if (match) {
        if (docFile || (!isExecutableFile(path) && isInsideFencedCodeBlock(content, match.index))) continue;
        return `[CCS/Security] tool "${name}" writing malicious executable content: ${label}`;
      }
    }
    // 3) 写入内容含密钥（写密钥文件）
    const secrets = scanForSecrets(content);
    if (secrets.length > 0) {
      return `[CCS/Security] tool "${name}" writing credential material to file: ${secrets.map(s => s.label).join(', ')}`;
    }
  }
  return null;
}

/**
 * Evaluate a tool call against the CCS policy.
 *
 * @param {object} call - { name, arguments, agent? }
 * @param {object} [userConfig] - policy overrides.
 * @returns {Promise<{ allow: boolean, reason?: string, warnings: string[], dimension: string }>}
 */
async function _evaluateToolCallInner(call, userConfig) {
  const config = mergeConfig(DEFAULT_POLICY, userConfig);
  const warnings = [];
  const { name, arguments: args } = call;

  // Skip deep scanning for allowlisted safe tools
  if (config.safeToolAllowlist.includes(name)) {
    return { allow: true, warnings, dimension: 'allowlist' };
  }

  // Dimension 7: Destructive tool check
  if (config.destructiveTools.enabled && isDestructive(name, config.destructiveTools.requireApproval)) {
    return {
      allow: false,
      reason: `[CCS/Security] destructive tool "${name}" requires explicit human approval (auto-approve is blocked by CCS policy)`,
      warnings,
      dimension: 'Security',
    };
  }

  // Scan string arguments for various threats
  const argStrings = [];
  const seen = new WeakSet();
  function collectStrings(val) {
    if (typeof val === 'string') argStrings.push(val);
    else if (val && typeof val === 'object') {
      if (seen.has(val)) return;
      seen.add(val);
      if (Array.isArray(val)) val.forEach(collectStrings);
      else Object.values(val).forEach(collectStrings);
    }
  }
  collectStrings(args);

  // Dimension 7: SSRF — 2026-08-20 R3 修复：整串锚定 → 全局 URL 提取逐个校验
  // 原先仅检查以 http(s) 开头的整串参数，攻击者把私有 URL 内嵌在 text/query 等
  // 非命令非写入工具参数中（如 text 字段含元数据地址）即可绕过。现在提取参数串内
  // 所有 URL（/https?:\/\/[^\s"'<>]+/g）逐个过 validateFetchUrl。
  if (config.ssrf.enabled) {
    for (const str of argStrings) {
      const urls = str.match(/https?:\/\/[^\s"'<>]+/gi) || [];
      for (const u of urls) {
        const ssrfReason = await validateFetchUrl(u, { allowPrivate: config.ssrf.allowPrivate });
        if (ssrfReason) {
          return { allow: false, reason: `[CCS/Security] ${ssrfReason}`, warnings, dimension: 'Security' };
        }
      }
    }
  }

  // Dimension 7: Command injection — 仅对命令执行类工具检查（2026-08-19 改造：消除文档/代码内容误报）
  if (config.commandInjection.enabled && isCommandTool(name, config)) {
    for (const str of argStrings) {
      if (str.length > 5000) continue; // skip very long strings (likely data, not commands)
      // Only scan strings that look like they could contain shell commands
      if (/[;&|`$]|\b(?:curl|wget|bash|sh|nc|python|perl|ruby|chmod|rm|powershell|pwsh|iex|invoke-expression|invoke-webrequest|start-bitstransfer|downloadstring|downloadfile)\b/i.test(str) || /-enc\b/i.test(str)) {
        const result = inspectSpawn({ command: str }, config.commandInjection.threshold);
        if (result.blocked) {
          return { allow: false, reason: `[CCS/Security] ${result.reason}`, warnings, dimension: 'Security' };
        }
      }
    }
  }

  // Dimension 7: File write safety — 文件写入类工具按「文件语义」检测（2026-08-19 新增，工具感知）
  // 攻击者可通过 write 写持久化后门/webshell/密钥文件——不是命令注入，但同样是真实攻击面
  if (isFileWriteTool(name)) {
    const writeReason = checkFileWriteSafety(name, args);
    if (writeReason) {
      return { allow: false, reason: writeReason, warnings, dimension: 'Security' };
    }
  }

  // Dimension 7: Credential exfiltration
  if (config.credentialExfil.enabled) {
    const secrets = scanForSecrets(args);
    if (secrets.length > 0) {
      // If the tool is network-facing (fetch, request, send), block
      const networkFacing = /^(fetch|request|web|http|send|post|put|upload|curl|api_call|call)/i.test(name);
      if (networkFacing) {
        return {
          allow: false,
          reason: `[CCS/Security] credential pattern detected in network-facing tool "${name}" arguments: ${secrets.map(s => s.label).join(', ')}`,
          warnings,
          dimension: 'Security',
        };
      }
      // For non-network tools, warn only
      warnings.push(`credential pattern detected: ${secrets.map(s => s.label).join(', ')}`);
    }

    // Check for credential file paths
    for (const str of argStrings) {
      const credPath = isCredentialPath(str);
      if (credPath) {
        const readTool = /^(read|cat|get|fetch|open|load|view|show|list)/i.test(name);
        if (readTool) {
          return {
            allow: false,
            reason: `[CCS/Security] tool "${name}" attempting to read credential file: ${str}`,
            warnings,
            dimension: 'Security',
          };
        }
        warnings.push(`credential file path referenced: ${str}`);
      }
    }
  }

  // Dimension 7: Path traversal
  if (config.pathTraversal.enabled) {
    const traversal = checkPathTraversal(args, config.pathTraversal.blockedPaths);
    if (traversal.length > 0) {
      return {
        allow: false,
        reason: `[CCS/Security] path traversal detected: ${traversal[0]}`,
        warnings,
        dimension: 'Security',
      };
    }
  }

  // Dimension 6: Prompt injection — scan all string arguments concatenated
  if (config.promptInjection.enabled) {
    const combined = argStrings.join('\n').slice(0, 50000);
    if (combined.length > 10) {
      const injection = detectInjection(combined, { threshold: config.promptInjection.threshold });
      if (injection.blocked) {
        return {
          allow: false,
          reason: `[CCS/Integrity] ${injection.reason}`,
          warnings,
          dimension: 'Integrity',
        };
      }
      if (injection.hits.length > 0) {
        warnings.push(`prompt injection pattern (score ${injection.score}): ${injection.hits.map(h => h.label).join(', ')}`);
      }
    }
  }

  return { allow: true, warnings, dimension: 'pass' };
}

/**
 * Evaluate a tool call against the CCS policy（收费门禁包装）。
 * 拦截行为与 _evaluateToolCallInner 完全一致；免费层仅在拦截说明后追加 CTA。
 */
export async function evaluateToolCall(call, userConfig) {
  const decision = await _evaluateToolCallInner(call, userConfig);
  if (!decision.allow) decision.reason = applyTierGate(decision.reason);
  return decision;
}

/**
 * Output-side tool awareness:
 * - local read tools (read/cat/grep/...) return trusted/local data → prompt-injection patterns are warn-only
 * - network-facing tools (fetch/web/request/search/...) return external/untrusted data → strict block
 * - other/unknown tools keep the previous strict behavior
 */
const OUTPUT_LOCAL_READ_TOOL_RE = /^(?:read|cat|grep|view|list|get|open|load|show|head|tail|less|more|find|ls|stat|file|type|print)(?:[_-]?(?:file|files|path|content|dir|directory))?\b/i;
const OUTPUT_NETWORK_TOOL_RE = /^(?:fetch|web|http|request|search|browse|curl|wget|api|call|post|download|get_url|open_url)(?:[_-]?(?:fetch|request|search|url|page|content|api|call|client|hook|file))?\b/i;
// 编排型工具：workflow/subagent/send_message 等的参数与输出是"我方编排指令回显"，
// 不是外部不可信数据。对其扫描注入会产生误报（编排脚本天然含 "输出 JSON"/"system" 等词），
// 2026-08-19 修复：这类工具跳过输出侧注入扫描，仅保留凭证扫描。
const OUTPUT_ORCHESTRATION_TOOL_RE = /^(?:workflow|subagent|send_message|sendMessage|agent_fork|subagent_fork|ralph|goal|update_goal|create_goal|get_goal)$/i;

function isLocalReadTool(name) {
  return OUTPUT_LOCAL_READ_TOOL_RE.test(name || '');
}

function isNetworkTool(name) {
  return OUTPUT_NETWORK_TOOL_RE.test(name || '');
}

function isOrchestrationTool(name) {
  return OUTPUT_ORCHESTRATION_TOOL_RE.test(name || '');
}

/**
 * Evaluate a tool result/output for credential leakage.
 *
 * @param {object} result - { content?, isError? }
 * @param {object} [userConfig]
 * @param {object} [context] - optional runtime context, e.g. { toolName: 'read_file' }
 * @returns {{ allow: boolean, reason?: string, warnings: string[] }}
 */
function _evaluateToolResultInner(result, userConfig, context = {}) {
  const config = mergeConfig(DEFAULT_POLICY, userConfig);
  const warnings = [];
  const toolName = (context && (context.toolName || context.name)) || '';

  if (!config.scanOutput.enabled || result.isError) return { allow: true, warnings };

  // Extract text from content blocks
  let text = '';
  if (Array.isArray(result.content)) {
    for (const block of result.content) {
      if (block?.type === 'text' && typeof block.text === 'string') {
        text += block.text + '\n';
      }
    }
  } else if (typeof result.content === 'string') {
    text = result.content;
  }

  if (text.length > config.scanOutput.maxScanLength) {
    text = text.slice(0, config.scanOutput.maxScanLength);
  }

  if (!text) return { allow: true, warnings };

  // Scan output for leaked secrets
  const secrets = scanForSecrets(text);
  if (secrets.length > 0) {
    warnings.push(`output contains credential patterns: ${secrets.map(s => s.label).join(', ')}`);
    // Redact in a future version; for now warn
  }

  // Scan output for injection attempts (fetched web content trying to hijack)
  // 2026-08-19 输出侧工具感知：read/cat/grep 等本地读取工具仅告警，fetch/web 等外部数据严格阻断
  // 2026-08-19 编排型工具豁免：workflow/subagent/send_message 参数回显不扫描（我方指令，非外部数据）
  if (config.promptInjection.enabled && !isOrchestrationTool(toolName)) {
    const injection = detectInjection(text, { threshold: config.promptInjection.threshold });
    if (injection.blocked) {
      const action = isLocalReadTool(toolName)
        ? config.scanOutput.localReadAction
        : isNetworkTool(toolName)
          ? config.scanOutput.networkAction
          : config.scanOutput.defaultAction;
      if (action === 'warn') {
        const source = isLocalReadTool(toolName) ? 'local read tool' : isNetworkTool(toolName) ? 'network tool' : 'tool';
        warnings.push(`output contains prompt injection patterns (${source} "${toolName}", warn-only): ${injection.reason}`);
      } else {
        return {
          allow: false,
          reason: `[CCS/Integrity] tool output contains prompt injection: ${injection.reason}`,
          warnings,
        };
      }
    } else if (injection.hits.length > 0) {
      warnings.push(`output contains prompt injection patterns (score ${injection.score}): ${injection.hits.map(h => h.label).join(', ')}`);
    }
  }

  return { allow: true, warnings };
}

/**
 * Evaluate a tool result/output（收费门禁包装）。
 * 拦截行为与 _evaluateToolResultInner 完全一致；免费层仅在拦截说明后追加 CTA。
 */
export function evaluateToolResult(result, userConfig, context = {}) {
  const decision = _evaluateToolResultInner(result, userConfig, context);
  if (!decision.allow) decision.reason = applyTierGate(decision.reason);
  return decision;
}

/**
 * Evaluate a subprocess spawn for security violations.
 *
 * @param {object} spec - spawn spec
 * @param {object} [userConfig]
 * @returns {{ allow: boolean, reason?: string, warnings: string[] }}
 */
function _evaluateSubprocessInner(spec, userConfig) {
  const config = mergeConfig(DEFAULT_POLICY, userConfig);
  const warnings = [];

  // Command injection
  if (config.commandInjection.enabled) {
    const result = inspectSpawn(spec, config.commandInjection.threshold);
    if (result.blocked) {
      return { allow: false, reason: `[CCS/Security] ${result.reason}`, warnings };
    }
    if (result.hits.length > 0) {
      warnings.push(`command patterns: ${result.hits.map(h => h.label).join(', ')}`);
    }
  }

  // Credential exposure
  if (config.credentialExfil.enabled) {
    const credFindings = scanSubprocessForCredentials(spec);
    if (credFindings.length > 0) {
      return {
        allow: false,
        reason: `[CCS/Security] credential exposure in subprocess: ${credFindings.map(f => f.label).join(', ')}`,
        warnings,
      };
    }
  }

  // Check argv for URLs (SSRF via subprocess)
  // 2026-08-20 R3: 同步路径同样改为参数串内全局 URL 提取，堵住整串锚定绕过
  if (config.ssrf.enabled) {
    const argv = Array.isArray(spec?.argv) ? spec.argv : [];
    for (const arg of argv) {
      if (typeof arg !== 'string') continue;
      const urls = arg.match(/https?:\/\/[^\s"'<>]+/gi) || [];
      for (const u of urls) {
        // Synchronous URL check for common private IP patterns (no DNS lookup in sync path)
        if (/^https?:\/\/(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|localhost|0\.0\.0\.0|\[::1\])/i.test(u)) {
          return {
            allow: false,
            reason: `[CCS/Security] subprocess targets private/internal network: ${u}`,
            warnings,
          };
        }
      }
    }
  }

  return { allow: true, warnings };
}

/**
 * Evaluate a subprocess spawn for security violations（收费门禁包装）。
 * 拦截行为与 _evaluateSubprocessInner 完全一致；免费层仅在拦截说明后追加 CTA。
 */
export function evaluateSubprocess(spec, userConfig) {
  const decision = _evaluateSubprocessInner(spec, userConfig);
  if (!decision.allow) decision.reason = applyTierGate(decision.reason);
  return decision;
}
