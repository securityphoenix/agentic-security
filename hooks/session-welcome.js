#!/usr/bin/env node
// SessionStart hook: print a one-time welcome per project so the user knows
// the plugin is active and what's available. Gated on a marker file so it
// only fires once per `.agentic-security` directory.
'use strict';
const fs = require('fs');
const path = require('path');

const cwd = process.env.CLAUDE_PROJECT_DIR || process.cwd();
const stateDir = path.join(cwd, '.agentic-security');
const marker = path.join(stateDir, '.welcomed');

if (fs.existsSync(marker)) process.exit(0);

const lines = [
  '',
  '🔒 agentic-security is active in this project.',
  '',
  '  /security-scan-all     full SAST + SCA + secrets + IaC sweep',
  '  /security-mcp-audit    audit MCP server configs (agent-host risks)',
  '  /security-authz        deep auth/authZ audit (OWASP A01)',
  '  /security-help         see all 25+ commands by category',
  '  /security-status       project health & plugin status',
  '',
  '  Hooks: every Edit/Write scans the changed file in <5s.',
  '  This message shows once per project.',
  '',
];

try {
  fs.mkdirSync(stateDir, { recursive: true });
  fs.writeFileSync(marker, new Date().toISOString());
} catch {}

console.error(lines.join('\n'));
process.exit(0);
