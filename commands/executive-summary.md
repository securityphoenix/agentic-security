---
description: One-page CISO-facing summary of the six harness controls — what runs, what's blocked, what's caught, what's proven, what fails safely, what's compliance-ready.
argument-hint: "[--output PATH] [--format text|md]"
---

Print a plain-English executive summary of the harness controls in this
project. Audience: a CISO who has five minutes, no familiarity with this
codebase, and needs to know whether to trust an AI agent working in it.

No jargon. No CWE numbers. No CVSS. Six numbered sections, each with a
one-line description of the control, what it prevents, the file or runtime
artifact that proves it, and a live status indicator drawn from the
current project state.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
node -e "
const fs = require('fs');
const path = require('path');

// ---- argument parsing -------------------------------------------------------
const args = process.argv.slice(1);
let outPath = null;
let format = 'text';
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--output' && args[i+1]) { outPath = args[++i]; format = 'md'; }
  else if (args[i] === '--format' && args[i+1]) { format = args[++i]; }
}

const cwd = process.env.CLAUDE_PROJECT_DIR || process.cwd();
const pluginRoot = process.env.CLAUDE_PLUGIN_ROOT || path.dirname(path.dirname(__filename));

// ---- evidence collection ----------------------------------------------------
// Each control reports: { active, detail, evidence }
//   active: 'on' | 'warn' | 'off' | 'unknown'
//   detail: one short sentence for the CISO
//   evidence: file/path/env var to look at for proof

function safeRead(p) { try { return fs.readFileSync(p, 'utf8'); } catch { return null; } }
function safeJSON(p) { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return null; } }
function exists(p) { try { fs.accessSync(p); return true; } catch { return false; } }
function mtimeOf(p) { try { return fs.statSync(p).mtime; } catch { return null; } }
function lineCount(p) { try { return fs.readFileSync(p, 'utf8').split('\n').filter(Boolean).length; } catch { return 0; } }

// 1. Tool access
function checkToolAccess() {
  const teamSettings = safeJSON(path.join(cwd, '.claude', 'settings.json'));
  const userSettings = safeJSON(path.join(cwd, '.claude', 'settings.local.json'));
  const denies = []
    .concat(teamSettings?.permissions?.deny || [])
    .concat(userSettings?.permissions?.deny || []);
  const confinement = exists(path.join(pluginRoot, 'agents', '_CONFINEMENT.md'));
  const mcpKill = process.env.AGENTIC_SECURITY_MCP_DISABLED === '1';
  return {
    active: denies.length > 0 || confinement ? 'on' : 'off',
    detail: 'The agent can only read files this project allows, and can only write to files outside a reserved list (build manifests, CI configs, the .git folder, the agent\\'s own state). The agent runs with one explicit write tool, and it refuses to apply a fix unless the project\\'s scan signature still verifies.',
    extra: [
      'Read deny rules: ' + denies.length + (mcpKill ? '  |  MCP server: DISABLED (kill switch active)' : ''),
      'Subagent write contract: ' + (confinement ? 'present' : 'missing') + '  (' + path.relative(cwd, path.join(pluginRoot, 'agents', '_CONFINEMENT.md')) + ')',
    ],
    evidence: '.claude/settings.json  +  agents/_CONFINEMENT.md  +  scanner/src/mcp/tools.js (_confine, RESERVED_WRITE_*)',
  };
}

// 2. Guardrails
function checkGuardrails() {
  const hooksPath = path.join(pluginRoot, 'hooks', 'hooks.json');
  const hooks = safeJSON(hooksPath) || {};
  const hooked = ['PreToolUse', 'PostToolUse', 'SessionStart', 'Stop'].filter(k => hooks.hooks && hooks.hooks[k]);
  const bodyguardCfg = safeJSON(path.join(cwd, '.agentic-security', 'bodyguard.json')) || { mode: 'warn' };
  const destructCfg = safeJSON(path.join(cwd, '.agentic-security', 'destructive-guard.json')) || { mode: 'block' };
  const active = hooked.length === 4;
  return {
    active: active ? (bodyguardCfg.mode === 'block' && destructCfg.mode !== 'off' ? 'on' : 'warn') : 'off',
    detail: 'Before every shell command, a guard rejects the dangerous ones — wiping a database, force-pushing to main, piping curl into bash, recursive S3 deletes. Before every code edit, a second guard scans the proposed text for the most common insecure patterns (hardcoded keys, SQL string-concat, service-role keys on the client) and refuses the write.',
    extra: [
      'Hooks active: ' + hooked.join(', ') + (hooked.length < 4 ? '  (some missing — run /install-hooks)' : ''),
      'Code-edit guard mode: ' + bodyguardCfg.mode + '   |   Shell guard mode: ' + destructCfg.mode,
    ],
    evidence: 'hooks/pre-bash-guard.js  +  hooks/pre-edit-bodyguard.js  +  .agentic-security/{bodyguard,destructive-guard}.json',
  };
}

// 3. Feedback loops
function checkFeedback() {
  const postEdit = exists(path.join(pluginRoot, 'hooks', 'post-edit-scan.js'));
  const drift = exists(path.join(pluginRoot, 'hooks', 'session-stop-drift-check.js'));
  const lastScan = mtimeOf(path.join(cwd, '.agentic-security', 'last-scan.json'));
  const hist = exists(path.join(cwd, '.agentic-security', 'fix-history'));
  return {
    active: postEdit && drift ? 'on' : 'warn',
    detail: 'After every file the agent writes, the scanner re-runs on that folder and reports any new high or critical findings the edit just introduced — within seconds. Before any fix is committed, a verifier re-scans the patched file in memory and refuses to apply the fix if the original problem is still there or a new one appeared.',
    extra: [
      'Post-edit scan hook: ' + (postEdit ? 'active' : 'missing'),
      'Last scan baseline: ' + (lastScan ? lastScan.toISOString() : 'none yet — run /scan --all to take one'),
      'Fix-attempt history: ' + (hist ? 'present (caps retries at 2 per finding)' : 'empty'),
    ],
    evidence: 'hooks/post-edit-scan.js  +  scanner/src/posture/fix-history.js  +  .agentic-security/last-scan.json',
  };
}

// 4. Audit evidence
function checkAudit() {
  const auditLog = path.join(cwd, '.agentic-security', 'mcp-audit.log');
  const sigPath = path.join(cwd, '.agentic-security', 'last-scan.json.sig');
  const entries = lineCount(auditLog);
  const webhook = !!process.env.AGENTIC_SECURITY_AUDIT_WEBHOOK;
  const sig = exists(sigPath);
  return {
    active: entries > 0 || sig ? 'on' : 'warn',
    detail: 'Every tool call the agent makes is appended to an audit log where each entry contains a hash of the previous entry. Tampering with any line breaks the chain from that point forward. The scan output itself is signed with a key only this machine holds, so a tampered findings file is rejected by downstream tools. Optionally, every audit entry is also POSTed to an off-host witness so a full-file rewrite would still leave a gap visible from outside the machine.',
    extra: [
      'Audit log entries (this project): ' + entries,
      'Last-scan signature present: ' + (sig ? 'yes' : 'no'),
      'Off-host witness configured: ' + (webhook ? 'yes (AGENTIC_SECURITY_AUDIT_WEBHOOK set)' : 'no — set the env var to a POST endpoint to enable'),
    ],
    evidence: '.agentic-security/mcp-audit.log  +  .agentic-security/last-scan.json.sig  +  AGENTIC_SECURITY_AUDIT_WEBHOOK',
  };
}

// 5. Failure mode
function checkFailure() {
  // Sources of policy: HMAC key, rules.yml signing requirement, fix-history budget.
  const rulesYml = safeRead(path.join(cwd, '.agentic-security', 'rules.yml'));
  const rulesSig = exists(path.join(cwd, '.agentic-security', 'rules.yml.sig'));
  const unsigned = process.env.AGENTIC_SECURITY_RULES_UNSIGNED === '1';
  return {
    active: 'on',
    detail: 'Refuse-by-default. If the scan signature does not verify, fixes do not apply. If a custom rule tries to DISABLE a detector, it is ignored unless signed by this project\\'s key. After two failed fix attempts on the same finding, the agent gives up and routes the finding back to a human. Experimental rules write to a shadow file that the CI gate does not read.',
    extra: [
      'Rules override present: ' + (rulesYml ? 'yes' : 'no') +
        (rulesYml ? ('  (' + (rulesSig ? 'signed' : (unsigned ? 'UNSIGNED — accepted because AGENTIC_SECURITY_RULES_UNSIGNED=1' : 'UNSIGNED — coverage-reducing entries will be ignored')) + ')') : ''),
      'Retry budget per finding: 2 attempts, then route to human',
      'When the model is wrong, the harness blocks the write — it does not best-effort it.',
    ],
    evidence: 'scanner/src/posture/{integrity,fix-history}.js  +  .agentic-security/rules.yml(.sig)',
  };
}

// 6. Compliance
function checkCompliance() {
  // Look for any compliance artifact the user may have generated.
  const have = [];
  for (const f of ['SECURITY.md', 'compliance-report.md', 'compliance-attestation.json', 'sbom.json', 'sbom.cdx.json', 'aibom.json', 'sarif.json']) {
    if (exists(path.join(cwd, f))) have.push(f);
  }
  const reportsDir = path.join(cwd, 'reports');
  if (exists(reportsDir)) {
    try {
      for (const f of fs.readdirSync(reportsDir)) {
        if (/^(sbom|aibom|sarif|compliance)/i.test(f)) have.push('reports/' + f);
      }
    } catch {}
  }
  return {
    active: have.length ? 'on' : 'warn',
    detail: 'The same scan that gates the agent\\'s edits also emits machine-readable evidence on demand: a Software Bill of Materials, an AI Bill of Materials, a SARIF file for the security dashboard, and a compliance attestation mapping each finding to NIST AI 600-1, OWASP ASVS, and the OWASP LLM Top 10. Re-runs are byte-identical when --deterministic is set, so a signed attestation stays signed.',
    extra: [
      have.length ? ('Evidence files found in this project:\n     - ' + have.join('\n     - ')) : 'No evidence files generated yet — run /compliance-report or /security-attestation',
    ],
    evidence: 'commands/{compliance-report,security-attestation}.md  +  scanner/src/report/',
  };
}

// ---- rendering --------------------------------------------------------------
const W = (s, code) => (process.stdout.isTTY && format === 'text') ? '\\x1b[' + code + 'm' + s + '\\x1b[0m' : s;
const BOLD = '1', RED = '31', YELLOW = '33', GREEN = '32', CYAN = '36', DIM = '2';

function statusGlyph(s) {
  if (s === 'on')   return W('● ACTIVE',   GREEN);
  if (s === 'warn') return W('◐ PARTIAL', YELLOW);
  if (s === 'off')  return W('○ OFF',     RED);
  return W('? UNKNOWN', DIM);
}

const sections = [
  ['1. Tool access — what the agent can and cannot run',         checkToolAccess()],
  ['2. Guardrails — forbidden commands, enforced limits',        checkGuardrails()],
  ['3. Feedback loops — what catches mistakes in flight',        checkFeedback()],
  ['4. Audit evidence — continuous proof of control',            checkAudit()],
  ['5. Failure mode — what happens when the model is wrong',     checkFailure()],
  ['6. Compliance — evidence generated automatically',           checkCompliance()],
];

function renderText() {
  const lines = [];
  const proj = path.basename(cwd);
  lines.push('');
  lines.push(W('━━━ Security Posture — Executive Summary ━━━', BOLD));
  lines.push('  Project: ' + proj);
  lines.push('  Generated: ' + new Date().toISOString());
  lines.push('  Audience: CISO / security reviewer / buyer questionnaire');
  lines.push('');
  lines.push(W('  Plain English. No CWE numbers. No CVSS. Six controls.', DIM));
  lines.push('');
  for (const [title, c] of sections) {
    lines.push(W(title, BOLD) + '   ' + statusGlyph(c.active));
    // wrap detail at ~88 cols
    const words = c.detail.split(' ');
    let row = '   ';
    for (const w of words) {
      if ((row + ' ' + w).length > 88) { lines.push(row); row = '   ' + w; }
      else { row = row === '   ' ? row + w : row + ' ' + w; }
    }
    if (row.trim()) lines.push(row);
    lines.push('');
    for (const ex of (c.extra || [])) lines.push('     ' + ex);
    lines.push(W('     Evidence: ', DIM) + W(c.evidence, DIM));
    lines.push('');
  }
  lines.push(W('━━━ What to do with this ━━━', BOLD));
  lines.push('  Hand this to: a CISO, a security buyer, an SOC 2 auditor, a Series A diligence team.');
  lines.push('  Drill-down commands a reviewer can run themselves:');
  lines.push('     /scan --all                — list every finding with severity');
  lines.push('     /show-findings --kev       — only the ones being weaponized today');
  lines.push('     /compliance-report         — NIST AI 600-1 / OWASP ASVS / OWASP LLM Top 10');
  lines.push('     /security-attestation      — one-page buyer-facing artifact');
  lines.push('     /why-fired <finding-id>    — provenance graph for any specific finding');
  lines.push('');
  return lines.join('\\n');
}

function renderMarkdown() {
  const lines = [];
  const proj = path.basename(cwd);
  lines.push('# Security Posture — Executive Summary');
  lines.push('');
  lines.push('- **Project:** ' + proj);
  lines.push('- **Generated:** ' + new Date().toISOString());
  lines.push('- **Audience:** CISO / security reviewer / buyer questionnaire');
  lines.push('');
  lines.push('> Plain English. No CWE numbers. No CVSS. Six controls.');
  lines.push('');
  for (const [title, c] of sections) {
    const badge = c.active === 'on' ? '✅ ACTIVE' : c.active === 'warn' ? '🟡 PARTIAL' : c.active === 'off' ? '🛑 OFF' : '❔';
    lines.push('## ' + title + '   ' + badge);
    lines.push('');
    lines.push(c.detail);
    lines.push('');
    for (const ex of (c.extra || [])) lines.push('- ' + ex);
    lines.push('');
    lines.push('_Evidence:_ \`' + c.evidence + '\`');
    lines.push('');
  }
  lines.push('---');
  lines.push('');
  lines.push('## Drill-down commands a reviewer can run');
  lines.push('');
  lines.push('| Command | What it shows |');
  lines.push('|---|---|');
  lines.push('| \`/scan --all\` | every finding with severity |');
  lines.push('| \`/show-findings --kev\` | only the ones being weaponized today |');
  lines.push('| \`/compliance-report\` | NIST AI 600-1 / OWASP ASVS / OWASP LLM Top 10 |');
  lines.push('| \`/security-attestation\` | one-page buyer-facing artifact |');
  lines.push('| \`/why-fired <id>\` | provenance graph for any specific finding |');
  lines.push('');
  return lines.join('\\n');
}

const out = (format === 'md') ? renderMarkdown() : renderText();

if (outPath) {
  fs.writeFileSync(outPath, out);
  console.log('Wrote ' + outPath + '  (' + out.length + ' bytes, format=' + format + ')');
} else {
  process.stdout.write(out + '\\n');
}
" -- "$@"
```

Print the output verbatim. The user wants a single self-contained briefing
they can read in five minutes or paste into a buyer questionnaire.

---

## Notes for downstream use

- **Default format is plain text** with ANSI color for terminal reading.
  `--format md` switches to GitHub-flavored markdown. `--output PATH`
  implies `--format md` and writes to that path (typical: `EXECUTIVE_SUMMARY.md`).
- **Live evidence.** Status indicators are derived from current state —
  whether hooks are wired, whether the last scan is signed, whether a
  remote witness is configured, whether compliance artifacts exist. A
  CISO reading the printout is reading the *current* posture, not a
  generic template.
- **No CWE numbers, no CVSS, no security jargon in the prose.** The
  evidence line at the end of each section names the exact files, so a
  technically-curious reader can drill down — but the prose itself is
  written for the executive.
- **What it is not.** This is the controls report. It is not the
  findings report (`/scan --all`), the grade (`/report-card`), or the
  compliance attestation (`/compliance-report`). Those exist; this one
  lives upstream of them — "should the CISO trust the agent at all."
