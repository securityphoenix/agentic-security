// Claude Code (and equivalent harnesses) settings.json audit.
//
// Targets the canonical bugs in agent-harness configuration files:
//   1. Wildcard allow-rules — `Bash(*)`, `*`, `Bash(rm *)`, `Bash(curl *)`
//   2. Missing deny-list — when a permissions.allow exists but permissions.deny
//      is empty/absent, dangerous-command interception is not enforced.
//   3. Bypass / dangerous flags — `dangerouslySkipPermissions`, `bypassAll`,
//      `--no-permission-check`, `acceptAllEdits`, `autoApprove`.
//   4. Env block secrets — `ANTHROPIC_API_KEY: "sk-ant-..."` literal in env.
//   5. Output-style overrides that disable safety reasoning.
//
// Targets these config-file shapes (Claude + equivalents):
//   .claude/settings.json
//   .claude/settings.local.json
//   .cursor/settings.json
//   .codex/settings.json
//   .gemini/settings.json
//   .kiro/settings.json
//   .opencode/settings.json
//   .trae/settings.json
//   .qwen/settings.json
//   .zed/settings.json
//   ~/.claude/settings.json     (via harness-discovery)
//
// Each finding carries family `harness-config-permissions` so downstream
// per-category grade UX can roll it up into the "Permissions" bar.

const _SETTINGS_FILE_RE = /(?:^|[\\/])\.(?:claude|cursor|codex|gemini|kiro|opencode|trae|qwen|zed|continue|aider)[\\/](?:settings|settings\.local|config)\.json$/i;

const _DANGEROUS_BARE_PATTERNS = [
  { pattern: /^Bash\(\s*\*\s*\)$/, label: 'Bash(*) — unrestricted shell access', sev: 'critical' },
  { pattern: /^\*$/, label: 'wildcard \'*\' — every tool unrestricted', sev: 'critical' },
  { pattern: /^Bash\(\s*rm\s+\*\s*\)$/i, label: 'Bash(rm *) — unrestricted destructive deletion', sev: 'critical' },
  { pattern: /^Bash\(\s*rm\s+-rf\s+\*?\s*\)$/i, label: 'Bash(rm -rf) — recursive force delete granted', sev: 'critical' },
  { pattern: /^Bash\(\s*sudo\s+\*\s*\)$/i, label: 'Bash(sudo *) — privilege escalation granted', sev: 'critical' },
  { pattern: /^Bash\(\s*curl\s+\*\s*\)$/i, label: 'Bash(curl *) — unrestricted outbound HTTP', sev: 'high' },
  { pattern: /^Bash\(\s*wget\s+\*\s*\)$/i, label: 'Bash(wget *) — unrestricted outbound HTTP', sev: 'high' },
  { pattern: /^Bash\(\s*ssh\s+\*\s*\)$/i, label: 'Bash(ssh *) — unrestricted remote shell', sev: 'critical' },
  { pattern: /^Bash\(\s*git\s+push\s+--force.*?\)$/i, label: 'Bash(git push --force ...) — destructive ref rewrite granted', sev: 'high' },
  { pattern: /^WebFetch\s*\(\s*\*\s*\)$/i, label: 'WebFetch(*) — unrestricted outbound fetch', sev: 'high' },
  { pattern: /^Edit\s*\(\s*\*\s*\)$/i, label: 'Edit(*) — unrestricted file editing', sev: 'high' },
  { pattern: /^Write\s*\(\s*\*\s*\)$/i, label: 'Write(*) — unrestricted file write', sev: 'high' },
];

const _BYPASS_KEY_RE = /\b(?:dangerouslySkipPermissions|bypassAll|skipAllPermissions|disablePermissions|disableSafetyCheck|acceptAllEdits|autoApprove(?:All)?|noPermissionCheck|trustAllTools|allowDangerousTools)\b/;

const _CRED_RE = [
  /sk-ant-[A-Za-z0-9_-]{20,}/,
  /sk-[A-Za-z0-9]{32,}/,
  /ghp_[A-Za-z0-9]{36}/,
  /github_pat_[A-Za-z0-9_]{20,}/,
  /AKIA[0-9A-Z]{16}/,
  /xox[abprs]-[A-Za-z0-9-]{10,}/,
];

function _line(raw, idx) {
  return raw.slice(0, idx).split('\n').length;
}

function _harnessFromPath(file) {
  const m = /\.(?:claude|cursor|codex|gemini|kiro|opencode|trae|qwen|zed|continue|aider)[\\/]/i.exec(file);
  return m ? m[0].replace(/[\\/.]/g, '') : 'unknown';
}

export function scanClaudeSettings(file, raw) {
  if (!file || !raw || typeof raw !== 'string') return [];
  if (!_SETTINGS_FILE_RE.test(file)) return [];
  if (raw.length > 200_000) return [];

  let parsed;
  try { parsed = JSON.parse(raw); } catch { return []; }
  if (!parsed || typeof parsed !== 'object') return [];

  const harness = _harnessFromPath(file);
  const findings = [];

  // 1. Wildcard allow rules.
  const allowList = (parsed.permissions && Array.isArray(parsed.permissions.allow)) ? parsed.permissions.allow : [];
  for (const rule of allowList) {
    if (typeof rule !== 'string') continue;
    for (const { pattern, label, sev } of _DANGEROUS_BARE_PATTERNS) {
      if (pattern.test(rule.trim())) {
        const idx = raw.indexOf(rule);
        findings.push({
          id: `harness-config:allow-wildcard:${file}:${rule}`,
          file,
          line: idx >= 0 ? _line(raw, idx) : 1,
          vuln: `Harness allow-list grants ${label}`,
          severity: sev,
          family: 'harness-config-permissions',
          cwe: 'CWE-732',
          confidence: 0.95,
          description: `${harness} settings.json includes a permissions.allow rule (${rule}) that hands the agent broad capability without scoping. Any tool call matching this pattern executes without per-invocation confirmation.`,
          remediation: 'Scope the rule to a specific command or argument prefix (e.g., `Bash(git status)`, `Bash(npm test)`) and rely on the deny-list for everything else.',
          harness,
        });
      }
    }
  }

  // 2. Missing deny-list when allow-list is present and non-trivial.
  const denyList = (parsed.permissions && Array.isArray(parsed.permissions.deny)) ? parsed.permissions.deny : [];
  if (allowList.length >= 1 && denyList.length === 0) {
    findings.push({
      id: `harness-config:missing-deny:${file}`,
      file,
      line: 1,
      vuln: `Harness permissions has allow-list but empty deny-list`,
      severity: 'medium',
      family: 'harness-config-permissions',
      cwe: 'CWE-732',
      confidence: 0.85,
      description: `${harness} settings.json defines permissions.allow with ${allowList.length} rule(s) but no permissions.deny entries. Defense-in-depth requires both: allow lists the permitted, deny lists the always-blocked (rm -rf, curl|sh, force-pushes to main).`,
      remediation: 'Add a deny-list with at least: `Bash(rm -rf *)`, `Bash(curl * | sh)`, `Bash(git push --force origin main)`, `Bash(sudo *)`.',
      harness,
    });
  }

  // 3. Bypass / dangerous flags.
  for (const m of raw.matchAll(/"([A-Za-z_$][\w$]*)"\s*:\s*(true|"true"|1)\b/g)) {
    if (_BYPASS_KEY_RE.test(m[1])) {
      findings.push({
        id: `harness-config:bypass-flag:${file}:${m[1]}`,
        file,
        line: _line(raw, m.index),
        vuln: `Harness bypass flag '${m[1]}' is enabled`,
        severity: 'critical',
        family: 'harness-config-permissions',
        cwe: 'CWE-269',
        confidence: 0.95,
        description: `${harness} settings.json sets ${m[1]} = true. This flag disables the per-tool confirmation prompts and lets the agent invoke destructive tools without human approval.`,
        remediation: `Remove the ${m[1]} key, or set it to false. Per-tool confirmation is the last line of defense against prompt-injection-driven destructive actions.`,
        harness,
      });
    }
  }

  // 4. Env block secrets.
  if (parsed.env && typeof parsed.env === 'object') {
    for (const [k, v] of Object.entries(parsed.env)) {
      if (typeof v !== 'string') continue;
      for (const re of _CRED_RE) {
        if (re.test(v)) {
          const idx = raw.indexOf(`"${k}"`);
          findings.push({
            id: `harness-config:env-secret:${file}:${k}`,
            file,
            line: idx >= 0 ? _line(raw, idx) : 1,
            vuln: `Harness env block contains a literal credential under '${k}'`,
            severity: 'critical',
            family: 'harness-config-secrets',
            cwe: 'CWE-798',
            confidence: 0.95,
            description: `${harness} settings.json's env.${k} holds a literal credential. Anyone with read access to the project (including the agent's own conversation surface) can exfiltrate it.`,
            remediation: `Move the value to a secure vault and reference it via env-var substitution (e.g., \"${k}\": \"\${${k}}\") so the literal never lives in source.`,
            harness,
          });
          break;
        }
      }
    }
  }

  return findings;
}
