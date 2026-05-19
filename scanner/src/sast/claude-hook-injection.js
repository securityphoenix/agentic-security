// Hook command-injection audit.
//
// Reads .claude/hooks.json (and equivalents in .cursor/, .codex/, etc.) and
// flags the canonical bugs:
//
//   1. Interpolation of attacker-controlled fields (${file}, ${input},
//      ${args}, $CLAUDE_TOOL_INPUT, $TOOL_INPUT, $PROMPT) directly into a
//      shell command without quoting. When the agent passes a filename
//      `; rm -rf ~` to a tool, the hook executes it as shell.
//   2. Silent error suppression in security-relevant hooks (`2>/dev/null`,
//      `|| true`, `set +e`) — the hook fails open and the user never sees it.
//   3. Outbound HTTP (curl / wget / nc) from a hook to a non-local URL.
//      Often a sign of an injected data-exfil command.
//   4. Privilege-escalating shells (sudo, doas, runuser, su) in hooks.
//   5. Eval / source / bash -c on dynamic content.
//
// Hook config shape (Claude Code):
//   {
//     "hooks": {
//       "PreToolUse": [
//         { "matcher": "Bash", "hooks": [{ "type": "command", "command": "..." }] }
//       ]
//     }
//   }
//
// We walk every `command` field and apply the rules. Adjacent harnesses use
// the same key in their settings or their own hooks file; we also walk any
// `*.hooks.json` and `hooks.json` under a harness directory.

const _HOOK_FILE_RE = /(?:^|[\\/])(?:hooks?\.json|\.(?:claude|cursor|codex|gemini|kiro|opencode|trae|qwen|zed|continue|aider)[\\/](?:hooks\.json|settings(?:\.local)?\.json))$/i;

// Tokens that can carry agent-driven payloads (untrusted input).
const _INTERPOLATION_TOKENS = [
  '${file}', '${input}', '${args}', '${path}', '${target}',
  '${tool_input}', '${prompt}', '${query}', '${message}',
  '$CLAUDE_TOOL_INPUT', '$TOOL_INPUT', '$INPUT', '$PROMPT', '$ARGS',
  '$CLAUDE_PROMPT', '$CLAUDE_ARGS', '$CLAUDE_FILE',
  '$AGENT_INPUT', '$AGENT_PROMPT',
];

const _SHELL_SUPPRESS_RE = /(?:2>\s*\/dev\/null|>\s*\/dev\/null\s+2>&1|\|\|\s*true|set\s+\+e)/;
const _OUTBOUND_HTTP_RE = /\b(?:curl|wget|nc|ncat|fetch)\b[^\n;|&]*?https?:\/\/(?!(?:127\.0\.0\.1|localhost|0\.0\.0\.0))[^\s'"]+/i;
const _PRIVESC_RE = /\b(?:sudo|doas|runuser|su\s+-)\b/;
const _EVAL_RE = /\b(?:eval|source|bash\s+-c|sh\s+-c|zsh\s+-c)\s+["'`]?[^"'`]*\$(?:\{[^}]+\}|[A-Z_][A-Z0-9_]*)/i;

function _line(raw, idx) {
  return raw.slice(0, idx).split('\n').length;
}

function _isQuoted(command, tokenIdx, token) {
  // Heuristic: check whether the token is inside a single-quoted span.
  // Single-quoted bash is the only safe-from-expansion form; double quotes
  // still substitute and let `; ` break out.
  let quote = null;
  for (let i = 0; i < tokenIdx; i++) {
    const c = command[i];
    if (quote === null) {
      if (c === "'") quote = "'";
      else if (c === '"') quote = '"';
    } else if (c === quote) {
      quote = null;
    }
  }
  return quote === "'";
}

function _walkCommands(node, out, pathPrefix = '') {
  if (!node || typeof node !== 'object') return;
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) _walkCommands(node[i], out, `${pathPrefix}[${i}]`);
    return;
  }
  for (const [k, v] of Object.entries(node)) {
    if (k === 'command' && typeof v === 'string') {
      out.push({ command: v, jsonPath: `${pathPrefix}.${k}` });
    } else if (k === 'commands' && Array.isArray(v)) {
      for (let i = 0; i < v.length; i++) {
        if (typeof v[i] === 'string') out.push({ command: v[i], jsonPath: `${pathPrefix}.${k}[${i}]` });
      }
    } else {
      _walkCommands(v, out, `${pathPrefix}.${k}`);
    }
  }
}

export function scanClaudeHookInjection(file, raw) {
  if (!file || !raw || typeof raw !== 'string') return [];
  if (!_HOOK_FILE_RE.test(file)) return [];
  if (raw.length > 200_000) return [];

  let parsed;
  try { parsed = JSON.parse(raw); } catch { return []; }
  if (!parsed || typeof parsed !== 'object') return [];

  const commands = [];
  _walkCommands(parsed.hooks || parsed, commands);
  if (!commands.length) return [];

  const findings = [];
  for (const { command, jsonPath } of commands) {
    // The line where this command lives in raw — best effort by searching
    // for the command substring (works because raw JSON preserves the text).
    const idx = raw.indexOf(command);
    const line = idx >= 0 ? _line(raw, idx) : 1;

    // 1. Interpolation of untrusted tokens, unquoted.
    for (const tok of _INTERPOLATION_TOKENS) {
      const ti = command.indexOf(tok);
      if (ti < 0) continue;
      if (_isQuoted(command, ti, tok)) continue;        // single-quoted is safe
      findings.push({
        id: `hook-injection:interpolation:${file}:${line}:${tok}`,
        file,
        line,
        vuln: `Hook command interpolates untrusted '${tok}' unquoted — shell injection`,
        severity: 'critical',
        family: 'hook-command-injection',
        cwe: 'CWE-78',
        confidence: 0.85,
        description: `The hook at ${jsonPath} embeds ${tok} directly into a shell command. If an agent (or a prompt-injected tool) passes a path containing ; rm -rf $HOME, the shell executes it. Even double-quoting does not fix this — backslash and dollar still allow escape.`,
        remediation: 'Pass the value via stdin or a sandboxed env var. If it must appear in the command line, wrap the receiving program in single-quotes and use \\\'\\\'\\\'\\\' for embedded literal quotes, or pre-validate the value against a strict allow-list before the hook runs.',
        snippet: command.slice(Math.max(0, ti - 20), ti + tok.length + 30),
      });
    }

    // 2. Silent error suppression on security hooks.
    if (_SHELL_SUPPRESS_RE.test(command)) {
      // Only flag when the hook is a security-relevant one. PostToolUse +
      // PreToolUse hooks that fail silently disable the guardrail. We can't
      // perfectly tell purpose, so emit at medium severity.
      findings.push({
        id: `hook-injection:silent-suppress:${file}:${line}`,
        file,
        line,
        vuln: `Hook silently swallows errors (fails open)`,
        severity: 'medium',
        family: 'hook-command-injection',
        cwe: 'CWE-754',
        confidence: 0.7,
        description: `The hook command redirects stderr to /dev/null or appends '|| true' / 'set +e'. If the hook's purpose is to enforce a check, swallowing its non-zero exit means a failure passes silently — the user thinks the guardrail ran.`,
        remediation: 'Let the hook fail loudly. If you genuinely need to ignore one specific error, narrow the suppression to that case rather than the whole pipeline.',
        snippet: command.slice(0, 120),
      });
    }

    // 3. Outbound HTTP from a hook.
    if (_OUTBOUND_HTTP_RE.test(command)) {
      findings.push({
        id: `hook-injection:outbound-http:${file}:${line}`,
        file,
        line,
        vuln: `Hook makes outbound HTTP to a non-local URL`,
        severity: 'high',
        family: 'hook-command-injection',
        cwe: 'CWE-918',
        confidence: 0.8,
        description: `The hook fetches or posts to an external URL. Outbound traffic from a hook is the canonical data-exfiltration shape — every Edit / Write / Bash event triggers the hook.`,
        remediation: 'Replace with a local script if possible. If the outbound call is intentional (telemetry, webhook), redact the payload and restrict the destination to an allow-list.',
        snippet: command.slice(0, 120),
      });
    }

    // 4. Privilege-escalating commands.
    if (_PRIVESC_RE.test(command)) {
      findings.push({
        id: `hook-injection:privesc:${file}:${line}`,
        file,
        line,
        vuln: `Hook invokes a privilege-escalating command`,
        severity: 'high',
        family: 'hook-command-injection',
        cwe: 'CWE-269',
        confidence: 0.9,
        description: `The hook calls sudo / doas / runuser. Hooks fire automatically on agent events; combining auto-trigger with privilege escalation gives the agent root via a documented side door.`,
        remediation: 'Remove the privilege-escalation. If admin actions are genuinely needed, gate them behind a separate user-initiated command, not an auto-fire hook.',
        snippet: command.slice(0, 120),
      });
    }

    // 5. Eval / dynamic execution.
    if (_EVAL_RE.test(command)) {
      findings.push({
        id: `hook-injection:eval-dynamic:${file}:${line}`,
        file,
        line,
        vuln: `Hook eval()s dynamic content from a shell variable`,
        severity: 'critical',
        family: 'hook-command-injection',
        cwe: 'CWE-78',
        confidence: 0.85,
        description: `The hook passes a variable through eval / source / bash -c. Whatever is in that variable becomes shell code.`,
        remediation: 'Rewrite the hook to invoke the target binary directly with positional args. Never eval a value the agent can influence.',
        snippet: command.slice(0, 120),
      });
    }
  }

  return findings;
}
