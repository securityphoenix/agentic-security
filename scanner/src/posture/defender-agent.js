// Blue-team / defender agent — Phase 2 of the three-agent review pipeline.
//
// Reads the red team's attack transcript (from adversary-agent.js) and
// proposes hardening: which controls would have blocked each tool call,
// what code changes mitigate the chain, what runtime guard would have
// fired, and which deferred items can be closed under the current threat
// posture.
//
// Interface mirrors adversary-agent.js — bounded LLM invocations, ACL'd
// tool set (read-only this time: no http.post, no db writes), hash-chained
// transcript. Without a configured LLM endpoint, runDefender short-circuits
// to a structured "no-llm-endpoint" output that still includes the static
// hardening recommendations derived from the attack transcript.

import * as crypto from 'node:crypto';

const TOOL_ACL = new Set([
  'read_finding',
  'read_control_inventory',
  'recommend_hardening',
  'record_defense',
]);

const STATIC_HARDENING_BY_FAMILY = {
  'sql-injection': [
    'Switch to parameterized queries (placeholder via ? or $1) — never concatenate user-controlled strings into SQL.',
    'Add a runtime WAF rule for SQLi shape at the edge.',
    'Add a per-request audit log entry that includes the bound parameter set.',
  ],
  'command-injection': [
    'Replace exec/system with spawn/execFile passing argv as an array.',
    'Add an allow-list of permitted commands; reject any value containing `;` `|` `&` ``` $`.',
    'Run the receiving service under a non-root user with a sealed PATH.',
  ],
  'xss': [
    'Output-encode at the sink — DOMPurify or templating-engine auto-escape.',
    'Set Content-Security-Policy headers with a strict default-src.',
    'For React: never call dangerouslySetInnerHTML on user input.',
  ],
  'ssrf': [
    'Resolve user-supplied URLs to an IP and reject 169.254.169.254, 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7.',
    'Pin the resolver before the HTTP client uses it (TOCTOU window).',
    'Block the cloud-metadata IP at the egress network policy layer.',
  ],
  'idor': [
    'Compare the requested resource owner to req.user.id on every read.',
    'Use an ORM scope that filters by tenantId/orgId at the query level — not at the controller.',
    'Add an integration test that authenticates as user A and tries to read user B\'s resource.',
  ],
  'broken-auth': [
    'Enforce JWT algorithm allow-list (HS256 OR RS256, never `none`).',
    'Verify signature BEFORE reading claims.',
    'Rotate the signing key on a schedule and revoke old keys.',
  ],
  'hardcoded-secret': [
    'Rotate the leaked credential immediately.',
    'Move all secrets to a vault and reference via env-var.',
    'Add a pre-commit hook that runs `/scan --secrets` on the diff.',
  ],
  'hook-command-injection': [
    'Pass agent-controlled values via stdin or a sandboxed env var, never shell-interpolation.',
    'Wrap the receiving program in single-quotes if the value must appear on the command line.',
    'Validate the value against a strict allow-list before the hook runs.',
  ],
  'harness-config-permissions': [
    'Replace wildcard rules (Bash(*), *) with scoped allow-list entries.',
    'Add a deny-list with at least: Bash(rm -rf *), Bash(curl * | sh), Bash(sudo *), Bash(git push --force origin main).',
    'Remove dangerouslySkipPermissions / bypassAll / autoApprove flags.',
  ],
  'agent-prompt-injection': [
    'Quarantine instruction files (CLAUDE.md, AGENTS.md) sourced from untrusted origin.',
    'Remove override / role-rewriting directives.',
    'Audit instruction files in CI with /scan --harness on every PR.',
  ],
};

function _familyOf(f) {
  if (!f) return null;
  if (f.family) return String(f.family).toLowerCase();
  const v = (f.vuln || '').toLowerCase();
  if (/sql.*injection/.test(v)) return 'sql-injection';
  if (/command.*injection/.test(v)) return 'command-injection';
  if (/xss/.test(v)) return 'xss';
  if (/ssrf/.test(v)) return 'ssrf';
  if (/idor/.test(v)) return 'idor';
  if (/broken.auth|jwt/.test(v)) return 'broken-auth';
  if (/hardcoded/.test(v)) return 'hardcoded-secret';
  if (/hook.*command/.test(v)) return 'hook-command-injection';
  return null;
}

function chainHash(prev, entry) {
  const h = crypto.createHash('sha256');
  h.update(prev || '');
  h.update(JSON.stringify(entry));
  return h.digest('hex').slice(0, 16);
}

export function staticHardeningFor(finding) {
  const fam = _familyOf(finding);
  if (!fam) return [];
  return STATIC_HARDENING_BY_FAMILY[fam] || [];
}

function startDefenderTranscript(finding, redTeamTranscript) {
  const seed = {
    seedFinding: {
      stableId: finding?.stableId || null,
      file: finding?.file || null,
      line: finding?.line || null,
      vuln: finding?.vuln || null,
      family: finding?.family || null,
    },
    redOutcome: redTeamTranscript?.outcome || null,
    redCallCount: (redTeamTranscript?.entries || []).filter(e => e.tool).length,
    startedAt: new Date().toISOString(),
    entries: [],
    chainHead: '',
  };
  seed.chainHead = chainHash('', seed.seedFinding);
  return seed;
}

function appendDefenderEntry(transcript, entry) {
  if (!transcript || !entry) return;
  if (entry.tool && !TOOL_ACL.has(entry.tool)) {
    entry = { ...entry, refused: true, refusedReason: `tool '${entry.tool}' not in defender ACL` };
  }
  transcript.chainHead = chainHash(transcript.chainHead, entry);
  transcript.entries.push({ ...entry, hash: transcript.chainHead });
}

// Run defender on a finding + the red team's transcript. Without an LLM
// endpoint, returns the static-hardening list (still useful — it's the
// minimum baseline guidance).
export async function runDefender(finding, redTeamTranscript, opts = {}) {
  const transcript = startDefenderTranscript(finding, redTeamTranscript);
  const staticAdvice = staticHardeningFor(finding);
  appendDefenderEntry(transcript, {
    phase: 'static-analysis',
    family: _familyOf(finding),
    recommendations: staticAdvice,
  });
  if (typeof opts.llmInvoke !== 'function' || !process.env.AGENTIC_SECURITY_LLM_ENDPOINT) {
    appendDefenderEntry(transcript, { phase: 'init', reason: 'no llmInvoke supplied / AGENTIC_SECURITY_LLM_ENDPOINT not set — static hardening only' });
    return { transcript, recommendations: staticAdvice, mode: 'static-only' };
  }
  try {
    const llmRec = await opts.llmInvoke(transcript);
    appendDefenderEntry(transcript, { phase: 'llm-defense', recommendations: llmRec });
    return { transcript, recommendations: [...staticAdvice, ...(Array.isArray(llmRec) ? llmRec : [])], mode: 'llm-augmented' };
  } catch (e) {
    appendDefenderEntry(transcript, { phase: 'llm-error', error: String(e?.message || e) });
    return { transcript, recommendations: staticAdvice, mode: 'static-fallback' };
  }
}

export { TOOL_ACL };
