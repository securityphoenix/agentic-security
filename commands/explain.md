---
description: Explain a finding in plain English — what, how attackers abuse it, worst case, fix. Also --provenance and --gap modes.
argument-hint: "[--finding <id>] [--narrative] [--provenance] [--gap <CWE>]"
---

Explain a security finding in plain English. The user can pass:

- A finding id (`struct:src/api.js:42:SQL_Injection`)
- A CWE number (`CWE-89` or just `89`)
- A vuln name fragment (`SQL Injection`)

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
node -e "
const fs = require('fs');
const path = require('path');

const arg = (process.argv[1] || '').trim();
if (!arg) {
  console.error('Usage: /explain <finding-id | CWE-89 | vuln-name>');
  console.error('  Example: /explain CWE-89');
  console.error('  Example: /explain SQL Injection');
  process.exit(1);
}

const pluginRoot = process.env.CLAUDE_PLUGIN_ROOT || path.dirname(path.dirname(__filename));
const explainerPath = path.join(pluginRoot, 'data', 'cwe-explainer.json');
let explainer = {};
try { explainer = JSON.parse(fs.readFileSync(explainerPath, 'utf8')); } catch (e) {
  console.error('Could not load CWE explainer table from ' + explainerPath);
  process.exit(1);
}

let scan = null;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}

// Resolve the input to a finding (or just a CWE)
let finding = null;
let cweKey = null;
const argLower = arg.toLowerCase();

// Try as CWE first
const cweMatch = arg.match(/CWE[-_]?(\d+)/i) || arg.match(/^(\d+)\$/);
if (cweMatch) cweKey = 'CWE-' + cweMatch[1];

// If we have a scan, try to match a finding by id, vuln name, or CWE
if (scan && Array.isArray(scan.findings)) {
  finding =
    scan.findings.find(f => f.id === arg) ||
    scan.findings.find(f => (f.id || '').includes(arg)) ||
    (cweKey && scan.findings.find(f => f.cwe === cweKey)) ||
    scan.findings.find(f => (f.vuln || '').toLowerCase().includes(argLower));
  if (finding && !cweKey) cweKey = finding.cwe;
}

const explainEntry = cweKey ? explainer[cweKey] : null;

// Render
const W = (s, code) => process.stdout.isTTY ? \`\\x1b[\${code}m\${s}\\x1b[0m\` : s;
const BOLD = '1', RED = '31', YELLOW = '33', CYAN = '36', DIM = '2';

console.log('');
if (finding) {
  console.log(W('━━━ ' + (finding.vuln || 'Finding') + ' ━━━', BOLD));
  console.log(\`File:     \${finding.file}:\${finding.line}\`);
  console.log(\`Severity: \${W(finding.severity.toUpperCase(), finding.severity === 'critical' ? RED : finding.severity === 'high' ? YELLOW : CYAN)}\`);
  if (finding.cwe) console.log(\`CWE:      \${finding.cwe}\`);
  if (finding.toxicity != null) console.log(\`Toxicity: \${finding.toxicity}/100 (\${finding.toxicityLabel || ''})\`);
  if (finding.kev) console.log(\`KEV:      \${W('Yes — actively abused in the wild', RED)}\`);
  console.log('');
} else if (cweKey) {
  console.log(W('━━━ ' + cweKey + (explainEntry ? ': ' + explainEntry.name : '') + ' ━━━', BOLD));
  console.log(W('(Generic explanation — no specific finding matched.)', DIM));
  console.log('');
} else {
  console.error(\`No finding or CWE matched '\${arg}'.\`);
  console.error('Run /scan --all first, then /explain <finding-id>.');
  process.exit(1);
}

if (explainEntry) {
  console.log(W('What this means', BOLD));
  console.log('  ' + explainEntry.risk);
  console.log('');
  console.log(W('How an attacker abuses it', BOLD));
  for (const line of explainEntry.attackerStory.match(/.{1,90}(\\s|\$)/g) || [explainEntry.attackerStory]) console.log('  ' + line.trim());
  console.log('');
  console.log(W('Worst case if not fixed', BOLD));
  for (const line of explainEntry.worstCase.match(/.{1,90}(\\s|\$)/g) || [explainEntry.worstCase]) console.log('  ' + line.trim());
  console.log('');
  console.log(W('How to fix it', BOLD));
  for (const line of explainEntry.fix.match(/.{1,90}(\\s|\$)/g) || [explainEntry.fix]) console.log('  ' + line.trim());
  console.log('');
} else {
  // Fallback to the finding's own fix description if we don't have a plain-English entry
  if (finding && finding.fix) {
    console.log(W('Fix recommendation (from scanner)', BOLD));
    const text = typeof finding.fix === 'string' ? finding.fix : (finding.fix.description || JSON.stringify(finding.fix));
    for (const line of text.match(/.{1,90}(\\s|\$)/g) || [text]) console.log('  ' + line.trim());
    console.log('');
  } else {
    console.log(W('No plain-English explainer for ' + (cweKey || arg) + ' yet.', DIM));
    console.log(W('The top 30 CWEs cover ~85% of findings; this one falls outside that set.', DIM));
    console.log('');
  }
}

if (finding) {
  console.log(W('What to do now', BOLD));
  console.log('  Apply the fix:    /agentic-security:security-fix ' + finding.id);
  console.log('  See in context:   open ' + finding.file);
  if (finding.severity === 'critical' || finding.severity === 'high') {
    console.log('  Generate PoC:     /agentic-security:validate-findings ' + finding.id);
  }
  console.log('');
}
" -- "$1"
```

Print the output verbatim. The user wants the explanation as a single self-contained card.

---

## `--narrative` mode (formerly `/story-explain`)

When the user passes `--narrative`, do NOT run the bash block above. Instead,
generate a short attack-story rendering. The post-mortem variant is the same
shape with past-tense + remediation footer.

### Audience

- **Vibecoders** building first intuition for what an attack actually looks like.
- **Security pros** writing the exec readout, post-mortem narrative, or customer-incident communication where CWE jargon will lose the reader.

### Tone rules

- **Present tense, third-person.** "Mallory opens", not "an attacker would open".
- **Specific, not abstract.** If the bug is in `GET /api/users/:id`, name that URL.
- **Concrete values.** Show an actual payload like `?id=2`, not `?id=<some-other-id>`.
- **Costs in $.** Tie consequences to money where possible.
- **No "could" — say "does".** Past conditional is for legal disclaimers.
- **No security acronyms in the story body.** Save "IDOR / CWE-639 / OWASP A01" for the footer.

### Structure

```
─── Story: <Vuln> at <file>:<line> ─────────────────────────────

Setup           — 2 sentences: what this app does, where the vuln sits.
Meet <Name>     — 1 sentence on attacker motivation (bored teen / fraudster / competitor / etc.)
The attack     — numbered, present-tense steps with concrete payloads
The aftermath  — first ticket / first media post / regulatory clock / cost estimate
What stops this — the literal 2–3 line code change

─── /explain --narrative ──────────────────────────────────────
  CWE: <X>   |   OWASP: <Y>   |   Severity: <Z>
  Run /fix --one <id> to apply the fix.
```

### Persona × vuln-class table

| Vuln class | Attacker persona | Story arc |
|---|---|---|
| SQL Injection | competitor doing recon | finds login → injects → dumps users → leak site |
| IDOR | curious user, then fraudster | changes ID → reads others → builds scraper |
| XSS (stored) | griefer, then phisher | posts script → logs every viewer's session |
| Open Redirect | phisher | victim → real domain → fake login → creds |
| Hardcoded API key | bot scraping github | bot finds key in minutes → racks bill |
| Prompt Injection | researcher, then competitor | review/PDF payload → agent leaks system prompt |
| Missing rate limit | scaling bug, then abuse | one buggy client → 50k req/min → DoS |
| Path Traversal | attacker hunting secrets | reads `../../../.env` → AWS keys → cloud bill |
| SSRF | researcher | hits 169.254.169.254 → IAM creds → GPU instances |
| Service-role on client | curious user | inspects bundle → admin DB from a browser tab |

### `--post-mortem`

Adds `--narrative --post-mortem`. Renders in past tense ("Mallory opened…"),
suppresses the CLI mascot footer, and appends a **"What we shipped"** block
reading from `.agentic-security/fix-history/` (most recent commit touching
the affected file) plus any matching `/validate-findings` cache entry.
Output is clean enough to paste into a Notion doc or a customer email.

### Don't

- No generic boilerplate. Mention THIS file, THIS function, THIS endpoint.
- No moralizing. The reader knows it's bad. Show why.
- No mustache-twirling attackers. Bots and bored teenagers are the realistic ones.
- No cliffhangers. End with the fix.

---

## `--provenance` mode (formerly `/why-fired`)

When the user passes `--provenance --finding <id>`, do NOT run the standard explain bash block. Instead run:

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
node -e "
const fs = require('fs');
let scan;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); }
catch { console.log('No scan yet. Run /scan first.'); process.exit(0); }
const id = process.argv[1] || '';
if (!id) { console.log('Usage: /explain --provenance --finding <id-or-stableId>'); process.exit(1); }
const f = (scan.findings || []).find(x => x.id === id || x.stableId === id);
if (!f) { console.log('No finding matches ' + id + '. Use /show-findings --all to browse.'); process.exit(0); }
const w = f.whyFired;
if (!w) { console.log('Finding has no whyFired record. Re-run /scan with v0.52+.'); process.exit(0); }
const W = (s,c) => process.stdout.isTTY ? '\x1b['+c+'m'+s+'\x1b[0m' : s;
const BOLD='1', DIM='2';
console.log('');
console.log(W('Provenance: ' + (f.vuln || ''), BOLD));
console.log(W('  ' + f.file + ':' + f.line + ' [' + (f.severity || '').toUpperCase() + ']', DIM));
console.log('');
console.log(W('Detector:        ', BOLD) + w.detector);
console.log(W('Rule ID:         ', BOLD) + w.ruleId);
console.log(W('Parser:          ', BOLD) + w.parser);
if (w.scanner && w.scanner.rulesetVersion) console.log(W('Rule pack:       ', BOLD) + w.scanner.rulesetVersion);
console.log('');
console.log(W('Evidence', BOLD));
if (w.evidence.sourceSnippet) console.log('  ' + W('source: ', DIM) + w.evidence.sourceSnippet.slice(0, 80));
if (w.evidence.sinkSnippet)   console.log('  ' + W('sink:   ', DIM) + w.evidence.sinkSnippet.slice(0, 80));
if (w.evidence.pathSteps && w.evidence.pathSteps.length) {
  console.log('  ' + W('flow:', DIM));
  for (const s of w.evidence.pathSteps.slice(0, 8)) console.log('    → ' + s.type + ' ' + (s.label || ''));
}
console.log('  ' + W('sanitizers considered: ', DIM) + (w.evidence.sanitizers.length ? w.evidence.sanitizers.join(', ') : '(none rejected)'));
console.log('  ' + W('guards observed:       ', DIM) + (w.evidence.guards.length ? w.evidence.guards.join(', ') : '(none)'));
console.log('');
console.log(W('What the engine considered', BOLD));
console.log('  reachability filter:    ' + w.considered.reachabilityFilter);
console.log('  cluster collapsed:      ' + (w.considered.clusterCollapsed ? 'yes' : 'no'));
console.log('  type-narrowed:          ' + (w.considered.typeNarrowed ? 'yes' : 'no'));
console.log('  crown-jewel tier:       ' + (w.considered.crownJewelTier || '(unscored)'));
console.log('  production verdict:     ' + (w.considered.mitigationVerdict || '(no prod context)'));
console.log('  suppressions applied:   ' + (w.considered.suppressionsApplied.length ? w.considered.suppressionsApplied.join(', ') : '(none)'));
console.log('  suppressions skipped:   ' + (w.considered.suppressionsSkipped.length ? w.considered.suppressionsSkipped.join(', ') : '(none)'));
console.log('');
if (f.exploitabilityFactors) console.log(W('Exploitability factors:  ', BOLD) + f.exploitabilityFactors.join(', '));
if (f.calibrated_confidence != null) console.log(W('Calibrated confidence:   ', BOLD) + (f.calibrated_confidence * 100).toFixed(1) + '%');
console.log('');
" -- "$2"
```

Print the output as-is. The provenance graph tells the security engineer *exactly* why the engine emitted this finding.

---

## `--gap` mode (formerly `/why-not`)

When the user passes `--gap <CWE>`, do NOT run the standard explain bash block. Instead run:

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
node -e "
const fs = require('fs');
const arg = (process.argv[1] || '').trim();
if (!arg) { console.error('Usage: /explain --gap <CWE> (e.g. CWE-89 or 89 or sql-injection)'); process.exit(1); }
let scan;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); }
catch { console.error('No last-scan.json found. Run /scan --all first.'); process.exit(1); }
const W = (s, code) => process.stdout.isTTY ? \`\\x1b[\${code}m\${s}\\x1b[0m\` : s;
const CWE_TO_FAMILY = {
  'CWE-89': 'sql-injection', 'CWE-79': 'xss', 'CWE-78': 'command-injection',
  'CWE-22': 'path-traversal', 'CWE-918': 'ssrf', 'CWE-611': 'xxe',
  'CWE-502': 'insecure-deserialization', 'CWE-94': 'code-injection',
  'CWE-915': 'mass-assignment', 'CWE-1321': 'prototype-pollution',
  'CWE-352': 'csrf', 'CWE-367': 'toctou', 'CWE-90': 'ldap-injection',
  'CWE-643': 'xpath-injection', 'CWE-943': 'nosql-injection',
  'CWE-601': 'open-redirect', 'CWE-798': 'hardcoded-secret',
  'CWE-327': 'weak-crypto', 'CWE-330': 'weak-rng', 'CWE-613': 'jwt-no-exp',
};
const FAMILY_ALIAS = { sql:'sql-injection', xss:'xss', cmd:'command-injection',
  command:'command-injection', csrf:'csrf', ssrf:'ssrf', idor:'idor', xxe:'xxe', deser:'insecure-deserialization' };
let cwe = null, family = null;
const m = arg.match(/(?:CWE[-_]?)(\\d+)/i) || arg.match(/^(\\d+)$/);
if (m) { cwe = 'CWE-' + m[1]; family = CWE_TO_FAMILY[cwe] || null; }
else { family = FAMILY_ALIAS[arg.toLowerCase()] || arg.toLowerCase(); for (const [k, v] of Object.entries(CWE_TO_FAMILY)) if (v === family) { cwe = k; break; } }
console.log('');
console.log(W('━━━ Why not: ' + (cwe || family || arg) + ' ━━━', '1'));
console.log('');
const matched = (scan.findings || []).filter(f => (cwe && f.cwe === cwe) || (family && f.family === family));
if (matched.length) {
  console.log(W('Actually, this CWE WAS flagged — ' + matched.length + ' finding(s):', '32'));
  for (const f of matched.slice(0, 5)) console.log('  · ' + f.vuln + '  →  ' + (f.file || '?') + ':' + (f.line || '?'));
  if (matched.length > 5) console.log('  · ... and ' + (matched.length - 5) + ' more.');
  process.exit(0);
}
const allSrc = scan.sources || []; const allSink = scan.sinks || [];
const sourcesOfFamily = allSrc.filter(s => (s.family || '').includes(family || '_NONE_'));
const sinksOfFamily = allSink.filter(s => (s.family || '').includes(family || '_NONE_'));
console.log(W('Considered for this CWE:', '1'));
console.log('  Sources matching this family:    ' + sourcesOfFamily.length);
console.log('  Sinks matching this family:      ' + sinksOfFamily.length);
const suppressions = (scan.suppressions || []).filter(s => {
  const r = (s.reason || '').toLowerCase();
  return r.includes(family || '_NONE_') || r.includes(cwe?.toLowerCase() || '_NONE_');
});
console.log('  Suppressed candidate findings:   ' + suppressions.length);
console.log('');
console.log(W('Why no finding:', '1'));
if (sourcesOfFamily.length === 0 && sinksOfFamily.length === 0) {
  console.log('  · No sources OR sinks of this family detected. Either the code path');
  console.log('    doesn\\'t exist, or the catalog doesn\\'t know your framework\\'s entry points.');
} else if (sourcesOfFamily.length === 0) {
  console.log('  · Sinks present, but no untrusted source flows into them.');
} else if (sinksOfFamily.length === 0) {
  console.log('  · Sources present, but they don\\'t flow into any sink of this family.');
} else if (suppressions.length > 0) {
  console.log('  · Candidates were generated but suppressed. Top reasons:');
  const byReason = new Map();
  for (const s of suppressions.slice(0, 50)) byReason.set(s.reason, (byReason.get(s.reason) || 0) + 1);
  for (const [r, n] of [...byReason.entries()].sort((a,b)=>b[1]-a[1]).slice(0,5)) console.log('       · ' + r + ' (' + n + 'x)');
} else {
  console.log('  · Sources and sinks both seen, but no taint path linked them.');
  console.log('    This is a recall gap — consider posting the file path for triage.');
}
console.log('');
" -- "$2"
```

Print the output as-is. The gap analysis tells the user why the engine did NOT fire for a CWE they expected.
