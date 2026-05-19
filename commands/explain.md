---
description: Explain a finding in plain English — what, how attackers abuse it, worst case, fix. --narrative for story shape.
argument-hint: "[--finding <id>] [--narrative]"
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
