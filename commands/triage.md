---
description: Interactive triage mode. Walk through the latest scan's ranked findings and mark each as true-positive, false-positive, or won't-fix. Decisions feed the active-learning loop so the next scan suppresses learned FPs.
argument-hint: "[<finding-id>]"
---

Interactive triage. By default cycles through every finding in the last scan ranked by exploitability + confidence. Pass a `<finding-id>` to triage a single finding directly.

The user's verdicts are persisted to `.agentic-security/triage-feedback.json` and read by the engine's active-learning loop on the next scan (FR-PREC-4): findings whose `stableId` was previously marked `fp` are suppressed; findings marked `tp` get a confidence boost.

```bash
node -e "
const fs = require('fs');
const path = require('path');
const readline = require('readline');

const arg = (process.argv[1] || '').trim();
let scan;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); }
catch (e) { console.error('No last-scan.json found. Run /scan --all first.'); process.exit(1); }

let findings = (scan.findings || []).slice();
if (arg) findings = findings.filter(f => f.id === arg || (f.id || '').includes(arg) || f.stableId === arg);
if (!findings.length) { console.error('No findings to triage.'); process.exit(0); }

findings.sort((a,b) => (b.exploitability||0) - (a.exploitability||0) || (b.confidence||0) - (a.confidence||0));

const FEEDBACK = '.agentic-security/triage-feedback.json';
let feedback = { entries: [] };
try { feedback = JSON.parse(fs.readFileSync(FEEDBACK, 'utf8')); } catch {}
feedback.entries = feedback.entries || [];

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = q => new Promise(res => rl.question(q, ans => res(ans.trim())));

(async () => {
  const W = (s, code) => process.stdout.isTTY ? \`\\x1b[\${code}m\${s}\\x1b[0m\` : s;
  let i = 0;
  while (i < findings.length) {
    const f = findings[i];
    console.log('');
    console.log(W('─'.repeat(72), '2'));
    console.log(\`[\${i+1}/\${findings.length}] \` + W(f.vuln || '(unnamed)', '1'));
    console.log(\`  File:           \${f.file || '(none)'}:\${f.line || '?'}\`);
    console.log(\`  Severity:       \${f.severity}  ·  Exploitability: \${f.exploitability ?? '?'}  ·  Confidence: \${f.confidence ?? '?'}\`);
    if (f.cwe) console.log(\`  CWE:            \${f.cwe}\`);
    if (f.stableId) console.log(\`  Stable ID:      \${f.stableId}\`);
    if (f.snippet) console.log(\`  Snippet:        \${(f.snippet || '').slice(0, 80)}\`);
    console.log('');
    const ans = (await ask('  [t]p · [f]p · [w]ontfix · [n]ext · [p]rev · [s]kip · [q]uit ? ')).toLowerCase();
    if (ans === 'q') break;
    if (ans === 'n' || ans === 's') { i++; continue; }
    if (ans === 'p') { i = Math.max(0, i - 1); continue; }
    if (['t','f','w'].includes(ans)) {
      const reason = (await ask('  Reason (optional): ')).slice(0, 280);
      const verdict = ans === 't' ? 'tp' : ans === 'f' ? 'fp' : 'wontfix';
      feedback.entries.push({
        stableId: f.stableId || null,
        verdict, reason,
        family: f.family || null,
        file: f.file || null, line: f.line || null, vuln: f.vuln || null,
        sinkSnippet: (f.sink?.snippet || f.snippet || '').slice(0, 200),
        at: new Date().toISOString(),
      });
      fs.mkdirSync(path.dirname(FEEDBACK), { recursive: true });
      fs.writeFileSync(FEEDBACK, JSON.stringify(feedback, null, 2));
      console.log(W('  ✓ recorded ' + verdict, '32'));
      i++; continue;
    }
    console.log('  (unrecognized — try t/f/w/n/p/s/q)');
  }
  rl.close();
  console.log('');
  console.log(W('Triage feedback saved to ' + FEEDBACK, '2'));
  console.log(W(\`\${feedback.entries.length} total entries — applied on next /scan run.\`, '2'));
})();
" -- "$1"
```

Tell the user how many verdicts were recorded and remind them the suppressions take effect on the next `/scan`.
