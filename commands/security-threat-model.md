---
description: Render a threat model from the last scan. Use --stride for the STRIDE coverage table (default) or --llm for the OWASP LLM Top 10 (2025) coverage map.
argument-hint: "[--stride|--llm]"
---

Render a threat model from `.agentic-security/last-scan.json`.

- _(no args)_ or `--stride` — STRIDE coverage table (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
- `--llm` — OWASP LLM Top 10 (2025) coverage map

```bash
MODE="${1:---stride}"

if [ "$MODE" = "--llm" ]; then

node -e "
const fs = require('fs');
let scan;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); }
catch { console.log('No scan yet. Run /scan --all first.'); process.exit(0); }

const findings = scan.findings || [];
const supplyChain = scan.supplyChain || [];

const tag = (id) => (f) => f && f.owaspLlm === id;
const LLM_TOP_10 = [
  { id: 'LLM01', name: 'Prompt Injection',              matches: (f) => tag('LLM01')(f) || /prompt.injection|llm.+injection|llm-pi|MCP.+prompt|tool description|prompt template.+isolation/i.test(f.vuln || '') },
  { id: 'LLM02', name: 'Sensitive Information Disclosure', matches: (f) => tag('LLM02')(f) || /system.prompt.+(?:leak|exfil)|hardcoded.(?:secret|key|token|password)|CWE-200|information disclosure|api.key|sensitive.+log/i.test(f.vuln || '') || f.cwe === 'CWE-798' || f.cwe === 'CWE-200' },
  { id: 'LLM03', name: 'Supply Chain',                  matches: (f) => tag('LLM03')(f) || /typosquat|dep.confusion|dependency.confusion|floating tag|trust_remote_code|from_pretrained without pinned|http.+model|pickle\.load|joblib|yaml\.(?:load|unsafe)|allow_pickle/i.test(f.vuln || '') || f.cwe === 'CWE-1357' || f.cwe === 'CWE-494' || f.cwe === 'CWE-502' },
  { id: 'LLM04', name: 'Data and Model Poisoning',      matches: (f) => tag('LLM04')(f) || /trust_remote_code|untrusted.+install|curl.+sh|http.+model|allow_pickle|pickle.+load|poisoned.+dataset|backdoor.+trigger/i.test(f.vuln || '') },
  { id: 'LLM05', name: 'Improper Output Handling',      matches: (f) => tag('LLM05')(f) || /improper output handling|llm.output|unsafe.html|unsanitized.llm|response.+innerHTML|dangerouslySetInnerHTML.+llm|llm.+sql|llm.+exec|XSS.+llm|model instructed to emit/i.test(f.vuln || '') },
  { id: 'LLM06', name: 'Excessive Agency',              matches: (f) => tag('LLM06')(f) || /excessive agency|dangerous capability|tool.+(?:shell|exec|eval)|MCP.+(?:fs.overscope|dangerous|filesystem.+root|HOME)|excessive.+perm|write-all|action.+dispatch|unrestricted.+\(\)/i.test(f.vuln || '') },
  { id: 'LLM07', name: 'System Prompt Leakage',         matches: (f) => tag('LLM07')(f) || /system prompt leakage|system.prompt.+(?:leak|disclosure|reveal|exfil|reflected)|secrets embedded in (?:system )?prompt|prompt.+log/i.test(f.vuln || '') },
  { id: 'LLM08', name: 'Vector and Embedding Weaknesses', matches: (f) => tag('LLM08')(f) || /vector.+embedding weakness|(?:embedding|vector.store|rag).+(?:poison|injection|tainted|provenance)|untrusted.rag|mutable embedding store/i.test(f.vuln || '') },
  { id: 'LLM09', name: 'Misinformation',                matches: (f) => tag('LLM09')(f) || /misinformation.+(?:prompt|fabric)|fabricated specificity/i.test(f.vuln || '') },
  { id: 'LLM10', name: 'Unbounded Consumption',         matches: (f) => tag('LLM10')(f) || /unbounded consumption|rate.limit|denial.of.service|ReDoS|resource.exhaust|unbounded|GraphQL.+depth|no token budget|missing timeout/i.test(f.vuln || '') || f.cwe === 'CWE-400' || f.cwe === 'CWE-1333' },
];

const all = [...findings, ...supplyChain.filter(s => s.type === 'vulnerable_dep')];
const buckets = LLM_TOP_10.map(cat => ({ ...cat, findings: all.filter(f => cat.matches(f)) }));

const W = (s, code) => process.stdout.isTTY ? '\x1b[' + code + 'm' + s + '\x1b[0m' : s;
const BOLD = '1', GREEN = '32', YELLOW = '33', RED = '31', DIM = '2';

console.log('');
console.log(W('OWASP LLM Top 10 (2025) — Coverage Map', BOLD));
console.log(W('Source: https://genai.owasp.org/llm-top-10/', DIM));
console.log('');
console.log('| ID    | Category                                | Findings | Status |');
console.log('|-------|-----------------------------------------|----------|--------|');
let totalFindings = 0;
for (const b of buckets) {
  const n = b.findings.length;
  totalFindings += n;
  const status = b.id === 'LLM09' ? W('out of scope', DIM) : n === 0 ? W('no exposure', GREEN) : n > 5 ? W(n + ' findings', RED) : W(n + ' findings', YELLOW);
  console.log('| ' + b.id + ' | ' + (b.name + ' '.repeat(40 - b.name.length)) + '| ' + (n + ' '.repeat(8 - String(n).length)) + ' | ' + status + ' |');
}
console.log('');
console.log(W('Top per category (up to 3 each):', BOLD));
console.log('');
for (const b of buckets) {
  if (!b.findings.length) continue;
  console.log(W(b.id + '  ' + b.name, BOLD) + '  (' + b.findings.length + ')');
  for (const f of b.findings.slice(0, 3)) {
    const sev = (f.severity || 'medium').toUpperCase();
    const file = f.file ? f.file + ':' + (f.line || '?') : (f.name + '@' + f.version);
    console.log('  [' + sev + ']  ' + (f.vuln || f.advisory || '').slice(0, 80) + '   ' + W(file, DIM));
  }
  if (b.findings.length > 3) console.log('  ' + W('... and ' + (b.findings.length - 3) + ' more', DIM));
  console.log('');
}
console.log(W('Summary: ' + totalFindings + ' total findings mapped to LLM Top 10 categories.', BOLD));
"

else

# STRIDE (default)
node -e "
const fs = require('fs');
let scan;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); }
catch { console.log('No scan yet. Run /scan --all first.'); process.exit(0); }

const findings = scan.findings || [];

const STRIDE = [
  { id: 'S', name: 'Spoofing' },
  { id: 'T', name: 'Tampering' },
  { id: 'R', name: 'Repudiation' },
  { id: 'I', name: 'Information Disclosure' },
  { id: 'D', name: 'Denial of Service' },
  { id: 'E', name: 'Elevation of Privilege' },
];

const W = (s, code) => process.stdout.isTTY ? '\x1b[' + code + 'm' + s + '\x1b[0m' : s;
const BOLD = '1', DIM = '2', YELLOW = '33', GREEN = '32';

const buckets = STRIDE.map(cat => ({
  ...cat,
  findings: findings.filter(f => f.stride === cat.id || f.stride === cat.name),
}));

console.log('');
console.log(W('STRIDE Coverage Table', BOLD));
console.log('');
console.log('| Category               | Count | Top finding |');
console.log('|------------------------|-------|-------------|');
for (const b of buckets) {
  const n = b.findings.length;
  const top = b.findings[0] ? (b.findings[0].title || b.findings[0].vuln || '').slice(0, 50) : W('no findings', DIM);
  const count = n === 0 ? W('0', GREEN) : W(String(n), YELLOW);
  console.log('| ' + (b.name + ' '.repeat(22 - b.name.length)) + ' | ' + count + ' '.repeat(5 - String(n).length) + ' | ' + top + ' |');
}
console.log('');

const zero = buckets.filter(b => b.findings.length === 0);
if (zero.length) {
  console.log(W('Categories with no findings (under-covered or genuinely absent):', BOLD));
  for (const b of zero) console.log('  ' + b.name);
  console.log('');
}

const top = buckets.flatMap(b => b.findings.slice(0, 1));
if (top.length) {
  console.log(W('Highest-exploitability finding per category:', BOLD));
  for (const b of buckets) {
    if (!b.findings.length) continue;
    const f = b.findings[0];
    console.log('  [' + b.name + ']  ' + (f.severity||'').toUpperCase() + '  ' + (f.title||f.vuln||''));
  }
}
"

fi
```

Print the output verbatim.

Use the `security-triager` subagent for deeper exploitability analysis of STRIDE findings if needed.
