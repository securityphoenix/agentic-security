---
description: Print a markdown badge users can paste into their own README to advertise the project's security grade. Same pattern as Codecov / OSSF Scorecard badges.
---

Generate a shareable security-grade badge.

```bash
node -e "
const fs = require('fs');
let scan;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); }
catch { console.log('No scan yet. Run /security-scan-all first, then /security-badge.'); process.exit(0); }

const findings = scan.findings || [];
const supplyChain = (scan.supplyChain || []).filter(s => s.type === 'vulnerable_dep');
const counts = { critical: 0, high: 0, medium: 0, low: 0 };
for (const f of findings) counts[f.severity] = (counts[f.severity]||0) + 1;
for (const s of supplyChain) counts[s.severity || 'high'] = (counts[s.severity || 'high']||0) + 1;
const kev = [...findings, ...supplyChain].filter(f => f.kev === true).length;
const c = counts.critical, h = counts.high;

let grade;
if (c > 10 || (c > 5 && kev > 0)) grade = 'F';
else if (c >= 6) grade = 'D';
else if (kev > 0) grade = 'D';
else if (c >= 3) grade = 'C-';
else if (c >= 1) grade = 'C';
else if (h > 10) grade = 'B-';
else if (h >= 3) grade = 'B';
else if (h > 0) grade = 'A-';
else if (counts.medium > 0) grade = 'A';
else grade = 'A+';

const colors = { 'A+': 'brightgreen', 'A': 'brightgreen', 'A-': 'green', 'B': 'green', 'B-': 'yellowgreen', 'C': 'yellow', 'C-': 'orange', 'D': 'orange', 'F': 'red' };
const color = colors[grade] || 'lightgrey';
// Use shields.io static/v1 API — URL-param form so hyphens in label/grade
// don't break the path-syntax escaping rules.
const params = new URLSearchParams({
  label: 'agentic-security',
  message: grade,
  color,
  logo: 'shield',
  logoColor: 'white',
});
const url = 'https://img.shields.io/static/v1?' + params.toString();
const repo = 'https://github.com/clearcapabilities/agentic-security';
const display = grade;

console.log('');
console.log('Your security grade: ' + display);
console.log('');
console.log('Add this to the top of your README to show it off:');
console.log('');
console.log('Markdown:');
console.log('  [![agentic-security: ' + display + '](' + url + ')](' + repo + ')');
console.log('');
console.log('HTML:');
console.log('  <a href=\"' + repo + '\"><img alt=\"agentic-security: ' + display + '\" src=\"' + url + '\"></a>');
console.log('');
console.log('The badge uses shields.io with a static value — re-run /security-badge after each scan to refresh it.');
console.log('');
"
```

Print the output verbatim. The user wants the badge markdown to copy into their README.

## Why this exists

Vibecoders love brag-tags. A security-grade badge in a README does three things at once: it builds social proof for the project, signals security maturity to potential users, and (because every project that adds it links back to agentic-security) advertises this tool. Same proven pattern as Codecov, Snyk, OSSF Scorecard, and OpenSSF Best Practices.

The badge is a static shields.io image — it reflects the grade at the moment you ran `/security-badge`. To keep it current, re-run after each meaningful scan (or wire `/security-badge` into your CI alongside `/security-scan-all`).
