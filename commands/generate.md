---
description: Generate security artifacts — privacy policy, disaster playbook, social posts, security regression tests.
argument-hint: "--type privacy|disaster|social|tests [type-specific flags...]"
---

Four document generators behind one command.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
TYPE=""
NEXT=""
EXTRA_ARGS=""

for arg in "$@"; do
  case "$NEXT" in
    type) TYPE="$arg"; NEXT=""; continue ;;
  esac
  case "$arg" in
    --type) NEXT="type" ;;
    privacy|disaster|social|tests)
      [ -z "$TYPE" ] && TYPE="$arg" && continue
      EXTRA_ARGS="$EXTRA_ARGS $arg"
      ;;
    *) EXTRA_ARGS="$EXTRA_ARGS $arg" ;;
  esac
done

if [ -z "$TYPE" ]; then
  echo ""
  echo "Usage: /generate --type <type>"
  echo ""
  echo "  Types:"
  echo "    privacy    Privacy policy + cookie banner from your stack"
  echo "    disaster   Incident-response playbook (DISASTER.md)"
  echo "    social     Copy-paste social posts (Twitter/LinkedIn/Discord)"
  echo "    tests      Security regression tests per finding"
  echo ""
  exit 0
fi

case "$TYPE" in
  privacy)
    echo "Generating privacy docs..."
    python3 ${CLAUDE_PLUGIN_ROOT}/scripts/privacy-docs.py $EXTRA_ARGS
    ;;
  disaster)
    echo "Generating disaster playbook..."
    python3 ${CLAUDE_PLUGIN_ROOT}/scripts/disaster-playbook.py $EXTRA_ARGS
    ;;
  social)
    node -e "
const fs = require('fs');
let scan, streak;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); }
catch { console.log('No scan yet. Run /scan --all first.'); process.exit(0); }
try { streak = JSON.parse(fs.readFileSync('.agentic-security/streak.json', 'utf8')); }
catch { streak = {}; }

const findings = scan.findings || [];
const counts = { critical: 0, high: 0, medium: 0, low: 0 };
for (const f of findings) counts[f.severity] = (counts[f.severity]||0) + 1;
const c = counts.critical, h = counts.high;
let grade;
if (c > 10 || (c > 5)) grade = 'F';
else if (c >= 6) grade = 'D';
else if (c >= 3) grade = 'C-';
else if (c >= 1) grade = 'C';
else if (h > 10) grade = 'B-';
else if (h >= 3) grade = 'B';
else if (h > 0) grade = 'A-';
else if (counts.medium > 0) grade = 'A';
else grade = 'A+';

const days = streak.daysCleanCritical || 0;
const fixes = streak.totalFixesInferred || 0;
const repo = 'https://github.com/Clear-Capabilities/agentic-security';
const target = (process.argv[1] || 'all').toLowerCase();
const W = (s, code) => process.stdout.isTTY ? \`\\x1b[\${code}m\${s}\\x1b[0m\` : s;

if (target === 'twitter' || target === 'x' || target === 'all') {
  console.log('');
  console.log(W('━━ Twitter / X ━━', '1'));
  let tweet;
  if (days >= 7) tweet = '🔒 ' + days + '-day clean streak · grade ' + grade + '\\n\\nAuto-scans every file edit. ' + repo;
  else if (grade <= 'A') tweet = '🔒 Grade ' + grade + ' on my codebase with agentic-security\\n\\n' + repo;
  else tweet = '🔒 Shipped ' + fixes + ' security fix' + (fixes===1?'':'es') + ' · grade ' + grade + '\\n\\n' + repo;
  console.log(tweet);
  console.log(W('  Length: ' + tweet.length + ' chars', '2'));
}

if (target === 'linkedin' || target === 'all') {
  console.log('');
  console.log(W('━━ LinkedIn ━━', '1'));
  const lines = ['Tracking security posture with the agentic-security plugin for Claude Code.','','• Grade: '+grade];
  if (days >= 1) lines.push('• Clean of critical: ' + days + ' day' + (days===1?'':'s'));
  if (fixes > 0) lines.push('• Fixes shipped: ' + fixes);
  lines.push('','Free for internal use. ' + repo);
  console.log(lines.join('\\n'));
}

if (target === 'discord' || target === 'slack' || target === 'all') {
  console.log('');
  console.log(W('━━ Discord / Slack ━━', '1'));
  const lines = [':closed_lock_with_key: Security check — **grade ' + grade + '**'];
  if (days >= 1) lines.push(':fire: ' + days + '-day clean streak');
  if (fixes > 0) lines.push(':wrench: ' + fixes + ' fix' + (fixes===1?'':'es') + ' shipped');
  lines.push('', 'Powered by agentic-security: ' + repo);
  console.log(lines.join('\\n'));
}
" -- "$EXTRA_ARGS"
    ;;
  tests)
    node -e "
const fs = require('fs');
const W = (s, c) => process.stdout.isTTY ? \`\\x1b[\${c}m\${s}\\x1b[0m\` : s;
const arg = (process.argv[1] || '--critical').trim();
let scan = null;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}
if (!scan) { console.log(W('No scan found.', '33') + ' Run /scan --all first.'); process.exit(0); }

const pkg = (() => { try { return JSON.parse(fs.readFileSync('package.json','utf8')); } catch { return null; } })();
const deps = pkg ? { ...(pkg.dependencies||{}), ...(pkg.devDependencies||{}) } : {};
const hasVitest = Object.keys(deps).some(k => k === 'vitest');
const hasJest = Object.keys(deps).some(k => k === 'jest' || k === '@jest/core');
const framework = hasVitest ? 'vitest' : hasJest ? 'jest' : 'node:test';

let targets = scan.findings || [];
if (arg === '--critical') targets = targets.filter(f => f.severity === 'critical' || f.severity === 'high');
else if (arg.startsWith('--finding')) {
  const id = arg.replace('--finding','').trim();
  targets = targets.filter(f => f.id === id);
}
targets = targets.slice(0, 10);

console.log('');
console.log(W('Security Regression Test Generator', '1'));
console.log('  Framework: ' + framework);
console.log('  Findings to cover: ' + targets.length);
console.log('');
console.log(JSON.stringify({
  framework,
  appType: Object.keys(deps).some(k=>k==='next') ? 'nextjs' : Object.keys(deps).some(k=>k==='express') ? 'express' : 'node',
  testDir: fs.existsSync('src/__tests__') ? 'src/__tests__' : fs.existsSync('test') ? 'test' : '__tests__',
  findings: targets.map(f => ({ id: f.id, vuln: f.vuln, severity: f.severity, file: f.file, line: f.line, description: f.description, cwe: f.cwe })),
}, null, 2));
" -- "$EXTRA_ARGS"
    ;;
  *)
    echo "Unknown type: $TYPE"
    echo "Valid types: privacy, disaster, social, tests"
    exit 1
    ;;
esac
```

For `--type privacy`: Using the detection output, generate a PRIVACY.md that names each detected processor, its purpose, the data it receives, and links to its DPA. Optionally generate a React cookie banner component with `--generate-banner`.

For `--type disaster`: Using the detection output, generate a DISASTER.md with stack-specific incident-response sections using the project's actual env var names.

For `--type tests`: Using the JSON above, generate a test file for each finding with VULNERABILITY (failing before fix) and FIXED (passing after fix) test cases using the detected framework.

## Quick reference

| Type | Was | Output |
|---|---|---|
| `privacy` | `/privacy-docs` | PRIVACY.md + optional cookie banner |
| `disaster` | `/disaster-playbook` | DISASTER.md incident-response playbook |
| `social` | `/social-media` | Copy-paste posts (twitter/linkedin/discord) |
| `tests` | `/security-tests` | Regression test files per finding |
