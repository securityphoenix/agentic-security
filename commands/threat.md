---
description: Threat modeling + attacker views — STRIDE, personas, playbooks, adversary agent, attack surface, trust boundaries, SPOF.
argument-hint: "[--view model|personas|playbook|bounty|adversary|surface|boundary|spof] [model flags...]"
---

Eight attacker/threat views behind one command. Default (no `--view`): STRIDE model.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
VIEW="model"
EXTRA_ARGS=""
NEXT=""

# Collect --view and pass everything else through
for arg in "$@"; do
  case "$NEXT" in
    view) VIEW="$arg"; NEXT=""; continue ;;
  esac
  case "$arg" in
    --view) NEXT="view" ;;
    *) EXTRA_ARGS="$EXTRA_ARGS $arg" ;;
  esac
done

# ── Shared setup ──
node -e "
const fs = require('fs');
const W = (s, c) => process.stdout.isTTY ? \`\x1b[\${c}m\${s}\x1b[0m\` : s;
const BOLD='1', DIM='2', YELLOW='33', RED='31', GREEN='32';

let scan;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); }
catch { console.log(W('No scan yet.', YELLOW) + ' Run /scan --all first.'); process.exit(0); }

const view = process.env.VIEW;
const args = (process.env.EXTRA_ARGS || '').trim().split(/\s+/).filter(Boolean);

// Parse common flags
function getArg(name, def) {
  const i = args.indexOf(name);
  return i >= 0 && args[i+1] ? args[i+1] : def;
}
const hasFlag = name => args.includes(name);

switch (view) {

// ── model (was /threat-model) ──
case 'model': {
  const tm = scan._v3 && scan._v3.threatModel;
  const full = hasFlag('--full');
  if (!tm) { console.log('No threat model on last scan. Re-run /scan with v0.53+.'); break; }
  console.log('');
  console.log(W('STRIDE Threat Model — auto-derived', BOLD));
  console.log(W('  ' + tm.summary.assetCount + ' assets · ' + tm.summary.boundaryCount + ' trust boundaries', DIM));
  console.log('');
  console.log('| Category               | Findings |');
  console.log('|------------------------|----------|');
  for (const [cat, count] of Object.entries(tm.summary.strideCounts)) {
    const pretty = cat.replace(/([A-Z])/g, ' \$1').trim();
    console.log('| ' + pretty.padEnd(22) + ' | ' + String(count).padEnd(8) + ' |');
  }
  console.log('');
  if (full) {
    console.log(W('Per-category top findings:', BOLD));
    for (const [cat, items] of Object.entries(tm.stride)) {
      if (!items.length) continue;
      console.log('\\n  ' + W(cat, BOLD) + ' (' + items.length + ')');
      for (const f of items.slice(0, 5))
        console.log('    [' + (f.severity||'').toUpperCase() + '] ' + (f.vuln || '').slice(0, 60) + '  ' + f.file + ':' + f.line);
    }
    console.log('');
    console.log(W('Asset inventory:', BOLD));
    for (const a of tm.assets.slice(0, 15))
      console.log('  ' + a.category.padEnd(18) + ' ' + (a.name || '').slice(0, 30).padEnd(30) + ' ' + a.file + ':' + a.line);
    console.log('');
    console.log(W('Trust boundaries:', BOLD));
    for (const b of tm.trustBoundaries.slice(0, 15))
      console.log('  ' + b.type.padEnd(20) + ' ' + (b.label || '').slice(0, 30).padEnd(30) + ' ' + b.file + ':' + b.line);
  }
  break;
}

// ── personas (was /personas) ──
case 'personas': {
  const PERSONAS = ['script-kiddie','opportunistic-criminal','apt-nation-state','supply-chain-attacker','malicious-insider'];
  const findings = (scan.findings || []).filter(f => f.personaScores);
  if (!findings.length) { console.log('No persona-scored findings. Re-run /scan with v0.52+.'); break; }
  const target = getArg('--persona', '');
  const top = parseInt(getArg('--top', '5'), 10);
  const personasToShow = target ? [target] : PERSONAS;
  console.log('');
  for (const p of personasToShow) {
    const items = findings.filter(f => f.personaScores[p]).sort((a,b) =>
      (b.personaScores[p].score || 0) - (a.personaScores[p].score || 0));
    console.log(W(p, BOLD) + W('  (' + items.length + ' relevant findings)', DIM));
    if (!items.length) { console.log('  ' + W('— no high-priority findings for this persona', DIM)); console.log(''); continue; }
    for (const f of items.slice(0, top)) {
      const ps = f.personaScores[p];
      const color = ps.tier === 'critical' ? RED : ps.tier === 'high' ? YELLOW : DIM;
      console.log('  [' + W(ps.score.toFixed(2), color) + ' ' + ps.tier.padEnd(8) + '] ' +
        (f.vuln || '').slice(0, 60).padEnd(60) + '  ' + f.file + ':' + f.line);
    }
    console.log('');
  }
  break;
}

// ── playbook (was /playbook) ──
case 'playbook': {
  const mode = getArg('--finding', '') ? 'finding' : getArg('--cwe', '') ? 'cwe' : 'all';
  let target = (scan.findings || []).filter(f => f.attackPlaybook);
  if (mode === 'finding') target = target.filter(f => f.id === getArg('--finding','') || f.stableId === getArg('--finding',''));
  else if (mode === 'cwe') target = target.filter(f => (f.cwe || '').toUpperCase() === getArg('--cwe','').toUpperCase());
  if (!target.length) { console.log('No matching findings carry an attack playbook.'); break; }
  console.log('');
  console.log(W('Attack playbooks for ' + target.length + ' finding(s):', BOLD));
  console.log('');
  for (const f of target.slice(0, 20)) {
    const pb = f.attackPlaybook;
    console.log(W('━'.repeat(72), DIM));
    console.log(W(pb.cwe + ' — ' + pb.title, BOLD));
    console.log(W('Finding: ' + (f.vuln || '') + '  ' + f.file + ':' + f.line, DIM));
    console.log('');
    console.log(pb.script);
    console.log('');
  }
  console.log(W('AUTHORIZED USE ONLY — run only against systems you own or have explicit permission to test.', DIM));
  break;
}

// ── bounty (was /bounty) ──
case 'bounty': {
  const top = parseInt(getArg('--top', '20'), 10);
  const wantWeb3 = hasFlag('--web3');
  let findings = (scan.findings || []).filter(f => f.predictedBountyUsd);
  if (wantWeb3) findings = findings.filter(f => f.predictedBountyUsd.program === 'web3');
  findings.sort((a,b) => (b.predictedBountyUsd.likely||0) - (a.predictedBountyUsd.likely||0));
  if (!findings.length) { console.log('No bounty-predicted findings.'); break; }
  console.log('');
  console.log(W('Predicted bug-bounty payouts (' + findings.length + ' findings)', BOLD));
  console.log('');
  console.log('| Likely    | Range            | Program | Finding                                        | Location                |');
  console.log('|-----------|------------------|---------|------------------------------------------------|-------------------------|');
  let total = 0;
  for (const f of findings.slice(0, top)) {
    const b = f.predictedBountyUsd;
    total += b.likely;
    const lk = '\$' + b.likely.toLocaleString();
    const rng = '\$' + b.low.toLocaleString() + '–\$' + b.high.toLocaleString();
    const vuln = (f.vuln||'').slice(0, 46).padEnd(46);
    const loc = (f.file + ':' + f.line).slice(0, 23).padEnd(23);
    console.log('| ' + lk.padEnd(9) + ' | ' + rng.padEnd(16) + ' | ' + (b.program || '-').padEnd(7) + ' | ' + vuln + ' | ' + loc + ' |');
  }
  console.log('');
  console.log(W('Total likely payouts (top ' + Math.min(top, findings.length) + '): \$' + total.toLocaleString(), GREEN));
  break;
}

// ── adversary (was /adversary) ──
case 'adversary': {
  const findingId = getArg('--finding', '');
  const target = getArg('--target', '');
  if (!findingId || !target) {
    console.log('Usage: /threat --view adversary --finding <id> --target <url> [--max-calls 20]');
    console.log('');
    console.log('Required env:');
    console.log('  AGENTIC_SECURITY_LLM_ENDPOINT  OpenAI-compatible chat completions URL');
    console.log('  AGENTIC_SECURITY_LLM_API_KEY   bearer token');
    break;
  }
  if (!process.env.AGENTIC_SECURITY_LLM_ENDPOINT) {
    console.log('❌  AGENTIC_SECURITY_LLM_ENDPOINT not set.');
    break;
  }
  const maxCalls = parseInt(getArg('--max-calls', '20'), 10);
  const maxWallMs = parseInt(getArg('--max-wall-ms', '300000'), 10);
  const f = (scan.findings || []).find(x => x.id === findingId || x.stableId === findingId);
  if (!f) { console.log('No finding matches ' + findingId); break; }
  console.log('');
  console.log(W('Adversary-agent run', BOLD));
  console.log(W('  Finding: ' + (f.vuln || '') + '  ' + f.file + ':' + f.line, DIM));
  console.log(W('  Target:  ' + target, DIM));
  console.log(W('  Budget:  ≤' + maxCalls + ' calls, ≤' + (maxWallMs/1000) + 's wall time', DIM));
  console.log('');
  const { runAgent } = require('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/adversary-agent.js');
  const result = await runAgent(f, { target, maxCalls, maxWallMs });
  for (const e of result.transcript.entries) {
    if (e.tool) console.log('  ' + e.tool.padEnd(20) + ' ' + JSON.stringify(e.args || {}).slice(0, 60));
    else console.log('  ' + W('phase:', DIM) + ' ' + (e.phase || '?'));
  }
  console.log('');
  console.log(W('Outcome: ', BOLD) + result.outcome);
  const path = require('path');
  const out = path.join('.agentic-security', 'adversary-transcripts', (f.stableId || f.id || 'transcript') + '.ndjson');
  fs.mkdirSync(path.dirname(out), { recursive: true });
  const lines = [JSON.stringify({ seedFinding: result.transcript.seedFinding, target: result.transcript.target })]
    .concat(result.transcript.entries.map(e => JSON.stringify(e)));
  fs.writeFileSync(out, lines.join('\\n') + '\\n');
  console.log(W('Transcript: ' + out, DIM));
  break;
}

// ── surface (was /attack-surface) ──
case 'surface': {
  const findings = scan.findings || [];
  const critAndHigh = findings.filter(f => f.severity === 'critical' || f.severity === 'high').slice(0, 20);
  const secretFindings = findings.filter(f => /CWE-798|hardcoded|secret|credential/i.test(f.cwe || f.vuln || ''));
  const authFindings = findings.filter(f => /auth|IDOR|session|JWT|csrf|CWE-284|CWE-287|CWE-352/i.test(f.cwe || f.vuln || ''));
  const injectionFindings = findings.filter(f => /SQL|injection|XSS|command|SSRF/i.test(f.vuln || ''));
  const chains = findings.filter(f => f.vuln && f.vuln.includes('→'));
  const routes = scan.routes || [];
  const unauthRoutes = routes.filter(r => !r.hasAuth && r.method !== 'GET').length;
  console.log('');
  console.log(W('Attack Surface — Threat Narrative', BOLD));
  console.log('');
  console.log(JSON.stringify({
    total_findings: findings.length,
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    secrets_leaked: secretFindings.length,
    auth_issues: authFindings.length,
    injection_issues: injectionFindings.length,
    attack_chains: chains.length,
    unauth_state_routes: unauthRoutes,
    top_findings: critAndHigh.slice(0, 10).map(f => ({ vuln: f.vuln, file: f.file, line: f.line, severity: f.severity, cwe: f.cwe })),
  }, null, 2));
  break;
}

// ── boundary (was /trust-boundary) ──
case 'boundary': {
  const d = scan._v3 && scan._v3.trustBoundaryDiagram;
  if (!d) { console.log('No trust-boundary diagram on last scan. Re-run /scan with v0.52+.'); break; }
  const inline = hasFlag('--inline');
  if (inline) { process.stdout.write(d.mermaid + '\\n'); break; }
  const path = require('path');
  const ts = new Date().toISOString().replace(/[:T]/g, '-').slice(0, 19);
  const explicitOut = getArg('--output', '');
  const out = explicitOut || ('reports/trust-boundary-' + ts + '.md');
  fs.mkdirSync(path.dirname(out), { recursive: true });
  const decorations = (d.decorations || []).slice(0, 25);
  const body = ['# Trust Boundaries','','> Auto-generated from the last scan.','','\`\`\`mermaid', d.mermaid, '\`\`\`','',
    '## Decorations (' + (d.decorations || []).length + ' findings)', ''];
  for (const dec of decorations)
    body.push('- **[' + (dec.severity || '').toUpperCase() + ']** ' + dec.vuln + '  →  ' + dec.file + ':' + dec.line);
  fs.writeFileSync(out, body.join('\\n'));
  console.log('Trust-boundary diagram written: ' + out);
  console.log('Open in any Markdown viewer with Mermaid support.');
  break;
}

// ── spof (was /spof) ──
case 'spof': {
  const c = scan._v3 && scan._v3.counterfactual;
  const threshold = parseInt(getArg('--threshold', '3'), 10);
  console.log('');
  console.log(W('Single-point-of-failure controls (counterfactual)', BOLD));
  if (!c) { console.log(W('Re-run /scan with v0.52+.', DIM)); break; }
  if (c.note === 'no-controls-detected') {
    console.log(W('No defensive controls detected — defense-in-depth is absent.', DIM));
    break;
  }
  console.log(W('  ' + (c.controlsDetected || 0) + ' control(s) detected', DIM));
  console.log('');
  const spof = (c.spofControls || []).filter(s => s.wouldExpose >= threshold);
  if (!spof.length) {
    console.log(W('✅  No SPOF controls — every control has redundant siblings or covers < ' + threshold + ' high+ findings.', GREEN));
    break;
  }
  console.log(W('  ' + spof.length + ' control(s) would expose ≥ ' + threshold + ' high+ findings if removed:', RED));
  console.log('');
  for (const s of spof.slice(0, 20)) {
    console.log(W('  ' + s.control + ' @ ' + s.location, BOLD));
    console.log('    ' + W('Would expose: ', DIM) + s.wouldExpose + ' high+ finding(s)');
    for (const ex of (s.examples || []).slice(0, 3))
      console.log('      • ' + ex.family + '  ' + ex.file + ':' + ex.line + '  [' + (ex.severity || '').toUpperCase() + ']');
    console.log('    ' + W('Recommend: ', YELLOW) + s.recommendation);
    console.log('');
  }
  break;
}

default:
  console.log('Unknown view: ' + view);
  console.log('Valid views: model, personas, playbook, bounty, adversary, surface, boundary, spof');
}
console.log('');
" VIEW="$VIEW" EXTRA_ARGS="$EXTRA_ARGS"
```

For `--view surface`: Using the JSON above, write a threat narrative in plain English for a builder. Format as 3-5 attack scenarios, each with: what the attacker does, what they get, likelihood, and the fix in one line. End with the single biggest thing to fix first.

## Quick reference

| View | Was | Purpose |
|---|---|---|
| `model` | `/threat-model` | STRIDE table. Add `--full` for assets + boundaries. |
| `personas` | `/personas` | Per-attacker priority. `--persona apt-nation-state --top 10` |
| `playbook` | `/playbook` | Attack scripts. `--finding <id>` or `--cwe CWE-89` |
| `bounty` | `/bounty` | Predicted HackerOne/Bugcrowd USD. `--top 50 --web3` |
| `adversary` | `/adversary` | Live LLM exploit agent. `--finding <id> --target <url>` |
| `surface` | `/attack-surface` | Plain-English narrative of top attack scenarios |
| `boundary` | `/trust-boundary` | Mermaid diagram. `--inline` for stdout. |
| `spof` | `/spof` | Counterfactual SPOF controls. `--threshold 5` |
