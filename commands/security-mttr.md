---
description: Track finding age and surface findings exceeding SLA. Computes mean time to remediate (MTTR) for fixed findings since the baseline.
argument-hint: "[--sla-days '{\"critical\":7,\"high\":30,\"medium\":60,\"low\":90}']"
---

Run the MTTR / finding-age report against the current scan and the saved baseline.

```bash
node -e "
const fs = await import('node:fs/promises');
const { stampFindingTimestamps, buildBaselineMap, findingsExceedingSLA, computeMTTR } = await import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/mttr.js');
const baseline = JSON.parse(await fs.readFile('.agentic-security/baseline.json', 'utf8').catch(() => '{}'));
const current = JSON.parse(await fs.readFile('.agentic-security/last-scan.json', 'utf8'));
const map = buildBaselineMap(baseline);
const findings = [...(current.findings||[]), ...(current.secrets||[]), ...(current.supplyChain||[]).filter(s => s.type==='vulnerable_dep')];
stampFindingTimestamps(findings, map);
const overSla = findingsExceedingSLA(findings);
console.log('SLA breaches:', overSla.length);
for (const f of overSla.slice(0, 20)) console.log('  ' + f.severity + '\t' + f.ageDays + 'd\t' + (f.file||'') + ':' + (f.line||0) + '\t' + (f.vuln||''));
// MTTR over removed findings (in baseline but not in current)
const currentFps = new Set(findings.map(f => f._fp));
const removed = (baseline.findings||[]).filter(f => f.firstSeenAt && !currentFps.has(require('crypto').createHash('sha256').update((f.file||'') + ':' + (f.line||0) + ':' + ((f.vuln||'').replace(/\W+/g,'_').toLowerCase()) + ':' + ((f.cwe||'').toUpperCase())).digest('hex').slice(0,16)));
const m = computeMTTR(removed);
console.log('MTTR — fixed since baseline:', m.count, 'findings, mean', m.meanDays?.toFixed(1) || 0, 'days, median', m.medianDays?.toFixed(1) || 0, 'days');
"
```

The report shows:
- **SLA breaches** — findings older than the per-severity threshold (default: critical=7d, high=30d, medium=60d, low=90d).
- **MTTR** — mean time to remediate, computed over findings present in the baseline but no longer in the current scan.

SLA tracking driven by your local baseline file. No tickets, no agents, no dashboards — just timestamps.
