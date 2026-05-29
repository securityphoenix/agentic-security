// Pattern propagation — annotator that surfaces cross-repo signals on
// findings. For each finding, queries the cross-repo store for past
// fixes and triage decisions on the same family from sibling repos and
// stamps the finding with a crossRepoSignal field.
//
// The /show-findings command / PR-augment / explain_finding MCP tool
// can render the signal alongside the finding so the developer sees
// "you already fixed this exact shape in repo X."
//
// Pure annotator — no LLM calls. Opt-out via the cross-repo-memory
// AGENTIC_SECURITY_NO_CROSS_REPO=1 flag.

import { findSiblingSignals, renderSiblingNote } from './cross-repo-memory.js';

export function annotateCrossRepoSignals(scanRoot, findings) {
  if (process.env.AGENTIC_SECURITY_NO_CROSS_REPO === '1') return { annotated: 0 };
  if (!Array.isArray(findings) || findings.length === 0) return { annotated: 0 };
  let annotated = 0;
  // De-duplicate signal lookups per family — many findings share a family.
  const sigCache = new Map();
  for (const f of findings) {
    const fam = f.family;
    if (!fam) continue;
    let signals = sigCache.get(fam);
    if (signals === undefined) {
      signals = findSiblingSignals(scanRoot, f);
      sigCache.set(fam, signals);
    }
    if (signals.siblingFixes.length || signals.siblingTriage.length) {
      f.crossRepoSignal = {
        fixes:  signals.siblingFixes.length,
        triage: signals.siblingTriage.length,
        note:   renderSiblingNote(signals),
      };
      annotated++;
    }
  }
  return { annotated, total: findings.length };
}
