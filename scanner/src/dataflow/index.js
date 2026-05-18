// Layer 2 entry point.
import { runTaintEngine } from './engine.js';
import { CATALOG, matchSource, matchSinkOrSanitizer, _catalogSize } from './catalog.js';
import { applyPathFeasibility } from './path-feasibility.js';
import { SummaryCache, entryStateFromCall } from './summaries.js';

export function runDeepAnalysis(perFileIR, callGraph, opts = {}) {
  // Path-feasibility pass over every function before the taint walk.
  let totalPruned = 0;
  for (const fn of callGraph.functions.values()) {
    const r = applyPathFeasibility(fn);
    totalPruned += r.pruned;
  }
  const findings = runTaintEngine(perFileIR, callGraph, opts);
  // Stamp pruned-edge count for debugging.
  for (const f of findings) f._pathFeasibilityPruned = totalPruned;
  return findings;
}

export { runTaintEngine, CATALOG, matchSource, matchSinkOrSanitizer, _catalogSize, applyPathFeasibility, SummaryCache, entryStateFromCall };
