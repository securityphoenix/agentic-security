// Root-cause clustering (FR-PREC-6).
//
// When a single missing sanitizer produces N flow paths converging on the
// same sink expression, the engine emits N findings. This module collapses
// them into one finding with `clusterSize` = N and `exampleFlows` containing
// up to 5 representative paths. Downstream `/fix` operates on the cluster,
// not on each leaf — one patch fixes all flows.
//
// Distinct from the existing `dedupeFindingsWithEvidence`, which clusters by
// (file, sink-line, family). Root-cause clustering goes further: it clusters
// across files when the sink shape and rule are identical, surfacing the
// "one bug, N expressions of it" view.

function sinkKey(f) {
  // Cluster by the rule that fired + the file + a normalized form of the sink
  // expression. We INTENTIONALLY do not cluster across files — the existing
  // fix-bundling pipeline does that (one buggy helper called from N routes →
  // one bundle of N findings). Clustering here is for the narrower case where
  // a single sink has multiple flows feeding it within the same file.
  const rule = f.cwe || f.family || (f.vuln || '').slice(0, 40);
  const file = f.file || f.sink?.file || '';
  const sinkExpr = (f.sink?.label || f.sink?.snippet || f.snippet || '')
    .replace(/['"`][^'"`]*['"`]/g, '_S_')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 120);
  return `${rule}::${file}::${sinkExpr}`;
}

export function clusterByRootCause(findings) {
  if (!Array.isArray(findings) || findings.length === 0) return findings;
  const buckets = new Map();
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    const k = sinkKey(f);
    if (!k || k === '::') continue;
    if (!buckets.has(k)) buckets.set(k, []);
    buckets.get(k).push(f);
  }
  const drop = new Set();
  for (const [, group] of buckets) {
    if (group.length < 2) continue;
    // Sort by severity (highest first), then by triageScore — keep the strongest.
    const SEV = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    group.sort((a, b) =>
      (SEV[a.severity] ?? 9) - (SEV[b.severity] ?? 9) ||
      (b.triageScore || 0) - (a.triageScore || 0)
    );
    const keeper = group[0];
    keeper.clusterSize = group.length;
    keeper.exampleFlows = group.slice(1, 6).map(f => ({
      file: f.file || f.sink?.file,
      line: f.line || f.sink?.line,
      source: f.source ? { file: f.source.file, line: f.source.line, label: f.source.label } : null,
      sink: f.sink ? { file: f.sink.file, line: f.sink.line, label: f.sink.label } : null,
      snippet: f.snippet,
    }));
    for (let i = 1; i < group.length; i++) drop.add(group[i]);
  }
  if (!drop.size) return findings;
  return findings.filter(f => !drop.has(f));
}
