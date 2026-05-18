// Per-CWE precision/recall metrics persistence.
//
// PRD success metric §5: "Recall on top-25 CWE classes ≥ 0.92." Tracking
// this requires running a labelled benchmark and persisting the per-family
// scorecard so /security-trend, /report-card, and the dashboard can
// surface the trend over time.
//
// File location: .agentic-security/validator-metrics.json
//
// Shape:
//   {
//     "history": [
//       { "when": "2026-05-18T...", "benchmark": "owasp-benchmark-v1.2",
//         "mode": "blind+strict",
//         "aggregate": { "tp": ..., "fp": ..., "fn": ..., "precision": ..., "recall": ..., "f1": ... },
//         "perFamily": { "<family>": { "tp": ..., "fp": ..., "fn": ..., "precision": ..., "recall": ..., "f1": ... } }
//       }
//     ],
//     "floors": {
//       "perFamily": { "default": { "recall": 0.92 }, "<family>": { "recall": 0.92, "precision": 0.85 } },
//       "aggregate": { "f1": 0.90 }
//     }
//   }

import * as fs from 'node:fs';
import * as path from 'node:path';

const FILE = '.agentic-security/validator-metrics.json';
const HISTORY_CAP = 100;

function _filePath(scanRoot) { return path.join(scanRoot || process.cwd(), FILE); }

function _read(scanRoot) {
  const fp = _filePath(scanRoot);
  if (!fs.existsSync(fp)) return { history: [], floors: { perFamily: { default: { recall: 0.92 } }, aggregate: { f1: 0.90 } } };
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); }
  catch { return { history: [], floors: { perFamily: { default: { recall: 0.92 } }, aggregate: { f1: 0.90 } } }; }
}

function _write(scanRoot, data) {
  const fp = _filePath(scanRoot);
  try {
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, JSON.stringify(data, null, 2));
  } catch { /* swallow — telemetry is best-effort */ }
}

function _round(n) { return Math.round(n * 10000) / 10000; }

function _computeStats(tp, fp, fn) {
  const precision = tp / Math.max(tp + fp, 1e-9);
  const recall    = tp / Math.max(tp + fn, 1e-9);
  const f1        = (2 * precision * recall) / Math.max(precision + recall, 1e-9);
  return { precision: _round(precision), recall: _round(recall), f1: _round(f1) };
}

// Record one benchmark run.
//   benchmark: 'owasp-benchmark-v1.2' | 'sard-juliet-java' | 'cve-replay' | ...
//   mode: 'blind+strict' | 'non-blind+strict' | 'non-blind+wildcard'
//   perFamily: { fam: { tp, fp, fn } }
export function recordRun(scanRoot, { benchmark, mode, tp, fp, fn, perFamily }) {
  const data = _read(scanRoot);
  const entry = {
    when: new Date().toISOString(),
    benchmark, mode,
    aggregate: { tp, fp, fn, ..._computeStats(tp, fp, fn) },
    perFamily: {},
  };
  for (const [fam, c] of Object.entries(perFamily || {})) {
    if (!c) continue;
    entry.perFamily[fam] = { tp: c.tp || 0, fp: c.fp || 0, fn: c.fn || 0, ..._computeStats(c.tp || 0, c.fp || 0, c.fn || 0) };
  }
  data.history = data.history || [];
  data.history.push(entry);
  if (data.history.length > HISTORY_CAP) data.history = data.history.slice(-HISTORY_CAP);
  _write(scanRoot, data);
  return entry;
}

// Read the latest entry and compare against floors.
export function getLatest(scanRoot, benchmark) {
  const data = _read(scanRoot);
  const matches = (data.history || []).filter(e => !benchmark || e.benchmark === benchmark);
  return matches[matches.length - 1] || null;
}

// Identify families that violate their floors in the latest run.
//   { aggregateBelowFloor: bool, familiesBelowFloor: [{fam, metric, value, floor}] }
export function checkFloors(scanRoot, benchmark) {
  const data = _read(scanRoot);
  const latest = getLatest(scanRoot, benchmark);
  if (!latest) return { aggregateBelowFloor: false, familiesBelowFloor: [], latest: null };
  const floors = data.floors || {};
  const out = { aggregateBelowFloor: false, familiesBelowFloor: [], latest };
  const aggMin = (floors.aggregate || {}).f1;
  if (typeof aggMin === 'number' && latest.aggregate.f1 < aggMin) {
    out.aggregateBelowFloor = true;
    out.aggregateFloor = aggMin;
  }
  const perFamFloors = floors.perFamily || {};
  const defaultFamFloor = perFamFloors.default || {};
  for (const [fam, stats] of Object.entries(latest.perFamily || {})) {
    const famFloor = { ...defaultFamFloor, ...(perFamFloors[fam] || {}) };
    for (const metric of ['precision', 'recall', 'f1']) {
      if (typeof famFloor[metric] === 'number' && stats[metric] < famFloor[metric]) {
        out.familiesBelowFloor.push({ fam, metric, value: stats[metric], floor: famFloor[metric] });
      }
    }
  }
  return out;
}

// Convenience: render a short human summary.
export function summarize(scanRoot, benchmark) {
  const latest = getLatest(scanRoot, benchmark);
  if (!latest) return '(no metrics history yet)';
  const r = latest.aggregate;
  const fams = Object.entries(latest.perFamily || {})
    .sort((a, b) => b[1].tp - a[1].tp);
  const lines = [];
  lines.push(`${latest.benchmark} (${latest.mode}) @ ${latest.when.slice(0, 16)}`);
  lines.push(`  F1=${r.f1} P=${r.precision} R=${r.recall} (TP=${r.tp} FP=${r.fp} FN=${r.fn})`);
  for (const [fam, s] of fams.slice(0, 10)) {
    lines.push(`  · ${fam.padEnd(20)} P=${s.precision} R=${s.recall} (TP=${s.tp} FP=${s.fp} FN=${s.fn})`);
  }
  return lines.join('\n');
}
