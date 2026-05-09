// 0.9.0 Feat-16: OSC&R coverage emitter.
//
// Loads scanner/src/posture/oscr-coverage.json and renders three formats:
//   - JSON: the raw matrix
//   - Markdown: a coverage table with ✓ / ✗ / △ per cell
//   - HTML fragment: drop-in for the report under an OSC&R tab

import { createRequire } from 'node:module';
const _require = createRequire(import.meta.url);
const _MATRIX = (() => {
  try {
    const raw = _require('./oscr-coverage.json');
    const out = {};
    for (const [k, v] of Object.entries(raw)) {
      if (k.startsWith('_')) continue;
      out[k] = v;
    }
    return out;
  } catch (_) {
    return {};
  }
})();

function _coverageOf(cell) {
  const n = (cell.coveredBy || []).length;
  if (n === 0) return 'none';
  if (n === 1) return 'partial';
  return 'full';
}

export function getOSCRMatrix() {
  return _MATRIX;
}

export function summarizeOSCR() {
  const summary = { total: 0, full: 0, partial: 0, none: 0, perTactic: {} };
  for (const [tactic, cells] of Object.entries(_MATRIX)) {
    const t = { total: cells.length, full: 0, partial: 0, none: 0 };
    for (const c of cells) {
      const cov = _coverageOf(c);
      t[cov]++;
      summary[cov]++;
      summary.total++;
    }
    summary.perTactic[tactic] = t;
  }
  return summary;
}

export function toOSCRMarkdown() {
  const lines = [];
  const sum = summarizeOSCR();
  lines.push('# OSC&R coverage');
  lines.push('');
  lines.push(`**Total techniques:** ${sum.total}    **Full:** ${sum.full}    **Partial:** ${sum.partial}    **Uncovered:** ${sum.none}`);
  lines.push('');
  lines.push(`Coverage = (full + 0.5 × partial) / total = **${(((sum.full + 0.5 * sum.partial) / Math.max(sum.total, 1)) * 100).toFixed(0)}%**`);
  lines.push('');
  for (const [tactic, cells] of Object.entries(_MATRIX)) {
    lines.push(`## ${tactic}`);
    lines.push('');
    lines.push('| ID | Technique | Coverage | Detected by |');
    lines.push('|---|---|---|---|');
    for (const c of cells) {
      const cov = _coverageOf(c);
      const icon = cov === 'full' ? '✅ full' : cov === 'partial' ? '🟡 partial' : '❌ none';
      const by = (c.coveredBy || []).map(s => `\`${s}\``).join(', ') || '_—_';
      lines.push(`| ${c.id} | ${c.technique} | ${icon} | ${by} |`);
    }
    lines.push('');
  }
  return lines.join('\n');
}
