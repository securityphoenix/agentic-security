// Shared F1 evaluation harness for detector tests.
//
// Each detector test imports `evaluateF1` and passes a labels[] array describing
// the expected detector behaviour over a fixture directory. The harness scans
// the directory once, computes precision/recall/F1, prints a debug trace, and
// asserts against per-detector floor thresholds.
//
// Usage:
//
//   import { evaluateF1 } from './helpers/f1.js';
//
//   const labels = [
//     { file: 'vuln-x.js',  positive: true,  matcher: /Vuln Title/i },
//     { file: 'safe-y.js',  positive: false, matcher: /Vuln Title/i },
//   ];
//   await evaluateF1({
//     name: 'My-detector', fixtureDir: 'my-fixtures', labels,
//     floors: { precision: 0.85, recall: 0.85, f1: 0.85 },
//   });

import assert from 'node:assert/strict';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../../src/runScan.js';
import { normalizeFindings } from '../../src/report/index.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (name) => path.join(__dirname, '..', 'fixtures', name);

export async function evaluateF1({ name, fixtureDir, labels, floors = {} }) {
  const { f1: f1Floor = 0.85, precision: pFloor = 0.83, recall: rFloor = 0.83 } = floors;
  const { scan } = await runScan(FIX(fixtureDir));
  const findings = normalizeFindings(scan);

  let TP = 0, FP = 0, FN = 0, TN = 0;
  const detail = [];

  for (const lbl of labels) {
    const matched = findings.some(f =>
      f.file.endsWith(lbl.file) && lbl.matcher.test(f.vuln));
    if (lbl.positive && matched)        { TP++; detail.push(`TP ${lbl.file}`); }
    else if (lbl.positive && !matched)  { FN++; detail.push(`FN ${lbl.file}  (missed)`); }
    else if (!lbl.positive && matched)  {
      const off = findings.find(f => f.file.endsWith(lbl.file) && lbl.matcher.test(f.vuln));
      FP++; detail.push(`FP ${lbl.file}  (${off?.vuln})`);
    } else                              { TN++; detail.push(`TN ${lbl.file}`); }
  }

  const precision = TP / Math.max(TP + FP, 1);
  const recall    = TP / Math.max(TP + FN, 1);
  const f1        = (2 * precision * recall) / Math.max(precision + recall, 1e-9);

  // eslint-disable-next-line no-console
  console.log(`[${name}] TP=${TP} FP=${FP} FN=${FN} TN=${TN} | P=${precision.toFixed(2)} R=${recall.toFixed(2)} F1=${f1.toFixed(2)}\n  ${detail.join('\n  ')}`);

  assert.ok(f1        >= f1Floor, `${name}: F1 below floor: ${f1.toFixed(2)} (P=${precision.toFixed(2)}, R=${recall.toFixed(2)});\n  ${detail.join('\n  ')}`);
  assert.ok(recall    >= rFloor,  `${name}: recall below floor: ${recall.toFixed(2)}`);
  assert.ok(precision >= pFloor,  `${name}: precision below floor: ${precision.toFixed(2)}`);

  return { TP, FP, FN, TN, precision, recall, f1 };
}
