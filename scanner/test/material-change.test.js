// 0.6.0 Feat-3: Material change detection — F1 over labelled synthetic diffs.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import * as fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { classifyDiff } from '../src/posture/material-change.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fixturesPath = path.join(__dirname, 'fixtures', 'material-change', 'diffs.json');
const FIXTURES = JSON.parse(fs.readFileSync(fixturesPath, 'utf8'));

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };

test('Material change detection — classifyDiff hits expected severity tier per fixture', () => {
  let TP = 0, FP = 0, FN = 0;
  const detail = [];
  for (const [name, fx] of Object.entries(FIXTURES)) {
    if (name.startsWith('_')) continue;
    const isVuln = name.startsWith('vuln_');
    const result = classifyDiff(fx.diff);
    const got = result.materialRisk;
    const expected = fx.expectedSeverity;
    // Vuln cases: result must be at least the expected severity tier
    if (isVuln) {
      if (SEV_RANK[got] >= SEV_RANK[expected]) { TP++; detail.push(`TP ${name} (${got}>=${expected})`); }
      else { FN++; detail.push(`FN ${name} (got ${got}, expected ${expected})`); }
    } else {
      // Routine cases: result must NOT exceed 'low'
      if (SEV_RANK[got] <= SEV_RANK['low']) { detail.push(`TN ${name} (got ${got})`); }
      else { FP++; detail.push(`FP ${name} (got ${got}; expected ≤ low)`); }
    }
  }
  const precision = TP / Math.max(TP + FP, 1);
  const recall    = TP / Math.max(TP + FN, 1);
  const f1        = (2 * precision * recall) / Math.max(precision + recall, 1e-9);
  // eslint-disable-next-line no-console
  console.log(`[Material-change] TP=${TP} FP=${FP} FN=${FN} | P=${precision.toFixed(2)} R=${recall.toFixed(2)} F1=${f1.toFixed(2)}\n  ${detail.join('\n  ')}`);
  assert.ok(f1        >= 0.85, `F1 below floor: ${f1.toFixed(2)};\n  ${detail.join('\n  ')}`);
  assert.ok(recall    >= 0.83, `recall below floor: ${recall.toFixed(2)}`);
  assert.ok(precision >= 0.83, `precision below floor: ${precision.toFixed(2)}`);
});

test('Material change detection — single auth-removed hunk lands as critical', () => {
  const r = classifyDiff(FIXTURES.vuln_auth_removed.diff);
  assert.equal(r.materialRisk, 'critical');
  assert.ok(r.findings.some(f => f.kind === 'auth-removed'), `expected auth-removed kind; got: ${r.findings.map(f => f.kind).join(', ')}`);
});

test('Material change detection — pure comment add lands as none/low', () => {
  const r = classifyDiff(FIXTURES.routine_comment_only.diff);
  assert.ok(r.materialRisk === 'none' || r.materialRisk === 'low', `got ${r.materialRisk}`);
});
