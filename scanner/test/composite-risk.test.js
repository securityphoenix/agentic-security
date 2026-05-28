// composite-risk.js — unit tests for the derived 0–100 ordinal.
//
// Verifies:
//   - exploitability * 100 is the primary base.
//   - mitigationVerdict scales the base (mitigated → 0.4×, unreachable → 0.2×).
//   - KEV / exploitedNow set floors regardless of other signals.
//   - toxicityScore contributes a capped nudge.
//   - severity-only fallback when exploitability is missing.
//   - tier thresholds match the documented bands.
//   - errors degrade gracefully (no-throw contract).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { annotateCompositeRisk } from '../src/posture/composite-risk.js';

function one(finding) {
  const arr = [finding];
  annotateCompositeRisk(arr);
  return arr[0];
}

test('exploitability=0.65, exposed-in-prod → ~65', () => {
  const f = one({ exploitability: 0.65, mitigationVerdict: 'exposed-in-prod', severity: 'high' });
  assert.equal(f.compositeRisk, 65);
  assert.equal(f.compositeRiskTier, 'high');
  assert.ok(f.compositeRiskFactors.includes('exploit:0.65'));
  assert.ok(f.compositeRiskFactors.includes('exposed-in-prod'));
});

test('mitigated-in-prod multiplies by 0.4', () => {
  const f = one({ exploitability: 0.80, mitigationVerdict: 'mitigated-in-prod', severity: 'critical' });
  // 80 * 0.4 = 32
  assert.equal(f.compositeRisk, 32);
  assert.equal(f.compositeRiskTier, 'low');
  assert.ok(f.compositeRiskFactors.includes('mitigated-in-prod'));
});

test('unreachable-in-prod multiplies by 0.2', () => {
  const f = one({ exploitability: 0.80, mitigationVerdict: 'unreachable-in-prod', severity: 'critical' });
  // 80 * 0.2 = 16
  assert.equal(f.compositeRisk, 16);
  assert.equal(f.compositeRiskTier, 'low');
});

test('KEV floor lifts a low-exploitability finding to ≥80', () => {
  const f = one({ exploitability: 0.30, kev: true, severity: 'medium', mitigationVerdict: 'exposed-in-prod' });
  assert.ok(f.compositeRisk >= 80, `expected ≥80, got ${f.compositeRisk}`);
  assert.equal(f.compositeRiskTier, 'high'); // 80 lands in 'high', not 'critical' (≥85)
  assert.ok(f.compositeRiskFactors.includes('kev-floor:80'));
});

test('exploitedNow floor lifts to ≥75', () => {
  const f = one({ exploitability: 0.20, exploitedNow: true, severity: 'low', mitigationVerdict: 'exposed-in-prod' });
  assert.ok(f.compositeRisk >= 75);
  assert.ok(f.compositeRiskFactors.includes('exploited-now-floor:75'));
});

test('toxicityScore adds a capped nudge', () => {
  const noTox  = one({ exploitability: 0.50, mitigationVerdict: 'exposed-in-prod', severity: 'medium' });
  const lowTox = one({ exploitability: 0.50, mitigationVerdict: 'exposed-in-prod', severity: 'medium', toxicityScore: 40 });
  const highTox= one({ exploitability: 0.50, mitigationVerdict: 'exposed-in-prod', severity: 'medium', toxicityScore: 999 });
  assert.equal(noTox.compositeRisk, 50);
  assert.equal(lowTox.compositeRisk, 54);   // 50 + min(15, 40/10) = 54
  assert.equal(highTox.compositeRisk, 65);  // 50 + min(15, 99.9) = 65 (cap)
  assert.ok(highTox.compositeRiskFactors.some(s => s.startsWith('toxicity+')));
});

test('severity-only fallback when exploitability missing', () => {
  const f = one({ severity: 'high', mitigationVerdict: 'exposed-in-prod' });
  // sev-only base for high is 55, no other signals.
  assert.equal(f.compositeRisk, 55);
  assert.ok(f.compositeRiskFactors.includes('sev-only:high'));
});

test('tier thresholds match documented bands', () => {
  const banded = (score) => {
    const f = one({ exploitability: score / 100, mitigationVerdict: 'exposed-in-prod' });
    return f.compositeRiskTier;
  };
  assert.equal(banded(90), 'critical');
  assert.equal(banded(85), 'critical');
  assert.equal(banded(84), 'high');
  assert.equal(banded(65), 'high');
  assert.equal(banded(60), 'medium');
  assert.equal(banded(35), 'medium');
  assert.equal(banded(20), 'low');
  assert.equal(banded(15), 'low');
  assert.equal(banded(10), 'minimal');
  assert.equal(banded(0), 'minimal');
});

test('non-array input passes through', () => {
  assert.equal(annotateCompositeRisk(null), null);
  assert.equal(annotateCompositeRisk(undefined), undefined);
});

test('malformed entries are skipped without throwing', () => {
  const arr = [null, undefined, 'string', 42, { severity: 'medium', mitigationVerdict: 'exposed-in-prod' }];
  assert.doesNotThrow(() => annotateCompositeRisk(arr));
  // Only the object got annotated.
  assert.equal(arr[4].compositeRisk, 35); // sev-only:medium=35
});

test('SCA-style finding (no exploitability) with KEV + EPSS', () => {
  const f = one({
    type: 'vulnerable_dep',
    severity: 'high',
    kev: true,
    epssScore: 0.92,
    epssPercentile: 0.99,
    exploitedNow: true,
    toxicityScore: 50,
  });
  // KEV floor at 80, exploitedNow floor at 75 (lower); toxicity adds 5; cap at 100.
  // base = 80 (KEV floor) + 5 (toxicity 50/10) = 85 → 'critical'
  assert.ok(f.compositeRisk >= 80);
  assert.ok(['high','critical'].includes(f.compositeRiskTier));
});

test('idempotent: re-running yields the same result', () => {
  const f = { exploitability: 0.65, mitigationVerdict: 'exposed-in-prod', severity: 'high' };
  annotateCompositeRisk([f]);
  const first = f.compositeRisk;
  annotateCompositeRisk([f]);
  assert.equal(f.compositeRisk, first);
});
