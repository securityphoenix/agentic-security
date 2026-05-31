import { test } from 'node:test';
import assert from 'node:assert';
import { annotateProofGate, verdictForFinding, _internals } from '../src/dataflow/proof-gate.js';

function taintFinding(over = {}) {
  return {
    id: 'F1', parser: 'IR-TAINT', severity: 'high',
    confidence: 0.8, confidenceTier: 'high',
    exploitability: 0.7, exploitabilityTier: 'high', exploitabilityFactors: [],
    ...over,
  };
}

test('verdictForFinding classifies the four cases', () => {
  assert.equal(verdictForFinding(taintFinding({ provenClean: true, provenanceProof: { sanitizers: ['setString'] } })).verdict, 'proven-clean');
  assert.equal(verdictForFinding(taintFinding({ _provenUnreachable: true })).verdict, 'proven-infeasible');
  assert.equal(verdictForFinding(taintFinding()).verdict, 'feasible');
  assert.equal(verdictForFinding({ parser: 'sast-regex' }).verdict, 'unproven');
});

test('proven-clean is demoted on confidence + tiers but NOT severity (recall-preserving)', () => {
  const f = taintFinding({ provenClean: true, provenanceProof: { sanitizers: ['setString'] } });
  annotateProofGate([f]);
  assert.equal(f.proof.verdict, 'proven-clean');
  assert.equal(f.proofGated, true);
  // confidence multiplied by DEMOTE_FACTOR (0.8 * 0.4 = 0.32)
  assert.ok(f.confidence < 0.4 && f.confidence > 0.3);
  assert.equal(f._confidenceBeforeProofGate, 0.8);
  assert.equal(f.confidenceTier, 'medium');       // high -> medium
  assert.equal(f.exploitabilityTier, 'medium');   // high -> medium
  assert.ok(f.exploitabilityFactors.includes('proof:proven-clean'));
  // Severity is deliberately preserved so a CI severity gate still fires.
  assert.equal(f.severity, 'high');
});

test('proven-infeasible is also demoted (confidence/tier), severity preserved', () => {
  const f = taintFinding({ _provenUnreachable: true, _provenUnreachableReason: 'sanitizer-excludes-metacharacters:encodeURIComponent' });
  annotateProofGate([f]);
  assert.equal(f.proof.verdict, 'proven-infeasible');
  assert.equal(f.proofGated, true);
  assert.equal(f.severity, 'high');
});

test('feasible and unproven findings are stamped but never demoted', () => {
  const feasible = taintFinding();
  const unproven = { id: 'U', parser: 'sast-regex', severity: 'medium', confidence: 0.6, confidenceTier: 'medium' };
  annotateProofGate([feasible, unproven]);
  assert.equal(feasible.proof.verdict, 'feasible');
  assert.equal(feasible.proofGated, undefined);
  assert.equal(feasible.confidence, 0.8);          // untouched
  assert.equal(unproven.proof.verdict, 'unproven');
  assert.equal(unproven.confidence, 0.6);          // untouched
});

test('stats reflect the demotions and never throws on junk', () => {
  const findings = [
    taintFinding({ provenClean: true }),
    taintFinding({ _provenUnreachable: true }),
    taintFinding(),
    null,
    { parser: 'sast-regex' },
  ];
  annotateProofGate(findings);
  assert.equal(findings._proofGateStats.gated, 2);
  assert.equal(findings._proofGateStats.provenClean, 1);
  assert.equal(findings._proofGateStats.provenInfeasible, 1);
  assert.equal(findings._proofGateStats.feasible, 1);
  assert.equal(findings._proofGateStats.unproven, 1);
});

test('demoteTier floors at the lowest tier', () => {
  assert.equal(_internals.demoteTier('very-low', _internals.CONFIDENCE_TIERS), 'very-low');
  assert.equal(_internals.demoteTier('low', _internals.EXPLOITABILITY_TIERS), 'low');
});

test('annotateProofGate returns non-array inputs unchanged', () => {
  assert.equal(annotateProofGate(null), null);
});
