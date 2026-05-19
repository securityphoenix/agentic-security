// FR-SDLC-9 policy gate tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { evaluatePolicy, _internals } from '../src/posture/policy-gate.js';

function _writePolicy(text) {
  const fp = path.join(os.tmpdir(), `as-policy-${Date.now()}-${Math.random().toString(36).slice(2,6)}.rego`);
  fs.writeFileSync(fp, text);
  return fp;
}

test('evaluatePolicy denies critical findings via embedded mini-DSL', () => {
  const policy = `
package agentic
deny[msg] {
  finding.severity == "critical"
  msg := "critical finding present"
}
`;
  const fp = _writePolicy(policy);
  const r = evaluatePolicy(fp, [
    { severity: 'critical', vuln: 'X', file: 'a.js' },
    { severity: 'low',      vuln: 'Y', file: 'b.js' },
  ], { embeddedOnly: true });
  assert.equal(r.ok, true);
  assert.equal(r.denials.length, 1);
  assert.match(r.denials[0], /critical finding present/);
  fs.unlinkSync(fp);
});

test('evaluatePolicy passes when no findings match', () => {
  const policy = `
package x
deny[msg] {
  finding.severity == "critical"
  msg := "no"
}
`;
  const fp = _writePolicy(policy);
  const r = evaluatePolicy(fp, [
    { severity: 'low', vuln: 'X' },
  ], { embeddedOnly: true });
  assert.deepEqual(r.denials, []);
  fs.unlinkSync(fp);
});

test('evaluatePolicy returns reason when policy file missing', () => {
  const r = evaluatePolicy('/no/such/file.rego', []);
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'policy-file-missing');
});

test('evaluatePolicy sprintf renders msg', () => {
  const policy = `
deny[msg] {
  finding.severity == "high"
  msg := sprintf("%v at %v", [finding.vuln, finding.file])
}
`;
  const fp = _writePolicy(policy);
  const r = evaluatePolicy(fp, [{ severity: 'high', vuln: 'SQL', file: 'app.js' }], { embeddedOnly: true });
  assert.equal(r.denials.length, 1);
  assert.equal(r.denials[0], 'SQL at app.js');
  fs.unlinkSync(fp);
});

test('mini parser supports >, <, >=, <=, !=', () => {
  const policy = `
deny[msg] {
  finding.confidence >= 0.8
  msg := "high-conf finding"
}
`;
  const fp = _writePolicy(policy);
  const r = evaluatePolicy(fp, [
    { confidence: 0.9, vuln: 'A' },
    { confidence: 0.5, vuln: 'B' },
  ], { embeddedOnly: true });
  assert.equal(r.denials.length, 1);
  fs.unlinkSync(fp);
});

test('_internals expose the parser and evaluator', () => {
  assert.equal(typeof _internals._parseEmbedded, 'function');
  assert.equal(typeof _internals._evalBlock, 'function');
});
