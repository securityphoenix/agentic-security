// FR-VER-3 regression-test generator tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { annotateRegressionTests } from '../src/posture/regression-test-gen.js';
import { generatePoc } from '../src/posture/poc-generator.js';

test('annotateRegressionTests emits Jest test for a Node PoC', () => {
  const finding = {
    vuln: 'SQL Injection',
    cwe: 'CWE-89',
    stableId: 'abc123',
    poc: generatePoc({ vuln: 'SQL Injection', cwe: 'CWE-89' }, { routes: [] }),
  };
  annotateRegressionTests([finding]);
  assert.ok(finding.regression_test);
  assert.equal(finding.regression_test.framework, 'jest');
  assert.equal(finding.regression_test.lang, 'node');
  assert.match(finding.regression_test.filename, /\.test\.mjs$/);
  assert.ok(finding.regression_test.code.includes('@jest/globals'));
  assert.ok(finding.regression_test.code.includes("expect(demonstrated).toBe(false)"));
});

test('annotateRegressionTests emits null when no PoC', () => {
  const f = { vuln: 'X', cwe: 'CWE-1' };
  annotateRegressionTests([f]);
  assert.equal(f.regression_test, null);
});

test('annotateRegressionTests never throws on garbage', () => {
  assert.doesNotThrow(() => annotateRegressionTests(null));
  assert.doesNotThrow(() => annotateRegressionTests([null, undefined, {}]));
});

test('filename slug is bounded length', () => {
  const long = 'a'.repeat(200);
  const f = {
    vuln: 'X', stableId: long,
    poc: generatePoc({ vuln: 'SQL Injection', cwe: 'CWE-89' }, { routes: [] }),
  };
  annotateRegressionTests([f]);
  assert.ok(f.regression_test.filename.length < 80);
});
