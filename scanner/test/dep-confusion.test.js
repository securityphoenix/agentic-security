// 0.9.0 Feat-15: Dependency confusion + typosquat tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { levenshtein, detectDepConfusion } from '../src/sca/dep-confusion.js';

test('Levenshtein — basic distances + maxDistance early exit', () => {
  assert.equal(levenshtein('lodash', 'lodash'), 0);
  assert.equal(levenshtein('lodahs', 'lodash'), 2);  // transposition = 2 substitutions in plain Levenshtein
  assert.equal(levenshtein('loadash', 'lodash'), 1); // single insertion
  assert.equal(levenshtein('lodas', 'lodash'), 1);   // single deletion
  assert.equal(levenshtein('react', 'reactt'), 1);
  assert.equal(levenshtein('aaaa', 'bbbbbbbbb'), 3); // > maxDistance → 3 (early exit returns max+1)
});

test('Typosquat detection — flags 1–2 edit distance from popular packages', () => {
  const components = [
    { ecosystem: 'npm', name: 'lodahs',  version: '1.0.0', filePath: 'package.json' }, // 2-edit from lodash
    { ecosystem: 'npm', name: 'lodash',  version: '4.17.21', filePath: 'package.json' }, // legitimate
    { ecosystem: 'npm', name: 'reactt',  version: '1.0.0', filePath: 'package.json' }, // 1-edit from react
    { ecosystem: 'npm', name: 'totally-novel-name', version: '1.0.0', filePath: 'package.json' }, // novel — no match
  ];
  const findings = detectDepConfusion(components, null);
  assert.equal(findings.length, 2, `expected 2 typosquat findings; got ${findings.length}: ${findings.map(f=>f.vuln).join(', ')}`);
  // 1-edit (reactt) is critical, 2-edit (lodahs) is high
  const reactFinding = findings.find(f => /reactt/.test(f.vuln));
  assert.equal(reactFinding.severity, 'critical');
  const lodashFinding = findings.find(f => /lodahs/.test(f.vuln));
  assert.equal(lodashFinding.severity, 'high');
});

test('Typosquat — popular package itself does NOT trigger', () => {
  const components = [{ ecosystem: 'npm', name: 'lodash', version: '4.17.21' }];
  const findings = detectDepConfusion(components, null);
  assert.equal(findings.length, 0);
});

test('Typosquat — unrelated package names do not match', () => {
  const components = [
    { ecosystem: 'npm', name: 'my-internal-utility', version: '1.0.0' },
    { ecosystem: 'npm', name: '@mycompany/sdk', version: '2.0.0' },
  ];
  const findings = detectDepConfusion(components, null);
  // Without internal-scopes.yml, the @mycompany/sdk shouldn't fire.
  assert.equal(findings.length, 0);
});
