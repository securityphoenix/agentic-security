// 0.6.0 Feat-4: Drift report — verify diffing two synthetic scans.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { driftBetween, driftToMarkdown } from '../src/posture/drift.js';

const baseScan = {
  routes: [
    { method: 'GET',  path: '/users',   file: 'app.js', line: 10, hasAuth: true,  classifications: ['PII'] },
    { method: 'POST', path: '/login',   file: 'app.js', line: 20, hasAuth: false, classifications: [] },
  ],
  components: [
    { ecosystem: 'npm', name: 'express', version: '4.18.0' },
    { ecosystem: 'npm', name: 'lodash',  version: '4.17.20' },
  ],
  supplyChain: [
    { type: 'vulnerable_dep', ecosystem: 'npm', name: 'lodash', version: '4.17.20', severity: 'high', osvId: 'GHSA-old' },
  ],
  findings: [],
  logicVulns: [],
};

const newScan = JSON.parse(JSON.stringify(baseScan));
// Drop auth from /users
newScan.routes[0].hasAuth = false;
// Add a new unauthenticated endpoint
newScan.routes.push({ method: 'GET', path: '/admin', file: 'admin.js', line: 5, hasAuth: false, classifications: ['Confidential'] });
// Add a new dep
newScan.components.push({ ecosystem: 'npm', name: 'jsonwebtoken', version: '8.5.1' });
// Add a new critical finding
newScan.findings.push({ kind: 'sast', severity: 'critical', vuln: 'SQL Injection', file: 'admin.js', line: 12 });

test('Drift — auth boundary lost flagged as critical tier', () => {
  const d = driftBetween(baseScan, newScan);
  assert.equal(d.tier, 'critical', `expected critical tier; got ${d.tier}`);
  assert.equal(d.authBoundaries.lost.length, 1);
  assert.equal(d.authBoundaries.lost[0].path, '/users');
});

test('Drift — added endpoints, deps, and findings are surfaced', () => {
  const d = driftBetween(baseScan, newScan);
  assert.equal(d.routes.added.length, 1);
  assert.equal(d.routes.added[0].path, '/admin');
  assert.equal(d.deps.added.length, 1);
  assert.equal(d.deps.added[0].name, 'jsonwebtoken');
  assert.equal(d.findings.added.length, 1);
  assert.equal(d.findings.added[0].vuln, 'SQL Injection');
});

test('Drift — newly exposed data class detected (Confidential added)', () => {
  const d = driftBetween(baseScan, newScan);
  assert.ok(d.dataClasses.newlyExposed.includes('Confidential'),
    `expected Confidential newly exposed; got: ${d.dataClasses.newlyExposed.join(', ')}`);
});

test('Drift — driftToMarkdown produces a usable report', () => {
  const md = driftToMarkdown(driftBetween(baseScan, newScan));
  assert.ok(/Posture drift/.test(md), 'header missing');
  assert.ok(/Auth boundaries LOST/i.test(md), 'auth-lost section missing');
  assert.ok(/admin/.test(md), 'new endpoint not surfaced');
  assert.ok(/SQL Injection/.test(md) || /New findings/.test(md), 'new findings not surfaced');
});

test('Drift — identical scans produce info tier with no changes', () => {
  const d = driftBetween(baseScan, baseScan);
  assert.equal(d.tier, 'info');
  assert.equal(d.totalChanged, 0);
});
