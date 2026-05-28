// SCA upgrade MCP tools — synthesize_sca_upgrade + apply_sca_upgrade.
// Phase 3 / Item 5 of the SCA improvement plan.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { createServer } from '../src/mcp/server.js';
import { signLastScan } from '../src/posture/integrity.js';
import { planScaUpgrade } from '../src/posture/sca-upgrade.js';

async function makeSession({ findings = [], pkg = null } = {}) {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'as-sca-'));
  const stateDir = path.join(dir, '.agentic-security');
  await fsp.mkdir(stateDir, { recursive: true });
  if (pkg) await fsp.writeFile(path.join(dir, 'package.json'), JSON.stringify(pkg, null, 2));
  const body = JSON.stringify({ supplyChain: findings });
  await fsp.writeFile(path.join(stateDir, 'last-scan.json'), body);
  await fsp.writeFile(path.join(stateDir, 'last-scan.json.sig'), signLastScan(body));
  const { handleRequest } = createServer({ sessionRoot: dir });
  return { root: dir, handleRequest, cleanup: async () => fsp.rm(dir, { recursive: true, force: true }) };
}

function call(handleRequest, name, args, id = 1) {
  return handleRequest({ jsonrpc: '2.0', id, method: 'tools/call', params: { name, arguments: args } });
}
function payload(r) { return JSON.parse(r.result.content[0].text); }

function makeFinding({ id = 'sca-1', name = 'lodash', version = '4.17.20', fixed = '4.17.21', ecosystem = 'npm' } = {}) {
  return {
    id, type: 'vulnerable_dep',
    name, version, ecosystem,
    osvId: 'GHSA-test-0001',
    cveAliases: ['CVE-2020-8203'],
    fixedVersions: [fixed],
    severity: 'high',
    file: 'package.json',
  };
}

// ── planScaUpgrade (direct, unit-level) ─────────────────────────────────────

test('plan: rejects non-vulnerable_dep findings', async () => {
  const plan = await planScaUpgrade({
    scanRoot: '/tmp',
    finding: { type: 'sast-finding', name: 'x' },
  });
  assert.equal(plan.ok, false);
});

test('plan: ecosystem without an automated path returns mode=manual', async () => {
  const plan = await planScaUpgrade({
    scanRoot: '/tmp',
    finding: makeFinding({ ecosystem: 'rubygems' }),
  });
  assert.equal(plan.ok, true);
  assert.equal(plan.mode, 'manual');
  assert.equal(plan.command, null);
  assert.equal(plan.package, 'lodash');
});

test('plan: missing fixed version returns ok:false', async () => {
  const plan = await planScaUpgrade({
    scanRoot: '/tmp',
    finding: { ...makeFinding(), fixedVersions: [] },
  });
  assert.equal(plan.ok, false);
});

test('plan: same-major versions are NOT flagged isBreaking', async () => {
  // We can't actually run `npm install --dry-run` in a unit test (no npm
  // network access guaranteed). Use a fake scanRoot so the dry-run shells
  // out, fails, but the plan still returns the structured metadata.
  const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'as-plan-'));
  try {
    await fsp.writeFile(path.join(tmp, 'package.json'), JSON.stringify({ name: 't', version: '0.0.1' }));
    const plan = await planScaUpgrade({
      scanRoot: tmp,
      finding: makeFinding({ version: '4.17.20', fixed: '4.17.21' }),
    });
    assert.equal(plan.ok, true);
    assert.equal(plan.isBreaking, false);
    assert.equal(plan.ecosystem, 'npm');
    assert.equal(plan.targetVersion, '4.17.21');
    assert.match(plan.command, /^npm install lodash@4\.17\.21/);
  } finally {
    await fsp.rm(tmp, { recursive: true, force: true });
  }
});

test('plan: major-version bump is flagged isBreaking', async () => {
  const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'as-plan-'));
  try {
    await fsp.writeFile(path.join(tmp, 'package.json'), JSON.stringify({ name: 't', version: '0.0.1' }));
    const plan = await planScaUpgrade({
      scanRoot: tmp,
      finding: makeFinding({ version: '3.0.0', fixed: '5.0.0' }),
    });
    assert.equal(plan.isBreaking, true);
  } finally {
    await fsp.rm(tmp, { recursive: true, force: true });
  }
});

// ── MCP synthesize_sca_upgrade ───────────────────────────────────────────────

test('synthesize_sca_upgrade: rejects unknown finding id', async () => {
  const sess = await makeSession({ findings: [makeFinding({ id: 'sca-1' })], pkg: { name: 't' } });
  try {
    const r = await call(sess.handleRequest, 'synthesize_sca_upgrade', { finding_id: 'sca-nope' });
    assert.match(r.result.content[0].text, /Finding not found/);
  } finally { await sess.cleanup(); }
});

test('synthesize_sca_upgrade: rejects SAST findings', async () => {
  const sast = { id: 'sast-1', type: 'xss', vuln: 'XSS', severity: 'high', file: 'a.js' };
  const sess = await makeSession({ findings: [sast], pkg: { name: 't' } });
  // Note: SAST findings live in scan.findings, but our makeSession only
  // populates supplyChain. We re-write last-scan.json to include the SAST
  // finding in the right bucket.
  const body = JSON.stringify({ findings: [sast], supplyChain: [] });
  await fsp.writeFile(path.join(sess.root, '.agentic-security', 'last-scan.json'), body);
  await fsp.writeFile(path.join(sess.root, '.agentic-security', 'last-scan.json.sig'), signLastScan(body));
  try {
    const r = await call(sess.handleRequest, 'synthesize_sca_upgrade', { finding_id: 'sast-1' });
    const p = payload(r);
    assert.equal(p.ok, false);
    assert.match(p.reason, /not an SCA vulnerable_dep/);
  } finally { await sess.cleanup(); }
});

test('synthesize_sca_upgrade: produces a structured plan for valid SCA finding', async () => {
  const sess = await makeSession({
    findings: [makeFinding({ id: 'sca-1' })],
    pkg: { name: 't', version: '0.0.1', dependencies: { lodash: '4.17.20' } },
  });
  try {
    const r = await call(sess.handleRequest, 'synthesize_sca_upgrade', { finding_id: 'sca-1' });
    const p = payload(r);
    assert.equal(p.ok, true);
    assert.equal(p.ecosystem, 'npm');
    assert.equal(p.package, 'lodash');
    assert.equal(p.targetVersion, '4.17.21');
    assert.equal(p.isBreaking, false);
    assert.match(p.command, /npm install lodash@4\.17\.21/);
  } finally { await sess.cleanup(); }
});

// ── MCP apply_sca_upgrade ────────────────────────────────────────────────────

test('apply_sca_upgrade: refuses without confirm:true', async () => {
  const sess = await makeSession({ findings: [makeFinding({ id: 'sca-1' })], pkg: { name: 't' } });
  try {
    const r = await call(sess.handleRequest, 'apply_sca_upgrade', { finding_id: 'sca-1', confirm: false });
    const p = payload(r);
    assert.equal(p.applied, false);
    assert.match(p.reason, /requires confirm/);
  } finally { await sess.cleanup(); }
});

test('apply_sca_upgrade: rejects SAST findings', async () => {
  const sast = { id: 'sast-1', type: 'xss', vuln: 'XSS', severity: 'high', file: 'a.js' };
  const sess = await makeSession({ findings: [], pkg: { name: 't' } });
  const body = JSON.stringify({ findings: [sast], supplyChain: [] });
  await fsp.writeFile(path.join(sess.root, '.agentic-security', 'last-scan.json'), body);
  await fsp.writeFile(path.join(sess.root, '.agentic-security', 'last-scan.json.sig'), signLastScan(body));
  try {
    const r = await call(sess.handleRequest, 'apply_sca_upgrade', { finding_id: 'sast-1', confirm: true });
    const p = payload(r);
    assert.equal(p.applied, false);
    assert.match(p.reason, /not an SCA vulnerable_dep/);
  } finally { await sess.cleanup(); }
});

test('apply_sca_upgrade: rejects unknown finding id', async () => {
  const sess = await makeSession({ findings: [makeFinding({ id: 'sca-1' })], pkg: { name: 't' } });
  try {
    const r = await call(sess.handleRequest, 'apply_sca_upgrade', { finding_id: 'sca-nope', confirm: true });
    const p = payload(r);
    assert.equal(p.applied, false);
    assert.match(p.reason, /Finding not found/);
  } finally { await sess.cleanup(); }
});

test('apply_sca_upgrade: ecosystem with no automation returns mode=manual', async () => {
  const sess = await makeSession({
    findings: [makeFinding({ id: 'sca-1', ecosystem: 'rubygems' })],
    pkg: { name: 't' },
  });
  try {
    const r = await call(sess.handleRequest, 'apply_sca_upgrade', { finding_id: 'sca-1', confirm: true });
    const p = payload(r);
    assert.equal(p.applied, false);
    assert.match(p.reason, /no automated upgrade in v1/);
  } finally { await sess.cleanup(); }
});

// ── tools/list now exposes the two new tools ─────────────────────────────────

test('tools/list exposes synthesize_sca_upgrade + apply_sca_upgrade', async () => {
  const sess = await makeSession();
  try {
    const r = await sess.handleRequest({ jsonrpc: '2.0', id: 99, method: 'tools/list' });
    const names = r.result.tools.map(t => t.name);
    assert.ok(names.includes('synthesize_sca_upgrade'));
    assert.ok(names.includes('apply_sca_upgrade'));
  } finally { await sess.cleanup(); }
});
