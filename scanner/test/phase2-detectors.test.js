// Phase-2 (Sentinel-parity) — Kotlin / Ruby / PHP / cross-lang regression tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../src/runScan.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (name) => path.join(__dirname, 'fixtures', name);

async function findingsFor(dir) {
  const { scan } = await runScan(dir);
  return scan.findings || [];
}

test('kotlin: force-unwrap + Runtime.exec + unsafe YAML + Gson polymorphic + File.readText fire', async () => {
  const fs = await findingsFor(FIX('kotlin-sast'));
  const vuln = fs.filter(f => f.file.endsWith('vuln.kt'));
  assert.ok(vuln.some(f => /force-unwrap/i.test(f.vuln)), 'force-unwrap (!!) should fire');
  assert.ok(vuln.some(f => /Command Injection.*Runtime\.exec/i.test(f.vuln)), 'Runtime.exec should fire');
  assert.ok(vuln.some(f => /YAML\.load/i.test(f.vuln) || /Unsafe YAML/i.test(f.vuln)), 'YAML.load should fire');
  assert.ok(vuln.some(f => /Gson polymorphic/i.test(f.vuln)), 'Gson polymorphic should fire');
  assert.ok(vuln.some(f => /File\.readText|Path Traversal/i.test(f.vuln)), 'File.readText should fire');
  const safe = fs.filter(f => f.file.endsWith('safe.kt') && /Kotlin|Yaml/.test(f.parser || ''));
  // The safe Kotlin file should not raise force-unwrap / unsafe YAML.
  assert.ok(!safe.some(f => /force-unwrap/i.test(f.vuln)), 'safe Kotlin should not fire force-unwrap');
  assert.ok(!safe.some(f => /Unsafe YAML/i.test(f.vuln)), 'safe Kotlin should not fire unsafe YAML');
});

test('ruby: eval / send / Marshal.load / YAML.load / backtick / mass-assign fire', async () => {
  const fs = await findingsFor(FIX('ruby-sast'));
  const vuln = fs.filter(f => f.file.endsWith('vuln.rb'));
  for (const expect of [/eval\b/, /send\b|Method Reflection/, /Marshal\.load/, /YAML\.load|safe_load/i, /Command Injection.*backtick/i, /Mass Assignment/]) {
    assert.ok(vuln.some(f => expect.test(f.vuln)), `expected match: ${expect}`);
  }
  const safe = fs.filter(f => f.file.endsWith('safe.rb') && f.parser === 'RUBY');
  assert.equal(safe.length, 0, `safe Ruby should produce zero Ruby findings, got: ${safe.map(f=>f.vuln).join(', ')}`);
});

test('php: dangerous call / unserialize / include / mysql concat / extract / md5 / phpinfo fire', async () => {
  const fs = await findingsFor(FIX('php-sast'));
  const vuln = fs.filter(f => f.file.endsWith('vuln.php'));
  for (const expect of [/Command\/Code Injection/, /Insecure Deserialization/, /File Inclusion/, /SQL Injection/, /Variable Injection|extract/i, /Weak password hashing/i, /phpinfo/i]) {
    assert.ok(vuln.some(f => expect.test(f.vuln)), `expected match: ${expect}`);
  }
  const safe = fs.filter(f => f.file.endsWith('safe.php') && f.parser === 'PHP');
  // Safe PHP may fire phpinfo if the file contains it — but our safe.php doesn't.
  assert.ok(!safe.some(f => /Variable Injection|Insecure Deserialization|File Inclusion|SQL Injection|Command\/Code/i.test(f.vuln)),
    'safe PHP should not fire the high-severity PHP rules');
});

test('cross-lang openapi: client → server with finding propagates as chain', async () => {
  const fs = await findingsFor(FIX('xlang-openapi'));
  const xl = fs.filter(f => f.cross_language || (f.parser === 'XLANG-OPENAPI'));
  assert.ok(xl.length >= 1, `expected at least one cross-language finding, got ${xl.length}`);
  const f = xl[0];
  assert.ok(/client\.js$/.test(f.file), `cross-lang finding should originate at the client site, got ${f.file}`);
  assert.ok(Array.isArray(f.chain) && f.chain.length === 3,
    'cross-lang chain should have 3 hops (client, route, server-finding)');
});

test('SARIF emit: confidence + exploitability + stableId surface as properties', async () => {
  const { scan } = await runScan(FIX('mass-assignment'));
  const { toSARIF } = await import('../src/report/index.js');
  const sarif = toSARIF(scan, { scanId: 'test' });
  const r = sarif.runs[0].results[0];
  assert.ok(r.properties, 'SARIF result must have properties');
  assert.ok(typeof r.properties.confidence === 'number', 'confidence should be in properties');
  assert.ok(typeof r.properties.exploitability === 'number', 'exploitability should be in properties');
  assert.ok(r.properties.exploitabilityTier, 'exploitabilityTier should be in properties');
  assert.ok(r.partialFingerprints.stableId, 'stableId should be in partialFingerprints');
});

test('LLM validator scaffold: no endpoint configured → every finding gets unvalidated', async () => {
  delete process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  delete process.env.AGENTIC_SECURITY_LLM_VALIDATE;
  const fs = await findingsFor(FIX('mass-assignment'));
  assert.ok(fs.every(f => f.validator_verdict === 'unvalidated'),
    'with no endpoint, every finding must be unvalidated');
});

test('Closed-loop verify: rescan returns ok=true when patch removes the finding', async () => {
  const { verifyPatch } = await import('../src/posture/fix-verify.js');
  // A patched "safe" version of vuln-express-objassign.js — the Mass Assignment
  // detector should no longer fire on this content.
  const safe = `const _ = require('lodash');
module.exports = async function update(req, res) {
  const allowed = _.pick(req.body, ['name', 'email']);
  const u = await User.create(allowed);
  res.json(u);
};
`;
  // First get the stableId of the original finding.
  const fs1 = await findingsFor(FIX('mass-assignment'));
  const orig = fs1.find(f => /Mass Assignment/.test(f.vuln) && f.file.endsWith('vuln-express-objassign.js'));
  assert.ok(orig && orig.stableId, 'original finding should exist with stableId');
  const r = await verifyPatch({
    scanRoot: FIX('mass-assignment'),
    originalFindingStableId: orig.stableId,
    files: { 'vuln-express-objassign.js': safe },
  });
  // The patch removes the original Mass Assignment finding. ok=true unless
  // the patch introduced something new at high+ — which the safe shape doesn't.
  assert.ok(r.ok, `rescan should pass: ${JSON.stringify(r)}`);
});
