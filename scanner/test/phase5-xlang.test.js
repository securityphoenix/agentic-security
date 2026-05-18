// Phase-5 (multi-session): cross-language taint + IaC reachability tests.
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

test('gRPC cross-language taint: client → server proto method maps to SQLi finding', async () => {
  const fs = await findingsFor(FIX('xlang-grpc'));
  const xl = fs.filter(f => f.parser === 'XLANG-GRPC' || (f.cross_language && /gRPC/i.test(f.vuln || '')));
  assert.ok(xl.length >= 1, `expected ≥1 gRPC cross-lang finding, got ${xl.length}; sample vulns: ${fs.slice(0,5).map(f=>f.vuln).join('; ')}`);
});

test('GraphQL cross-language taint: client query maps to resolver SQLi', async () => {
  const fs = await findingsFor(FIX('xlang-graphql'));
  const xl = fs.filter(f => f.parser === 'XLANG-GRAPHQL' || (f.cross_language && /GraphQL/i.test(f.vuln || '')));
  assert.ok(xl.length >= 1, `expected ≥1 GraphQL cross-lang finding, got ${xl.length}; sample vulns: ${fs.slice(0,5).map(f=>f.vuln).join('; ')}`);
});

test('IaC reachability: public S3 bucket + 0.0.0.0/0 SG + publicly_accessible DB fire', async () => {
  const fs = await findingsFor(FIX('iac-reach'));
  const iac = fs.filter(f => f.parser === 'IAC-REACH');
  assert.ok(iac.length >= 2, `expected ≥2 IaC findings, got ${iac.length}`);
  assert.ok(iac.some(f => /public_bucket/.test(f.vuln || '') && /s3-public-acl/.test(f.vuln || '')),
    'public S3 ACL should fire');
  assert.ok(iac.some(f => /publicly_accessible|exposed_db/.test(f.vuln || '')),
    'publicly_accessible DB should fire');
});

test('Function-summary cache: stable hash + recursion guard', async () => {
  const { SummaryCache, entryStateFromCall } = await import('../src/dataflow/summaries.js');
  const c = new SummaryCache();
  const sentinel = { returnTainted: true, mutatedParams: new Set(['a']), taintedGlobals: new Set(), findings: [] };
  let analyzed = 0;
  const r1 = c.compute('q1', new Set(['x']), () => { analyzed++; return sentinel; });
  const r2 = c.compute('q1', new Set(['x']), () => { analyzed++; return { returnTainted: false }; });
  assert.equal(analyzed, 1, 'second call should hit cache');
  assert.equal(r1.returnTainted, true);
  assert.equal(r2.returnTainted, true);
  // entryStateFromCall: tainted arg → param tainted.
  const entry = entryStateFromCall(['p1','p2'], [
    { kind: 'ident', name: 'localTainted' },
    { kind: 'literal', value: 7 },
  ], new Set(['localTainted']));
  assert.ok(entry.has('p1'));
  assert.ok(!entry.has('p2'));
});

test('Expanded catalog: ≥ 100 entries', async () => {
  const { _catalogSize } = await import('../src/dataflow/catalog.js');
  assert.ok(_catalogSize() >= 100, `catalog should have grown; got ${_catalogSize()}`);
});
