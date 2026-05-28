// SCA batched EPSS lookups — verify that _enrichWithEPSS makes one HTTP
// request per 100 CVEs instead of one per CVE.
//
// The engine has its own disk-backed sessionStorage shim under
// ~/.claude/agentic-security/osv-cache/. To avoid that cache returning
// stale data from prior runs, every test uses a unique CVE-id range
// keyed off process.pid + Date.now().

import { test } from 'node:test';
import assert from 'node:assert/strict';

// Track every fetch call so we can assert on batching.
let fetchCalls = [];
globalThis.fetch = async (url) => {
  fetchCalls.push(url);
  const m = String(url).match(/[?&]cve=([^&]+)/);
  const cves = m ? decodeURIComponent(m[1]).split(',') : [];
  const data = cves.map((cve, i) => ({
    cve,
    epss: (0.001 * (i + 1)).toFixed(4),
    percentile: (0.5 + 0.001 * i).toFixed(4),
  }));
  return { ok: true, json: async () => ({ data }) };
};

delete process.env.AGENTIC_SECURITY_OFFLINE;

const { _enrichWithEPSS, _fetchEPSSBatch } = await import('../src/engine.js');

// Per-run-unique CVE namespace so we never collide with a prior run's cache.
// Format: CVE-9{run}-{seq6}. The leading 9 in year position ensures we never
// collide with a real CVE id, and {run} disambiguates across test invocations.
const RUN_ID = String(process.pid).slice(-3).padStart(3, '0');
function cveId(seq) {
  return `CVE-9${RUN_ID}-${String(seq).padStart(6, '0')}`;
}
function makeFinding(cve, name) {
  return { type: 'vulnerable_dep', name: name || 'pkg', cveAliases: [cve] };
}

test('EPSS: single CVE → one batched request', async () => {
  fetchCalls = [];
  const cve = cveId(100001);
  const out = await _enrichWithEPSS([makeFinding(cve, 'lodash')]);
  assert.equal(fetchCalls.length, 1, 'exactly one HTTP request');
  assert.match(fetchCalls[0], new RegExp(`cve=${cve}`));
  assert.ok(out[0].epssScore != null, 'epssScore populated');
});

test('EPSS: 50 CVEs → one batched request (under batch size)', async () => {
  fetchCalls = [];
  const findings = Array.from({ length: 50 }, (_, i) =>
    makeFinding(cveId(200000 + i + 1), `pkg${i}`));
  await _enrichWithEPSS(findings);
  assert.equal(fetchCalls.length, 1, 'one batched request for 50 CVEs');
  const cveCount = (fetchCalls[0].match(/CVE-/g) || []).length;
  assert.equal(cveCount, 50, 'all 50 CVEs in one request');
});

test('EPSS: 250 CVEs → 3 batched requests (100 + 100 + 50)', async () => {
  fetchCalls = [];
  const findings = Array.from({ length: 250 }, (_, i) =>
    makeFinding(cveId(300000 + i + 1), `pkg${i}`));
  await _enrichWithEPSS(findings);
  assert.equal(fetchCalls.length, 3, 'three batched requests at batch=100');
  const counts = fetchCalls.map(u => (u.match(/CVE-/g) || []).length);
  assert.deepEqual(counts.sort((a, b) => a - b), [50, 100, 100]);
});

test('EPSS: cached CVEs skip the network entirely on rerun', async () => {
  const cve = cveId(400000);
  // Warm the cache.
  fetchCalls = [];
  await _enrichWithEPSS([makeFinding(cve, 'pkg')]);
  assert.equal(fetchCalls.length, 1, 'warmup fetched');
  // Second call against the same CVE must use the cache and skip fetch.
  fetchCalls = [];
  await _enrichWithEPSS([makeFinding(cve, 'pkg')]);
  assert.equal(fetchCalls.length, 0, 'cached CVE issues no further requests');
});

test('EPSS: malformed CVE ids are filtered out before fetching', async () => {
  fetchCalls = [];
  const goodCve = cveId(500001);
  const findings = [
    makeFinding(goodCve, 'good'),
    { type: 'vulnerable_dep', name: 'noaliases', cveAliases: [] },
    { type: 'vulnerable_dep', name: 'malformed', cveAliases: ['NOT-A-CVE'] },
  ];
  await _enrichWithEPSS(findings);
  assert.equal(fetchCalls.length, 1, 'one fetch for the only valid CVE');
  assert.match(fetchCalls[0], new RegExp(goodCve));
});

test('EPSS: offline mode skips all fetching', async () => {
  process.env.AGENTIC_SECURITY_OFFLINE = '1';
  fetchCalls = [];
  const findings = Array.from({ length: 10 }, (_, i) =>
    makeFinding(cveId(600000 + i + 1), `pkg${i}`));
  await _enrichWithEPSS(findings);
  assert.equal(fetchCalls.length, 0, 'no fetches in offline mode');
  delete process.env.AGENTIC_SECURITY_OFFLINE;
});

test('_fetchEPSSBatch: empty input is a no-op', async () => {
  fetchCalls = [];
  const out = await _fetchEPSSBatch([]);
  assert.equal(fetchCalls.length, 0);
  assert.equal(out.size, 0);
});
