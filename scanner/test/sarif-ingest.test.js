// 0.7.0 Feat-7: SARIF ingest tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ingestSARIFFile, mergeSARIFFindings, ingestAndMerge } from '../src/sca/sarif-ingest.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (n) => path.join(__dirname, 'fixtures', 'sarif-ingest', n);

test('SARIF ingest — Semgrep file parses to normalized findings', () => {
  const findings = ingestSARIFFile(FIX('semgrep.sarif'));
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.kind, 'sast');
  assert.equal(f.file, 'src/auth.js');
  assert.equal(f.line, 42);
  assert.equal(f.cwe, 'CWE-1004');
  assert.equal(f.severity, 'high'); // warning -> high
  assert.deepEqual(f.sources, ['semgrep']);
});

test('SARIF ingest — gitleaks file becomes a secret-kind finding with critical severity', () => {
  const findings = ingestSARIFFile(FIX('gitleaks.sarif'));
  assert.equal(findings.length, 1);
  const f = findings[0];
  assert.equal(f.kind, 'secret');
  assert.equal(f.severity, 'critical'); // error -> critical
  assert.equal(f.cwe, 'CWE-798');
  assert.deepEqual(f.sources, ['gitleaks']);
});

test('SARIF ingest — mergeSARIFFindings adds new findings into the right buckets', () => {
  const scan = { findings: [], secrets: [], supplyChain: [] };
  const externals = [
    ...ingestSARIFFile(FIX('semgrep.sarif')),
    ...ingestSARIFFile(FIX('gitleaks.sarif')),
  ];
  const r = mergeSARIFFindings(scan, externals);
  assert.equal(r.added, 2, 'expected both findings appended (no fingerprint collision)');
  assert.equal(r.merged, 0);
  assert.equal(scan.findings.length, 1, 'sast finding lands in scan.findings');
  assert.equal(scan.secrets.length, 1, 'secret finding lands in scan.secrets');
});

test('SARIF ingest — fingerprint dedupe merges a SARIF finding into an existing one and adds source[]', () => {
  // Pre-existing scan finding at the SAME file/line as the Semgrep result above.
  const scan = {
    findings: [{
      id: 'pre:existing', kind: 'sast', severity: 'medium',
      vuln: 'Cookie missing HttpOnly flag at /admin endpoint',
      cwe: 'CWE-1004', file: 'src/auth.js', line: 42, snippet: '',
    }],
    secrets: [], supplyChain: [],
  };
  const externals = ingestSARIFFile(FIX('semgrep.sarif'));
  const r = mergeSARIFFindings(scan, externals);
  assert.equal(r.merged, 1, 'expected fingerprint match on file/line/cwe');
  assert.equal(r.added, 0);
  // sources[] must include both
  assert.ok(scan.findings[0].sources.includes('semgrep'),
    `expected semgrep in sources; got: ${JSON.stringify(scan.findings[0].sources)}`);
  // Severity bumped from medium → high (semgrep level was warning)
  assert.equal(scan.findings[0].severity, 'high');
});

test('SARIF ingest — ingestAndMerge handles glob-style multi-file ingest', () => {
  const scan = { findings: [], secrets: [], supplyChain: [] };
  const r = ingestAndMerge(scan, [FIX('semgrep.sarif'), FIX('gitleaks.sarif')]);
  assert.equal(r.added + r.merged, 2);
});
