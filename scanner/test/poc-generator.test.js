// PoC generator tests (P1.1 / FR-VER-2).
//
// Asserts every top-10 CWE in the parent PRD gets a runnable template, that
// templates do not contain destructive shell commands, and that the engine
// pipeline annotates findings with f.poc when the CWE matches.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  generatePoc,
  annotatePocs,
  pocCoverageSummary,
  _templateCount,
  _knownCwes,
} from '../src/posture/poc-generator.js';
import { isPocSupported, isExplicitlyNoPoc } from '../src/posture/poc-cwe-map.js';

// ─── coverage ────────────────────────────────────────────────────────────────

test('all 10 PRD-listed CWE families have a PoC template', () => {
  const expected = ['CWE-89','CWE-78','CWE-79','CWE-22','CWE-918',
                    'CWE-94','CWE-352','CWE-601','CWE-611','CWE-502'];
  for (const cwe of expected) {
    assert.ok(_knownCwes.includes(cwe),
      `CWE ${cwe} missing from PoC template registry — required by P1.1 acceptance criteria.`);
  }
});

test('_templateCount reflects exactly the registered templates', () => {
  assert.equal(_templateCount(), _knownCwes.length);
});

// ─── generation ──────────────────────────────────────────────────────────────

test('generatePoc returns code for a SQL injection finding', () => {
  const poc = generatePoc({ vuln: 'SQL Injection', cwe: 'CWE-89' }, { routes: [] });
  assert.ok(poc, 'expected a PoC for SQL injection');
  assert.equal(poc.lang, 'node');
  assert.equal(poc.cwe, 'CWE-89');
  assert.ok(poc.code.includes('UNION SELECT'), 'PoC must include a UNION-style payload');
  assert.ok(poc.code.includes('process.exit(0)'), 'PoC must exit 0 on demonstrated exploit');
  assert.ok(poc.code.includes('process.exit(1)'), 'PoC must exit non-0 on negative case');
});

test('generatePoc renders endpoint context from routes when available', () => {
  const finding = {
    vuln: 'Command Injection',
    cwe: 'CWE-78',
    file: 'app.js',
    line: 12,
    source: { variable: 'host' },
  };
  const routes = [{ method: 'POST', path: '/api/ping', file: 'app.js', line: 11 }];
  const poc = generatePoc(finding, { routes });
  assert.ok(poc.code.includes('http://localhost:3000/api/ping'), 'PoC URL should reflect the discovered route path');
  assert.ok(poc.code.includes('"host"') || poc.code.includes("'host'"), 'PoC body should reference the tainted source variable name');
});

test('generatePoc returns null for an unsupported CWE family', () => {
  const poc = generatePoc({ vuln: 'Hardcoded Secret', cwe: 'CWE-798' }, {});
  assert.equal(poc, null);
});

test('isExplicitlyNoPoc tags known no-poc families', () => {
  assert.equal(isExplicitlyNoPoc('hardcoded-secret'), true);
  assert.equal(isExplicitlyNoPoc('timing-oracle'), true);
  assert.equal(isExplicitlyNoPoc('sql-injection'), false);
});

// ─── safety ──────────────────────────────────────────────────────────────────

test('no PoC template contains destructive shell commands', () => {
  // Generate a PoC for every supported CWE and grep for known-bad patterns.
  const BAD = [/rm\s+-rf/, /mkfs/, /dd\s+if=/, /:>:\(\)/, /shutdown/, /reboot/, /chmod\s+777\s+\//];
  for (const cwe of _knownCwes) {
    const poc = generatePoc({ cwe, vuln: 'placeholder' }, {});
    if (!poc) continue;
    for (const re of BAD) {
      assert.ok(!re.test(poc.code), `PoC for ${cwe} contains destructive pattern ${re}`);
    }
  }
});

test('PoCs target localhost only, never real cloud metadata IPs', () => {
  for (const cwe of _knownCwes) {
    const poc = generatePoc({ cwe, vuln: 'placeholder' }, {});
    if (!poc) continue;
    // 169.254.169.254 is the AWS IMDS — never appears in shipped templates.
    assert.ok(!poc.code.includes('169.254.169.254'),
      `PoC for ${cwe} hardcodes AWS metadata IP — refused by safety rule`);
    assert.ok(!poc.code.includes('metadata.google.internal'),
      `PoC for ${cwe} hardcodes GCP metadata host — refused by safety rule`);
  }
});

// ─── batch annotation ───────────────────────────────────────────────────────

test('annotatePocs sets f.poc on supported findings and null on others', () => {
  const findings = [
    { vuln: 'SQL Injection', cwe: 'CWE-89', id: 'f1' },
    { vuln: 'Hardcoded Secret', cwe: 'CWE-798', id: 'f2' },
    { vuln: 'Open Redirect', cwe: 'CWE-601', id: 'f3' },
  ];
  annotatePocs(findings, { routes: [] });
  assert.ok(findings[0].poc && findings[0].poc.cwe === 'CWE-89');
  assert.equal(findings[1].poc, null);
  assert.ok(findings[2].poc && findings[2].poc.cwe === 'CWE-601');
});

test('annotatePocs never throws on garbage input', () => {
  assert.doesNotThrow(() => annotatePocs(null));
  assert.doesNotThrow(() => annotatePocs([null, undefined, 0, '', { vuln: '' }]));
});

test('pocCoverageSummary aggregates correctly', () => {
  const findings = [
    { vuln: 'SQL Injection', cwe: 'CWE-89', family: 'sql-injection' },
    { vuln: 'XSS', cwe: 'CWE-79', family: 'xss' },
    { vuln: 'Hardcoded Secret', cwe: 'CWE-798', family: 'hardcoded-secret' },
  ];
  annotatePocs(findings);
  const s = pocCoverageSummary(findings);
  assert.equal(s.withPoc, 2);
  assert.equal(s.withoutPoc, 1);
  assert.deepEqual(s.byFamily['sql-injection'], { withPoc: 1, withoutPoc: 0 });
});
