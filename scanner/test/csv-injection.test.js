import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanCsvInjection } from '../src/sast/csv-injection.js';
import { CATALOG } from '../src/dataflow/catalog.js';

test('flags user data written to a CSV writer with no neutralization', () => {
  const src = "const csv = require('csv-stringify');\ncsvStringify([{ name: req.body.name, columns: true }]);\n";
  const f = scanCsvInjection('export.js', src);
  assert.ok(f.length >= 1);
  assert.equal(f[0].cwe, 'CWE-1236');
});

test('flags python csv.writer().writerow with request data', () => {
  const src = "w = csv.writer(out)\nw.writerow([request.GET['title'], 1])\n";
  assert.ok(scanCsvInjection('v.py', src).length >= 1);
});

test('does NOT flag when a formula-escape helper is present', () => {
  const src = "const safe = escapeFormula(req.body.name);\nwriteRecords([{ name: safe }]);\n";
  assert.equal(scanCsvInjection('e.js', src).length, 0);
});

test('does NOT flag CSV writes of non-user (constant) data', () => {
  const src = "writeRecords([{ name: 'static', total: 42 }]);\n";
  assert.equal(scanCsvInjection('s.js', src).length, 0);
});

test('ignores unrelated files', () => {
  assert.equal(scanCsvInjection('a.go', "w.writerow([req.x])").length, 0);
});

// #7 — validation-library sanitizers are scoped to mongo-operator ONLY.
test('validation-library sanitizers exist and are NOT tagged for xss/sql/cmd', () => {
  const ids = ['js-zod-safeParse', 'js-zod-parseAsync', 'js-class-validator'];
  for (const id of ids) {
    const e = CATALOG.find(x => x.id === id);
    assert.ok(e, `missing catalog entry ${id}`);
    assert.equal(e.kind, 'sanitizer');
    assert.deepEqual(e.appliesTo, ['mongo-operator'], `${id} must only sanitize mongo-operator`);
    assert.ok(!e.appliesTo.includes('xss') && !e.appliesTo.includes('sql') && !e.appliesTo.includes('cmd'));
  }
});
