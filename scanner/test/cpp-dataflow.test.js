// cpp-dataflow.test.js — unit tests for the intra-procedural C/C++ dataflow detectors.
// Run: AGENTIC_SECURITY_CPP_DATAFLOW=1 node --test scanner/test/cpp-dataflow.test.js
// (The CPP_DATAFLOW env var must be set; see scanner/src/sast/cpp-dataflow.js.)

import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import * as fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (sub) => path.join(__dirname, 'fixtures', 'cpp-dataflow', sub);

// Enable the feature flag for tests.
process.env.AGENTIC_SECURITY_CPP_DATAFLOW = '1';

// Import after setting env var.
const { scanCppDataflow, _internals, _parseErrorCount } = await import(
  '../src/sast/cpp-dataflow.js'
);
const { _esc, _findFunctions, _detectUseAfterFree, _detectDoubleFree,
        _detectMissingNullCheck, _detectAllocSizeOverflow, _detectOffByOne } = _internals;

// ── _esc() ────────────────────────────────────────────────────────────────────
describe('_esc()', () => {
  test('leaves simple identifiers unchanged', () => {
    assert.equal(_esc('ptr'), 'ptr');
    assert.equal(_esc('node123'), 'node123');
  });

  test('escapes dot (struct member)', () => {
    const escaped = _esc('obj.field');
    assert.ok(/\\\./.test(escaped), `expected escaped dot in: ${escaped}`);
    const re = new RegExp(`\\b${escaped}\\b`);
    assert.ok(re.test('obj.field'));
    assert.ok(!re.test('objXfield'));
  });

  test('escapes -> (arrow member)', () => {
    const escaped = _esc('p->x');
    // -> contains > which is not a special regex char but - is in char class context
    // Mostly we check it doesn't throw when compiled into a RegExp.
    assert.doesNotThrow(() => new RegExp(escaped));
  });

  test('escapes [ and ] (array subscript)', () => {
    const escaped = _esc('arr[0]');
    assert.doesNotThrow(() => new RegExp(escaped));
    const re = new RegExp(escaped);
    assert.ok(re.test('arr[0]'));
  });

  test('escapes regex metacharacters that would break dynamic patterns', () => {
    const dangerous = ['(x)', 'a+b', 'a*b', 'a.b', 'a[0]', 'a{1}', 'a^b', 'a$b'];
    for (const d of dangerous) {
      assert.doesNotThrow(() => new RegExp(_esc(d)), `_esc should make "${d}" safe`);
    }
  });
});

// ── _findFunctions() ──────────────────────────────────────────────────────────
describe('_findFunctions()', () => {
  test('finds a simple function body', () => {
    const src = `int foo(int x) { return x + 1; }`;
    const fns = _findFunctions(src);
    assert.equal(fns.length, 1);
    assert.equal(fns[0].name, 'foo');
  });

  test('finds multiple functions', () => {
    const src = `void a(void) { } int b(int x) { return x; }`;
    const fns = _findFunctions(src);
    assert.equal(fns.length, 2);
    assert.deepEqual(fns.map(f => f.name), ['a', 'b']);
  });

  test('ignores keyword control flow (if, while, for)', () => {
    const src = `void f(void) { if (1) { } while (0) { } for (;;) { } }`;
    const fns = _findFunctions(src);
    assert.equal(fns.length, 1);
    assert.equal(fns[0].name, 'f');
  });

  test('handles empty source', () => {
    assert.deepEqual(_findFunctions(''), []);
  });
});

// ── _detectUseAfterFree() ────────────────────────────────────────────────────
describe('_detectUseAfterFree()', () => {
  test('detects UAF: deref after free()', () => {
    const body = `char *p = malloc(10); free(p); p[0] = 'x';`;
    const findings = _detectUseAfterFree(body, 1);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].cwe, 'CWE-416');
  });

  test('no finding when pointer reassigned before use', () => {
    const body = `char *p = malloc(10); free(p); p = malloc(10); p[0] = 'x'; free(p);`;
    const findings = _detectUseAfterFree(body, 1);
    assert.equal(findings.length, 0);
  });

  test('no finding with no deref after free', () => {
    const body = `char *p = malloc(10); free(p); p = NULL;`;
    const findings = _detectUseAfterFree(body, 1);
    assert.equal(findings.length, 0);
  });

  test('fixture file: uaf.c produces a UAF finding', () => {
    const src = fs.readFileSync(FIX('vulnerable/uaf.c'), 'utf8');
    const findings = scanCppDataflow('uaf.c', src);
    const uaf = findings.filter(f => f.cwe === 'CWE-416');
    assert.ok(uaf.length >= 1, `expected ≥1 CWE-416 finding; got ${JSON.stringify(findings)}`);
  });
});

// ── _detectDoubleFree() ──────────────────────────────────────────────────────
describe('_detectDoubleFree()', () => {
  test('detects double-free in same function', () => {
    const body = `char *buf = malloc(16); free(buf); free(buf);`;
    const findings = _detectDoubleFree(body, 1);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].cwe, 'CWE-415');
  });

  test('no finding when pointer reassigned between frees', () => {
    const body = `char *buf = malloc(16); free(buf); buf = malloc(16); free(buf);`;
    const findings = _detectDoubleFree(body, 1);
    assert.equal(findings.length, 0);
  });

  test('fixture file: double_free.c produces a double-free finding', () => {
    const src = fs.readFileSync(FIX('vulnerable/double_free.c'), 'utf8');
    const findings = scanCppDataflow('double_free.c', src);
    const df = findings.filter(f => f.cwe === 'CWE-415');
    assert.ok(df.length >= 1, `expected ≥1 CWE-415 finding; got ${JSON.stringify(findings)}`);
  });
});

// ── _detectMissingNullCheck() ────────────────────────────────────────────────
describe('_detectMissingNullCheck()', () => {
  test('detects missing null check before deref', () => {
    const body = `int *p = malloc(sizeof(int)); *p = 42;`;
    const findings = _detectMissingNullCheck(body, 1);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].cwe, 'CWE-476');
  });

  test('no finding when null check precedes deref', () => {
    const body = `int *p = malloc(sizeof(int)); if (!p) return; *p = 42;`;
    const findings = _detectMissingNullCheck(body, 1);
    assert.equal(findings.length, 0);
  });

  test('fixture file: null_deref.c produces a null-check finding', () => {
    const src = fs.readFileSync(FIX('vulnerable/null_deref.c'), 'utf8');
    const findings = scanCppDataflow('null_deref.c', src);
    const nc = findings.filter(f => f.cwe === 'CWE-476');
    assert.ok(nc.length >= 1, `expected ≥1 CWE-476 finding; got ${JSON.stringify(findings)}`);
  });
});

// ── _detectOffByOne() ────────────────────────────────────────────────────────
describe('_detectOffByOne()', () => {
  test('detects <= len bound with array access', () => {
    const body = `for (int i = 0; i <= len; i++) { arr[i] = 0; }`;
    const findings = _detectOffByOne(body, 1);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].cwe, 'CWE-193');
  });

  test('no finding for < bound (correct)', () => {
    const body = `for (int i = 0; i < len; i++) { arr[i] = 0; }`;
    const findings = _detectOffByOne(body, 1);
    assert.equal(findings.length, 0);
  });

  test('fixture file: off_by_one.c produces an off-by-one finding', () => {
    const src = fs.readFileSync(FIX('vulnerable/off_by_one.c'), 'utf8');
    const findings = scanCppDataflow('off_by_one.c', src);
    const obo = findings.filter(f => f.cwe === 'CWE-193');
    assert.ok(obo.length >= 1, `expected ≥1 CWE-193 finding; got ${JSON.stringify(findings)}`);
  });
});

// ── Clean fixture ─────────────────────────────────────────────────────────────
describe('clean fixture', () => {
  test('safe_patterns.c produces zero findings', () => {
    const src = fs.readFileSync(FIX('clean/safe_patterns.c'), 'utf8');
    const findings = scanCppDataflow('safe_patterns.c', src);
    assert.equal(findings.length, 0,
      `clean fixture must produce 0 findings; got: ${findings.map(f => f.vuln).join(', ')}`);
  });
});

// ── Error counter ─────────────────────────────────────────────────────────────
describe('parse-error counter', () => {
  test('_parseErrorCount is exported and starts at a known value', () => {
    assert.ok(typeof _parseErrorCount.value === 'number');
    assert.ok(_parseErrorCount.value >= 0);
  });

  test('scanCppDataflow does not throw on malformed input', () => {
    // Degenerate inputs that previously caused dynamic-regex failures.
    const inputs = [
      'void f(void) { char *p(a+b) = malloc(4); free(p(a+b)); p(a+b)[0]=0; }',
      'void g(void) { int *arr[0] = malloc(4); free(arr[0]); arr[0][0]=1; }',
      '{ {{ } }',   // unbalanced braces — should not throw
    ];
    for (const src of inputs) {
      assert.doesNotThrow(() => scanCppDataflow('test.c', src), `should not throw on: ${src.slice(0,40)}`);
    }
  });

  test('feature flag: scanCppDataflow returns [] when env var is unset', async () => {
    const saved = process.env.AGENTIC_SECURITY_CPP_DATAFLOW;
    delete process.env.AGENTIC_SECURITY_CPP_DATAFLOW;
    // Re-import with fresh module — Node test runner caches modules, so use
    // the already-imported one and unset the flag directly.
    // We can't re-import but we can test the gate indirectly:
    // set to empty string, which is falsy.
    process.env.AGENTIC_SECURITY_CPP_DATAFLOW = '';
    const src = fs.readFileSync(FIX('vulnerable/uaf.c'), 'utf8');
    // The guard is `if (!process.env.AGENTIC_SECURITY_CPP_DATAFLOW)` —
    // empty string is falsy.
    const findings = scanCppDataflow('uaf.c', src);
    assert.equal(findings.length, 0, 'feature flag unset must return empty array');
    process.env.AGENTIC_SECURITY_CPP_DATAFLOW = saved;
  });
});
