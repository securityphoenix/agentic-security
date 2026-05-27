import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isUnsafeRegex, extractPyRegexBodies, extractJavaRegexBodies, scanRegexReDoS } from '../src/sast/redos-nfa.js';

// ── isUnsafeRegex: known-dangerous patterns ─────────────────────────────────

test('detects (a+)+ nested quantifier', () => {
  const r = isUnsafeRegex('(a+)+');
  assert.ok(r.unsafe, 'expected unsafe');
});

test('detects (a|aa)* alternation ambiguity', () => {
  const r = isUnsafeRegex('(a|aa)*');
  assert.ok(r.unsafe, 'expected unsafe');
});

test('detects ([a-z]+)+$ nested quantifier', () => {
  const r = isUnsafeRegex('([a-z]+)+$');
  assert.ok(r.unsafe, 'expected unsafe');
});

test('detects (\\d+\\.?\\d+)+ overlapping nullable under quantifier', () => {
  const r = isUnsafeRegex('(\\d+\\.?\\d+)+');
  assert.ok(r.unsafe, 'expected unsafe');
});

test('detects (.*a){10} nested quantifier', () => {
  const r = isUnsafeRegex('(.*a){10}');
  assert.ok(r.unsafe, 'expected unsafe');
});

test('detects (\\w+\\s+)+ nested quantifier via {n,}', () => {
  const r = isUnsafeRegex('(\\w+\\s+)+');
  assert.ok(r.unsafe, 'expected unsafe');
});

// ── isUnsafeRegex: known-safe patterns ──────────────────────────────────────

test('safe: [a-z]+', () => {
  assert.ok(!isUnsafeRegex('[a-z]+').unsafe);
});

test('safe: \\d{1,3}\\.\\d{1,3}', () => {
  assert.ok(!isUnsafeRegex('\\d{1,3}\\.\\d{1,3}').unsafe);
});

test('safe: [^/]+', () => {
  assert.ok(!isUnsafeRegex('[^/]+').unsafe);
});

test('safe: \\w+@\\w+\\.com', () => {
  assert.ok(!isUnsafeRegex('\\w+@\\w+\\.com').unsafe);
});

test('safe: ^\\d+$', () => {
  assert.ok(!isUnsafeRegex('^\\d+$').unsafe);
});

test('safe: empty or null', () => {
  assert.ok(!isUnsafeRegex('').unsafe);
  assert.ok(!isUnsafeRegex(null).unsafe);
});

// ── Python/Java extraction ──────────────────────────────────────────────────

test('extractPyRegexBodies: captures re.compile patterns', () => {
  const code = `
import re
pat = re.compile(r'(a+)+')
m = re.match(r'\\d+', text)
`;
  const bodies = extractPyRegexBodies(code);
  assert.ok(bodies.length >= 2);
  assert.ok(bodies.some(b => b.body === '(a+)+'));
});

test('extractJavaRegexBodies: captures Pattern.compile and .matches', () => {
  const code = `
Pattern p = Pattern.compile("(a+)+");
boolean ok = input.matches("\\\\d+");
`;
  const bodies = extractJavaRegexBodies(code);
  assert.ok(bodies.length >= 1);
  assert.ok(bodies.some(b => b.body === '(a+)+'));
});

// ── scanRegexReDoS: end-to-end ──────────────────────────────────────────────

test('scanRegexReDoS: flags JS file with dangerous regex', () => {
  const code = `const re = /(a+)+/;`;
  const findings = scanRegexReDoS('app.js', code);
  assert.ok(findings.length >= 1);
  assert.ok(findings[0].vuln.includes('ReDoS'));
});

test('scanRegexReDoS: flags Python file with dangerous regex', () => {
  const code = `import re\npat = re.compile(r'(a+)+')`;
  const findings = scanRegexReDoS('app.py', code);
  assert.ok(findings.length >= 1);
});

test('scanRegexReDoS: no findings for safe JS regex', () => {
  const code = `const re = /[a-z]+/;`;
  const findings = scanRegexReDoS('app.js', code);
  assert.equal(findings.length, 0);
});
