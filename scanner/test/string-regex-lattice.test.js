// v0.69 #4a — string-domain regex lattice tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  TOP, BOTTOM,
  makeConst, makeConcat, makeRegex,
  abstract, join, render, provablyMatches,
} from '../src/dataflow/string-domain.js';

test('makeRegex rejects unanchored patterns', () => {
  // Unanchored regex would be unsound — could match a substring.
  assert.equal(makeRegex(/[A-Z]+/), TOP);
  assert.equal(makeRegex(/^[A-Z]+/), TOP);
  assert.equal(makeRegex(/[A-Z]+$/), TOP);
  // Anchored both sides → real Regex value.
  const r = makeRegex(/^[A-Z]+$/);
  assert.equal(r.kind, 'Regex');
});

test('abstract recognizes encodeURIComponent as regex-constrained output', () => {
  const expr = { kind: 'call', callee: 'encodeURIComponent', args: [{ kind: 'ident', name: 'x' }] };
  const a = abstract(expr);
  assert.equal(a.kind, 'Regex');
  assert.match(a.pattern.source, /^\^/);
  assert.match(a.pattern.source, /\$$/);
});

test('abstract returns TOP for unknown calls', () => {
  const expr = { kind: 'call', callee: 'mysteryFn', args: [] };
  const a = abstract(expr);
  assert.equal(a.kind, 'Unknown');
});

test('provablyMatches: constant fits within a safe charset', () => {
  const v = makeConst('hello123');
  assert.equal(provablyMatches(v, /^[A-Za-z0-9]*$/), true);
  assert.equal(provablyMatches(v, /^\d+$/), false);
});

test('provablyMatches: regex value matches identical safe-charset regex', () => {
  const r = makeRegex(/^[A-Za-z0-9\-_.!~*'()%]*$/);
  // Same source → provable.
  assert.equal(provablyMatches(r, /^[A-Za-z0-9\-_.!~*'()%]*$/), true);
  // Different (looser) → not provable in v1 (we don't do regex subset).
  assert.equal(provablyMatches(r, /^.*$/), false);
});

test('provablyMatches: Concat of provably-safe parts matches a starred-charset safe regex', () => {
  const a = makeConst('abc');
  const b = makeConst('123');
  const c = makeConcat([a, b]);
  // Safe regex permits arbitrary repetition.
  assert.equal(provablyMatches(c, /^[A-Za-z0-9]*$/), true);
  // Safe regex requires exact ^digits$ — concat of "abc"+"123" doesn't fit.
  assert.equal(provablyMatches(c, /^\d+$/), false);
});

test('join: Regex ⊔ matching Const = Regex', () => {
  const r = makeRegex(/^[A-Z]+$/);
  const c = makeConst('HELLO');
  const j = join(r, c);
  assert.equal(j.kind, 'Regex');
  assert.equal(j.pattern.source, '^[A-Z]+$');
});

test('join: Regex ⊔ non-matching Const = Unknown', () => {
  const r = makeRegex(/^[A-Z]+$/);
  const c = makeConst('hello');
  const j = join(r, c);
  assert.equal(j.kind, 'Unknown');
});

test('join: same-pattern Regexes meet to themselves', () => {
  const r1 = makeRegex(/^\d+$/);
  const r2 = makeRegex(/^\d+$/);
  const j = join(r1, r2);
  assert.equal(j.kind, 'Regex');
});

test('join: different Regex patterns become Unknown (no regex-subset in v1)', () => {
  const r1 = makeRegex(/^\d+$/);
  const r2 = makeRegex(/^\d{1,3}$/);
  const j = join(r1, r2);
  assert.equal(j.kind, 'Unknown');
});

test('render: regex value renders its pattern source', () => {
  const r = makeRegex(/^[A-Z]+$/);
  assert.equal(render(r), '^[A-Z]+$');
});

test('parseInt is recognized as integer-output', () => {
  const expr = { kind: 'call', callee: 'parseInt', args: [{ kind: 'ident', name: 'x' }] };
  const a = abstract(expr);
  assert.equal(a.kind, 'Regex');
  assert.ok(a.pattern.test('42'));
  assert.ok(a.pattern.test('-7'));
  assert.equal(a.pattern.test('1e5'), false);
});
