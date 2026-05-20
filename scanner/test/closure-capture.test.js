// v0.69 #8a — closure capture-set extraction tests.
//
// Verifies the `capturedFreeVars` + `callbackCaptureSet` helpers. Engine
// wiring is deferred to v0.70 when alias analysis lands; this release ships
// the extractor + tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { capturedFreeVars, callbackCaptureSet } from '../src/dataflow/higher-order.js';

// Helpers to build IR-shaped expressions.
const ident = (name) => ({ kind: 'ident', name });
const lit   = (value) => ({ kind: 'literal', value });
const call  = (callee, ...args) => ({ kind: 'call', callee, args });
const member = (obj, prop) => ({ kind: 'member', object: obj, prop });
const fnVal = (params, body) => ({ kind: 'function-value', params, body });

test('plain identifier is captured when not bound', () => {
  const out = capturedFreeVars(ident('t'), new Set());
  assert.ok(out.has('t'));
});

test('plain identifier is NOT captured when bound', () => {
  const out = capturedFreeVars(ident('t'), new Set(['t']));
  assert.equal(out.size, 0);
});

test('member access roots: only base identifier counts as free', () => {
  // obj.foo.bar — only `obj` is the free var
  const expr = member(member(ident('obj'), 'foo'), 'bar');
  const out = capturedFreeVars(expr, new Set());
  assert.deepEqual([...out], ['obj']);
});

test('binary op walks both sides', () => {
  const expr = { kind: 'binary', op: '+', left: ident('a'), right: ident('b') };
  const out = capturedFreeVars(expr, new Set(['b']));
  assert.ok(out.has('a'));
  assert.ok(!out.has('b'));
});

test('call captures both string-callee root and arg identifiers', () => {
  // `exec(t, x)`
  const expr = call('exec', ident('t'), ident('x'));
  const out = capturedFreeVars(expr, new Set());
  assert.ok(out.has('exec'));
  assert.ok(out.has('t'));
  assert.ok(out.has('x'));
});

test('call with dotted-string callee captures only receiver root', () => {
  // `db.query(t)` — `db` is free, `query` is a method name
  const expr = call('db.query', ident('t'));
  const out = capturedFreeVars(expr, new Set());
  assert.ok(out.has('db'));
  assert.ok(!out.has('query'));
  assert.ok(out.has('t'));
});

test('inline arrow body: callback args do NOT leak as captures', () => {
  // i => exec(t, i)  ;  `t` is captured from outside, `i` is the callback param
  const callback = fnVal(['i'], call('exec', ident('t'), ident('i')));
  const captures = callbackCaptureSet(callback);
  assert.ok(captures.has('t'),  'expected t to be captured');
  assert.ok(!captures.has('i'), 'i is a param, must not leak');
});

test('nested function-value: inner params shadow outer captures', () => {
  // outerArg => arr.map(inner => exec(outerArg, inner))
  // The inner callback has its own params (inner); outerArg is NOT in inner.params
  // but IS in outer.params, so the OVERALL free var set is empty.
  const inner  = fnVal(['inner'], call('exec', ident('outerArg'), ident('inner')));
  const outer  = fnVal(['outerArg'], call('arr.map', inner));
  const captures = callbackCaptureSet(outer);
  // `arr` is a free var from the outer scope; `outerArg` and `inner` are
  // both bound somewhere in the chain.
  assert.ok(captures.has('arr'), 'arr is free');
  assert.ok(!captures.has('outerArg'), 'outerArg is bound by outer function');
  assert.ok(!captures.has('inner'), 'inner is bound by inner function');
});

test('callbackCaptureSet returns empty for non-arrow callable arg', () => {
  // arr.map(savedHandler) — saved fn reference, no inline body to inspect.
  const captures = callbackCaptureSet(ident('savedHandler'));
  assert.equal(captures.size, 0);
});

test('template literal walks every part', () => {
  // `${a}-${b.c}` with `b` bound
  const expr = { kind: 'tpl', parts: [ident('a'), lit('-'), member(ident('b'), 'c')] };
  const out = capturedFreeVars(expr, new Set(['b']));
  assert.ok(out.has('a'));
  assert.ok(!out.has('b'));
});

test('array literal walks elements', () => {
  const expr = { kind: 'array', elements: [ident('x'), ident('y')] };
  const out = capturedFreeVars(expr, new Set(['y']));
  assert.ok(out.has('x'));
  assert.ok(!out.has('y'));
});

test('classic captured-tainted-var shape: i => exec(t)', () => {
  // The motivating example from the plan: `let t = req.query.x; arr.map(i => exec(t))`.
  // We assert that the capture set of the arrow ⟨i ↦ exec(t)⟩ contains `t`.
  const callback = fnVal(['i'], call('exec', ident('t')));
  const captures = callbackCaptureSet(callback);
  assert.ok(captures.has('t'));
});
