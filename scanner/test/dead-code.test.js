// Tests for the dead-code scanner (posture/dead-code.js).

import { test } from 'node:test';
import * as assert from 'node:assert/strict';

import {
  detectDeadJsTs, detectWrapperFns, filterDynamicReferences,
  classifyTier, scanDeadCode, groupByTier,
} from '../src/posture/dead-code.js';

// ── helpers ────────────────────────────────────────────────────────────────

function makeFn(file, name, { exported = false, line = 10, body = '', params = [] } = {}) {
  return {
    qid: `${file}::${name}@${line}`,
    file, name, line, exported, body, params,
    calls: [],
  };
}

function makeCallgraph(fns, edges = []) {
  const functions = new Map();
  for (const fn of fns) functions.set(fn.qid, fn);
  const callersOf = new Map();
  for (const e of edges) {
    if (!e.callee) continue;
    if (!callersOf.has(e.callee)) callersOf.set(e.callee, []);
    callersOf.get(e.callee).push(e);
  }
  return { functions, edges, callersOf };
}

// ── detectDeadJsTs ─────────────────────────────────────────────────────────

test('detectDeadJsTs: flags exported function with zero callers', () => {
  const exported = makeFn('src/util.js', 'unused', { exported: true });
  const used = makeFn('src/util.js', 'used', { exported: true });
  const caller = makeFn('src/main.js', 'main');
  const cg = makeCallgraph([exported, used, caller], [
    { caller: caller.qid, callee: used.qid },
  ]);
  const fc = new Map([['src/util.js', ''], ['src/main.js', '']]);
  const out = detectDeadJsTs('.', fc, cg);
  const unusedFinding = out.find(f => f.name === 'unused' && f.kind === 'unused-export');
  assert.ok(unusedFinding, 'should flag unused export');
  const usedFinding = out.find(f => f.name === 'used');
  assert.equal(usedFinding, undefined, 'should not flag used export');
});

test('detectDeadJsTs: does not flag entry-point exports', () => {
  const entry = makeFn('bin/cli.js', 'main', { exported: true });
  const cg = makeCallgraph([entry], []);
  const fc = new Map([['bin/cli.js', '']]);
  const out = detectDeadJsTs('.', fc, cg);
  assert.equal(out.find(f => f.name === 'main'), undefined);
});

test('detectDeadJsTs: flags unused file with declared but uncalled fns', () => {
  const orphan = makeFn('src/orphan.js', 'helper', { exported: true });
  const main   = makeFn('src/main.js',   'main',   { exported: true });
  const cg = makeCallgraph([orphan, main], []);
  const fc = new Map([['src/orphan.js', ''], ['src/main.js', '']]);
  const out = detectDeadJsTs('.', fc, cg);
  const fileFinding = out.find(f => f.kind === 'unused-file' && f.file === 'src/orphan.js');
  assert.ok(fileFinding, 'should flag orphan.js as unused-file');
});

// ── detectWrapperFns ───────────────────────────────────────────────────────

test('detectWrapperFns: catches `return other(a, b)` passthrough', () => {
  const wrapper = makeFn('src/util.js', 'doStuff', {
    body: 'return other(a, b)',
    params: [{ name: 'a' }, { name: 'b' }],
  });
  const cg = makeCallgraph([wrapper], []);
  const out = detectWrapperFns(cg);
  assert.equal(out.length, 1);
  assert.equal(out[0].name, 'doStuff');
  assert.equal(out[0].kind, 'wrapper-fn');
});

test('detectWrapperFns: ignores fns whose body modifies args', () => {
  const real = makeFn('src/util.js', 'compute', {
    body: 'return other(a + 1, b)',
    params: [{ name: 'a' }, { name: 'b' }],
  });
  const cg = makeCallgraph([real], []);
  assert.equal(detectWrapperFns(cg).length, 0);
});

test('detectWrapperFns: ignores fns with mismatched arity', () => {
  const fn = makeFn('src/util.js', 'shim', {
    body: 'return other(a)',
    params: [{ name: 'a' }, { name: 'b' }],
  });
  const cg = makeCallgraph([fn], []);
  assert.equal(detectWrapperFns(cg).length, 0);
});

// ── filterDynamicReferences ────────────────────────────────────────────────

test('dynamic filter: demotes to CAUTION when name appears as string literal', () => {
  const candidates = [
    { name: 'handleClick', file: 'src/a.js', line: 5, key: 'src/a.js::handleClick', tierHint: 'safe' },
  ];
  const fc = new Map([
    ['src/a.js', 'export function handleClick() {}\n'],
    ['src/router.js', 'const map = { "handleClick": null };\n'],
  ]);
  const { kept } = filterDynamicReferences(candidates, fc);
  assert.equal(kept[0].tierHint, 'caution');
  assert.equal(kept[0].reason, 'dynamic-reference-match');
});

test('dynamic filter: drops the candidate when a framework decorator is present', () => {
  // `def index()` is on line 2; `@app.route` is on line 1 (line - 2 = 0).
  const candidates = [
    { name: 'index', file: 'src/views.py', line: 2, key: 'src/views.py::index', tierHint: 'safe' },
  ];
  const fc = new Map([
    ['src/views.py', '@app.route\ndef index():\n    return "ok"\n'],
  ]);
  const { kept, removed } = filterDynamicReferences(candidates, fc);
  assert.equal(kept.length, 0);
  assert.equal(removed[0].reason, 'framework-decorator');
});

test('dynamic filter: keeps SAFE tier when no dynamic-ref signal', () => {
  const candidates = [
    { name: 'internalHelper', file: 'src/a.js', line: 5, key: 'src/a.js::internalHelper', tierHint: 'safe' },
  ];
  const fc = new Map([
    ['src/a.js', 'function internalHelper() {}\n'],
    ['src/b.js', 'export const other = 42;\n'],
  ]);
  const { kept } = filterDynamicReferences(candidates, fc);
  assert.equal(kept[0].tierHint, 'safe');
});

// ── classifyTier ───────────────────────────────────────────────────────────

test('classifyTier: entry-point files always DANGER', () => {
  assert.equal(classifyTier({ file: 'bin/cli.js' }), 'danger');
  assert.equal(classifyTier({ file: 'src/main.go' }), 'danger');
  assert.equal(classifyTier({ file: 'manage.py' }), 'danger');
});

test('classifyTier: honours tierHint for non-entry-point files', () => {
  assert.equal(classifyTier({ file: 'src/util.js', tierHint: 'safe' }), 'safe');
  assert.equal(classifyTier({ file: 'src/util.js', tierHint: 'caution' }), 'caution');
});

// ── groupByTier ────────────────────────────────────────────────────────────

test('groupByTier: buckets correctly', () => {
  const f = [
    { tier: 'safe' }, { tier: 'caution' }, { tier: 'safe' }, { tier: 'danger' },
  ];
  const g = groupByTier(f);
  assert.equal(g.safe.length, 2);
  assert.equal(g.caution.length, 1);
  assert.equal(g.danger.length, 1);
});

// ── scanDeadCode integration ───────────────────────────────────────────────

test('scanDeadCode: ties together JS callgraph + wrapper detection + tier classifier', () => {
  const exported = makeFn('src/util.js', 'orphan', { exported: true });
  const wrapper  = makeFn('src/wrap.js', 'shim',   { exported: true, body: 'return real(a)', params: [{ name: 'a' }] });
  const real     = makeFn('src/wrap.js', 'real',   { exported: true });
  const cg = makeCallgraph([exported, wrapper, real], [
    { caller: wrapper.qid, callee: real.qid },
  ]);
  const fc = new Map([
    ['src/util.js', 'export function orphan() {}\n'],
    ['src/wrap.js', 'export function shim(a){ return real(a); }\nexport function real(){}\n'],
  ]);
  const out = scanDeadCode('.', { languages: ['js'], callgraph: cg, fileContents: fc, skipDynamicCheck: true });
  // Expect at least one unused-export + one wrapper-fn finding.
  assert.ok(out.some(f => f.kind === 'unused-export' && f.name === 'orphan'));
  assert.ok(out.some(f => f.kind === 'wrapper-fn'   && f.name === 'shim'));
  // Every finding has a tier classification.
  for (const f of out) assert.ok(['safe','caution','danger'].includes(f.tier));
});

test('scanDeadCode: empty input returns []', () => {
  assert.deepEqual(scanDeadCode('.', { languages: ['js'] }), []);
});
