// Roadmap #3 — same-file-preference call resolution.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildCallGraph } from '../src/ir/callgraph.js';

// Two files each define a function named `handler` (a common collision).
function twoFileGraph() {
  const perFileIR = {
    'a.js': { functions: [{ qid: 'a.js::handler@1#aaa', name: 'handler', file: 'a.js', calls: [] }] },
    'b.js': { functions: [{ qid: 'b.js::handler@1#bbb', name: 'handler', file: 'b.js', calls: [] }] },
  };
  return buildCallGraph(perFileIR, { 'a.js': '', 'b.js': '' });
}

test('resolve prefers the caller\'s own file on a cross-file name collision', () => {
  const g = twoFileGraph();
  assert.equal(g.resolve('handler', 'a.js'), 'a.js::handler@1#aaa');
  assert.equal(g.resolve('handler', 'b.js'), 'b.js::handler@1#bbb');
});

test('resolve without a callerFile is backward-compatible (still resolves)', () => {
  const g = twoFileGraph();
  const r = g.resolve('handler');
  // Returns one of the two (original first-match behavior) — never null.
  assert.ok(r === 'a.js::handler@1#aaa' || r === 'b.js::handler@1#bbb');
});

test('callerFile with no local match falls back to global resolution (no dropped edge)', () => {
  const perFileIR = {
    'a.js': { functions: [{ qid: 'a.js::caller@1#x', name: 'caller', file: 'a.js', calls: [] }] },
    'util.js': { functions: [{ qid: 'util.js::escape@1#y', name: 'escape', file: 'util.js', calls: [] }] },
  };
  const g = buildCallGraph(perFileIR, { 'a.js': '', 'util.js': '' });
  // `escape` isn't defined in a.js → still resolves to util.js, not null.
  assert.equal(g.resolve('escape', 'a.js'), 'util.js::escape@1#y');
});

test('unknown name still returns null', () => {
  assert.equal(twoFileGraph().resolve('nope', 'a.js'), null);
});
