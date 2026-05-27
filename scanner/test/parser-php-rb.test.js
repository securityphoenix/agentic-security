import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parsePhpFile } from '../src/ir/parser-php.js';
import { parseRubyFile } from '../src/ir/parser-rb.js';

// ── PHP parser ───────────────────────────────────────────────────────────────

test('parsePhpFile: captures function with params', () => {
  const code = `<?php
function getUser($id) {
    $result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $id);
    return $result;
}
`;
  const ir = parsePhpFile('app.php', code);
  assert.ok(ir);
  assert.equal(ir.functions.length, 1);
  assert.equal(ir.functions[0].name, 'getUser');
  assert.deepEqual(ir.functions[0].params, ['$id']);
  const nodes = Object.values(ir.functions[0].cfg.nodes);
  const assigns = nodes.filter(n => n.kind === 'assign');
  assert.ok(assigns.some(a => a.target === '$result'), 'expected $result assignment');
});

test('parsePhpFile: captures class method with modifiers', () => {
  const code = `<?php
class UserController {
    public function show($request) {
        $name = $request->input('name');
        return $name;
    }
}
`;
  const ir = parsePhpFile('controller.php', code);
  assert.ok(ir);
  assert.equal(ir.functions[0].name, 'show');
  assert.deepEqual(ir.functions[0].params, ['$request']);
});

test('parsePhpFile: lowers method calls', () => {
  const code = `<?php
function process($data) {
    $db->query("INSERT INTO logs VALUES (" . $data . ")");
    return true;
}
`;
  const ir = parsePhpFile('app.php', code);
  assert.ok(ir);
  const nodes = Object.values(ir.functions[0].cfg.nodes);
  const calls = nodes.filter(n => n.kind === 'call');
  assert.ok(calls.length >= 1, 'expected a call node');
});

test('parsePhpFile: returns null for non-PHP files', () => {
  assert.equal(parsePhpFile('app.js', 'function f(){}'), null);
});

test('parsePhpFile: IR shape matches universal contract', () => {
  const code = `<?php
function f($x) {
    $y = $x + 1;
    return $y;
}
`;
  const ir = parsePhpFile('test.php', code);
  assert.ok(ir);
  assert.equal(ir.file, 'test.php');
  assert.equal(ir.topLevel, null);
  const fn = ir.functions[0];
  assert.equal(typeof fn.qid, 'string');
  assert.ok(Array.isArray(fn.params));
  assert.equal(typeof fn.cfg.nodes, 'object');
  for (const [, node] of Object.entries(fn.cfg.nodes)) {
    assert.ok(node.kind);
    assert.ok(Array.isArray(node.succ));
    assert.ok(Array.isArray(node.pred));
  }
});

// ── Ruby parser ──────────────────────────────────────────────────────────────

test('parseRubyFile: captures def with params', () => {
  const code = `
def show(id)
  user = User.find(id)
  return user
end
`;
  const ir = parseRubyFile('app.rb', code);
  assert.ok(ir);
  assert.equal(ir.functions.length, 1);
  assert.equal(ir.functions[0].name, 'show');
  assert.deepEqual(ir.functions[0].params, ['id']);
  const nodes = Object.values(ir.functions[0].cfg.nodes);
  const assigns = nodes.filter(n => n.kind === 'assign');
  assert.ok(assigns.some(a => a.target === 'user'), 'expected user assignment');
});

test('parseRubyFile: captures def self.method', () => {
  const code = `
def self.find_by_name(name)
  sql = "SELECT * FROM users WHERE name = '" + name + "'"
  return User.find_by_sql(sql)
end
`;
  const ir = parseRubyFile('user.rb', code);
  assert.ok(ir);
  assert.equal(ir.functions[0].name, 'find_by_name');
  assert.deepEqual(ir.functions[0].params, ['name']);
});

test('parseRubyFile: handles string interpolation', () => {
  const code = `
def greet(name)
  msg = "Hello, #{name}!"
  return msg
end
`;
  const ir = parseRubyFile('app.rb', code);
  assert.ok(ir);
  const nodes = Object.values(ir.functions[0].cfg.nodes);
  const assign = nodes.find(n => n.kind === 'assign' && n.target === 'msg');
  assert.ok(assign);
  assert.equal(assign.source.kind, 'tpl');
});

test('parseRubyFile: handles bare method calls', () => {
  const code = `
def create(params)
  cmd = params[:cmd]
  system cmd
  return
end
`;
  const ir = parseRubyFile('app.rb', code);
  assert.ok(ir);
  const nodes = Object.values(ir.functions[0].cfg.nodes);
  const calls = nodes.filter(n => n.kind === 'call');
  assert.ok(calls.some(c => c.callee === 'system'), 'expected system call node');
});

test('parseRubyFile: returns null for non-Ruby files', () => {
  assert.equal(parseRubyFile('app.js', 'function f(){}'), null);
});

test('parseRubyFile: multiple defs in one file', () => {
  const code = `
def a(x)
  return x
end

def b(y)
  return y
end
`;
  const ir = parseRubyFile('app.rb', code);
  assert.ok(ir);
  assert.equal(ir.functions.length, 2);
  assert.equal(ir.functions[0].name, 'a');
  assert.equal(ir.functions[1].name, 'b');
});
