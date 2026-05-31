// Go structural detectors — PRD Tier 1 (Go recall).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanGoStructural as go } from '../src/sast/go-structural.js';

const has = (f, cwe) => f.some(x => x.cwe === cwe);
const none = (f, cwe) => f.filter(x => x.cwe === cwe).length === 0;

test('Go SQLi — db.Query with fmt.Sprintf or concat; parameterized is clean', () => {
  assert.ok(has(go('main.go', 'rows, _ := db.Query(fmt.Sprintf("SELECT * FROM users WHERE name=\'%s\'", name))'), 'CWE-89'));
  assert.ok(has(go('main.go', 'rows, _ := db.Query("SELECT * FROM u WHERE n=\'" + name + "\'")'), 'CWE-89'));
  assert.ok(none(go('main.go', 'rows, _ := db.Query("SELECT * FROM users WHERE name=?", name)'), 'CWE-89'));
});

test('Go path traversal — os.Open with concat/Sprintf; bare/canonicalized is clean', () => {
  assert.ok(has(go('main.go', 'f, err := os.Open("/var/data/" + r.URL.Query().Get("name"))'), 'CWE-22'));
  assert.ok(has(go('main.go', 'f, _ := os.ReadFile(fmt.Sprintf("/data/%s", name))'), 'CWE-22'));
  // canonicalized path bound to a var (no concat in the os.Open arg) → clean
  assert.ok(none(go('main.go', 'want := filepath.Join(base, filepath.Base(name))\nf, err := os.Open(want)'), 'CWE-22'));
});

test('non-Go files and clean Go produce nothing', () => {
  assert.deepEqual(go('a.js', 'db.Query("x" + name)'), []);
  assert.deepEqual(go('ok.go', 'func add(a, b int) int { return a + b }'), []);
});
