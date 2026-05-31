// Ruby + PHP structural (taint-independent) injection detectors — PRD Tier 1.
// Closes corpus FNs where the value is routed through a local var first
// (params[:x] / $r->query->get), so the existing token-on-sink rules miss it.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanRuby } from '../src/sast/ruby.js';
import { scanPhp } from '../src/sast/php.js';

const has = (f, cwe) => f.some(x => x.cwe === cwe);
const noneCwe = (f, cwe) => f.filter(x => x.cwe === cwe).length === 0;

test('Ruby SQLi — ActiveRecord .where with #{} interpolation (CWE-89)', () => {
  assert.ok(has(scanRuby('u.rb', 'def i; name = params[:name]; User.where("name = \'#{name}\'"); end'), 'CWE-89'));
  // parameterized → clean
  assert.ok(noneCwe(scanRuby('u.rb', "def i; name = params[:name]; User.where('name = ?', name); end"), 'CWE-89'));
});

test('Ruby cmdi — backtick with #{} interpolation (CWE-78)', () => {
  assert.ok(has(scanRuby('app.rb', 'get("/who"){ user = params[:user]; `finger #{user}` }'), 'CWE-78'));
  // array-form Open3 → clean
  assert.ok(noneCwe(scanRuby('app.rb', "get('/who'){ user = params[:user]; out,_ = Open3.capture2('finger', user); out }"), 'CWE-78'));
});

test('PHP cmdi — shell_exec with concat / $interp (CWE-78)', () => {
  assert.ok(has(scanPhp('C.php', "<?php \$f = \$r->query->get('file'); return shell_exec('gzip ' . \$f);"), 'CWE-78'));
  assert.ok(has(scanPhp('C.php', '<?php $f = $r->query->get("file"); return shell_exec("gzip $f");'), 'CWE-78'));
  // array-form proc_open → clean
  assert.ok(noneCwe(scanPhp('C.php', "<?php \$f = \$r->query->get('file'); proc_open(['gzip', \$f], [], \$p);"), 'CWE-78'));
});

test('PHP SQLi — DB::raw / whereRaw with concat or $interp (CWE-89)', () => {
  assert.ok(has(scanPhp('U.php', '<?php $name = $request->input("name"); return DB::select(DB::raw("SELECT * FROM users WHERE name=\'" . $name . "\'"));'), 'CWE-89'));
  // parameter bindings → clean
  assert.ok(noneCwe(scanPhp('U.php', "<?php \$name = \$request->input('name'); return DB::select('SELECT * FROM users WHERE name=?', [\$name]);"), 'CWE-89'));
});

test('no false positives on clean Ruby / PHP', () => {
  assert.deepEqual(scanRuby('ok.rb', 'def add(a,b); a + b; end'), []);
  assert.deepEqual(scanPhp('ok.php', '<?php function add($a,$b){ return $a + $b; }'), []);
});
