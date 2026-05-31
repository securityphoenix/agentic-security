import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scanFrontendHygiene } from '../src/sast/frontend-hygiene.js';

test('flags target=_blank without rel=noopener', () => {
  const f = scanFrontendHygiene('page.html', '<a href="https://x.com" target="_blank">go</a>');
  assert.equal(f.length, 1);
  assert.equal(f[0].cwe, 'CWE-1022');
});

test('does NOT flag target=_blank WITH rel=noopener/noreferrer', () => {
  assert.equal(scanFrontendHygiene('p.html', '<a target="_blank" rel="noopener noreferrer" href="/x">go</a>').length, 0);
  assert.equal(scanFrontendHygiene('p.html', '<a target="_blank" rel="noopener" href="/x">go</a>').length, 0);
});

test('flags cross-origin <script> without integrity, not same-origin', () => {
  const ext = scanFrontendHygiene('i.html', '<script src="https://cdn.example.com/x.js"></script>');
  assert.ok(ext.some(x => x.cwe === 'CWE-353'));
  // relative/same-origin script needs no SRI
  assert.equal(scanFrontendHygiene('i.html', '<script src="/js/app.js"></script>').length, 0);
  // with integrity → clean
  assert.equal(scanFrontendHygiene('i.html', '<script src="//cdn.x.com/a.js" integrity="sha384-abc" crossorigin="anonymous"></script>').length, 0);
});

test('flags cross-origin stylesheet without integrity', () => {
  const f = scanFrontendHygiene('i.html', '<link rel="stylesheet" href="https://cdn.x.com/a.css">');
  assert.ok(f.some(x => x.id.startsWith('missing-sri-link')));
});

test('flags Angular bypassSecurityTrust* on a dynamic value, not a literal', () => {
  const dyn = scanFrontendHygiene('a.component.ts', 'this.html = this.sanitizer.bypassSecurityTrustHtml(userInput);');
  assert.equal(dyn.length, 1);
  assert.equal(dyn[0].cwe, 'CWE-79');
  // constant literal argument is developer-controlled → safe
  assert.equal(scanFrontendHygiene('a.ts', "x = s.bypassSecurityTrustUrl('https://safe.example.com');").length, 0);
});

test('ignores unrelated file types', () => {
  assert.equal(scanFrontendHygiene('main.go', '<a target="_blank">x</a>').length, 0);
});
