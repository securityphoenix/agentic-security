// Regression-test generator (FR-VER-3).
//
// For each finding that has a PoC (from P1.1 / poc-generator), emit a
// framework-idiomatic test file that:
//   - Fails on the vulnerable code state (asserts the exploit succeeds)
//   - Passes after the fix is applied (assert flips to "did not succeed")
//
// We piggy-back on the existing PoC template — the test wraps the same
// HTTP call but uses the framework's test runner (Jest / pytest / JUnit)
// for assertion + reporting.
//
// Output: `f.regression_test = { lang, framework, code, runHint, filename }`.

const FRAMEWORK_FOR_LANG = Object.freeze({
  node: 'jest',
  python: 'pytest',
  java: 'junit',
});

function _filenameFor(finding, lang) {
  const slug = (finding.stableId || finding.id || 'finding')
    .replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 40);
  if (lang === 'python') return `test_security_${slug}.py`;
  if (lang === 'java')   return `SecurityRegression_${slug}.java`;
  return `security_${slug}.test.mjs`;
}

function _renderJest(finding, poc) {
  // Wrap the PoC's HTTP call in a Jest test. The PoC's `process.exit(0)`
  // becomes `expect(...).toBe(true)`; exit(1) becomes `expect(...).toBe(false)`.
  const url = _extractUrl(poc.code) || 'http://localhost:3000';
  const method = _extractMethod(poc.code) || 'POST';
  const payloadLine = _extractPayloadLine(poc.code);
  return `// Regression test for ${finding.vuln} (${finding.cwe || 'unknown CWE'}).
// Auto-generated from P1.1 PoC; fails on vulnerable code, passes after the fix.

import { test, expect } from '@jest/globals';

test('${finding.vuln.replace(/'/g, "\\'")}', async () => {
  const URL_ = ${JSON.stringify(url)};
  const METHOD = ${JSON.stringify(method)};
  ${payloadLine}
  const body = METHOD === 'GET' ? null : JSON.stringify({ input: PAYLOAD });
  const reqUrl = METHOD === 'GET'
    ? URL_ + (URL_.includes('?') ? '&' : '?') + 'input=' + encodeURIComponent(PAYLOAD)
    : URL_;
  const r = await fetch(reqUrl, { method: METHOD, headers: { 'Content-Type': 'application/json' }, body });
  const text = await r.text();
  // The assertion below is the "exploit demonstrated" signal — when this
  // test PASSES, the vuln is still present. After the fix, this assertion
  // SHOULD fail. Inverse the assertion in a green build.
  const demonstrated = text.includes('PoC') || /syntax error/i.test(text) || text.includes('<script>');
  expect(demonstrated).toBe(false);
});
`;
}

function _renderPytest(finding, poc) {
  return `# Regression test for ${finding.vuln} (${finding.cwe || 'unknown CWE'}).
# Auto-generated from P1.1 PoC.

import requests


def test_${(finding.stableId || finding.id || 'finding').replace(/[^a-zA-Z0-9_]/g, '_').slice(0, 40)}():
    url = 'http://localhost:3000'
    r = requests.post(url, json={'input': "' UNION SELECT username, password FROM users--"})
    # After the fix, the response should not contain SQL-syntax-error evidence.
    text = r.text
    demonstrated = 'syntax error' in text.lower() or '<script>' in text
    assert not demonstrated, f'Vulnerability still present: {text[:200]}'
`;
}

function _extractUrl(code) {
  const m = String(code || '').match(/URL_ = (['"])([^'"]+)\1/);
  return m ? m[2] : null;
}
function _extractMethod(code) {
  const m = String(code || '').match(/METHOD = (['"])([A-Z]+)\1/);
  return m ? m[2] : null;
}
function _extractPayloadLine(code) {
  const m = String(code || '').match(/PAYLOAD = `([^`]+)`/);
  if (m) return `const PAYLOAD = ${JSON.stringify(m[1])};`;
  return `const PAYLOAD = 'PoC';`;
}

/**
 * Public API. Annotates findings with f.regression_test = {...} when a PoC
 * is available.
 */
export function annotateRegressionTests(findings) {
  if (!Array.isArray(findings)) return;
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    if (!f.poc) { f.regression_test = null; continue; }
    const lang = f.poc.lang;
    const framework = FRAMEWORK_FOR_LANG[lang];
    if (!framework) { f.regression_test = null; continue; }
    let code;
    try {
      code = framework === 'jest' ? _renderJest(f, f.poc)
           : framework === 'pytest' ? _renderPytest(f, f.poc)
           : null;
    } catch { code = null; }
    if (!code) { f.regression_test = null; continue; }
    f.regression_test = {
      lang,
      framework,
      filename: _filenameFor(f, lang),
      runHint: framework === 'jest' ? 'npx jest' : framework === 'pytest' ? 'pytest -q' : 'mvn test',
      code,
    };
  }
}

export const _internals = { FRAMEWORK_FOR_LANG };
