import { blankComments } from './_comment-strip.js';
// XPath injection.
//
// Same shape as LDAP injection — string concatenation into a query language
// that has its own operators. We catch concatenation patterns into:
//   - javax.xml.xpath / org.jaxen / org.dom4j  (Java)
//   - lxml.etree / xml.etree                   (Python)
//   - xpath npm pkg                            (Node)

const PATTERNS = {
  java: /\.\s*(?:compile|evaluate)\s*\(\s*"[^"]*"\s*\+\s*\w+/g,
  py:   /\.\s*(?:xpath|find|findall)\s*\(\s*["'][^"']*["']\s*[%+]\s*\w+|\.\s*xpath\s*\(\s*f["']/g,
  js:   /\b(?:xpath|select)\s*\(\s*[`"][^`"]*[`"]\s*\+\s*\w+|\bxpath\.select\s*\(\s*`[^`]*\$\{/g,
};

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

export function scanXPathInjection(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  let lang;
  if (/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(fp)) lang = 'js';
  else if (/\.java$/i.test(fp)) lang = 'java';
  else if (/\.py$/i.test(fp)) lang = 'py';
  else return [];

  const code = blankComments(raw, lang === 'py' ? 'py' : undefined);
  if (!/\bxpath|XPath|\.xpath\(/i.test(code)) return [];
  const re = new RegExp(PATTERNS[lang].source, PATTERNS[lang].flags);
  const findings = [];
  const seen = new Set();
  let m;
  while ((m = re.exec(code))) {
    const line = lineOf(raw, m.index);
    const id = `xpath-injection:${fp}:${line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    findings.push({
      id,
      file: fp, line,
      vuln: 'XPath Injection: query built via string concatenation',
      severity: 'high',
      cwe: 'CWE-643',
      stride: 'Tampering',
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
      remediation: 'Use a parameterized XPath API. Java: `XPathExpression.evaluate(doc, XPathConstants.NODESET)` with `xpath.setXPathVariableResolver(...)`. Python lxml: `tree.xpath("//user[name=$n]", n=name)`. JavaScript: pass values as variables to an evaluator that supports binding, never via concatenation.',
      parser: 'XPATH-INJECTION',
      confidence: 0.85,
    });
  }
  return findings;
}
