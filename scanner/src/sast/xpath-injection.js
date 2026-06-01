import { blankComments } from './_comment-strip.js';
// XPath injection.
//
// Same shape as LDAP injection — string concatenation into a query language
// that has its own operators. We catch concatenation patterns into:
//   - javax.xml.xpath / org.jaxen / org.dom4j  (Java, Kotlin)
//   - lxml.etree / xml.etree                   (Python)
//   - xpath npm pkg                            (Node)
//   - DOMXPath::query / ::evaluate             (PHP)
//   - XPathNavigator.Select / SelectNodes      (C#)
//   - Nokogiri xpath / REXML::XPath            (Ruby)
//   - xmlpath / htmlquery / antchfx xpath      (Go)

// A string literal whose body may contain the OTHER quote char — an XPath
// expression like `"//user[@name='" + x` embeds a single quote, which a naive
// `[^"']*` body would stop at. Match each quote style with its own body.
const STR = String.raw`(?:"(?:[^"\\\n]|\\.)*"|'(?:[^'\\\n]|\\.)*')`;

const PATTERNS = {
  java: new RegExp(String.raw`\.\s*(?:compile|evaluate)\s*\(\s*${STR}\s*\+\s*\w+`, 'g'),
  kt:   new RegExp(String.raw`\.\s*(?:compile|evaluate)\s*\(\s*${STR}\s*\+\s*\w+|\.\s*(?:compile|evaluate)\s*\(\s*"[^"\n]*\$\{`, 'g'),
  py:   new RegExp(String.raw`\.\s*(?:xpath|find|findall)\s*\(\s*${STR}\s*[%+]\s*\w+|\.\s*xpath\s*\(\s*[fF]["']`, 'g'),
  js:   new RegExp(String.raw`\b(?:xpath|select)\s*\(\s*(?:` + '`' + String.raw`[^` + '`' + String.raw`]*` + '`' + String.raw`|${STR})\s*\+\s*\w+|\bxpath\.select\s*\(\s*` + '`' + String.raw`[^` + '`' + String.raw`]*\$\{`, 'g'),
  // PHP DOMXPath: $xpath->query("…" . $u) / ->evaluate("…" . $u)
  php:  new RegExp(String.raw`->\s*(?:query|evaluate)\s*\(\s*${STR}\s*\.\s*\$\w+`, 'g'),
  // C#: nav.Select / doc.SelectNodes / SelectSingleNode / XPathSelectElements with concat
  cs:   new RegExp(String.raw`\.\s*(?:Select|SelectNodes|SelectSingleNode|XPathSelectElement|XPathSelectElements|Compile)\s*\(\s*\$?${STR}\s*\+\s*\w+|\.\s*(?:Select|SelectNodes|SelectSingleNode)\s*\(\s*\$"[^"\n]*\{`, 'g'),
  // Ruby Nokogiri / REXML: .xpath("…#{u}") / .at_xpath / XPath.match with #{} or concat
  rb:   new RegExp(String.raw`\.\s*(?:xpath|at_xpath|search)\s*\(\s*(?:"[^"\n]*#\{|'[^'\n]*#\{)|\.\s*(?:xpath|at_xpath)\s*\(\s*${STR}\s*\+\s*\w+|XPath\s*\.\s*(?:match|first|each)\s*\([^,]+,\s*(?:"[^"\n]*#\{|'[^'\n]*#\{)`, 'g'),
  // Go xmlpath/htmlquery/antchfx: xmlpath.Compile("…"+u) / htmlquery.Find(doc, "…"+u)
  go:   new RegExp(String.raw`\b(?:xmlpath\.Compile|htmlquery\.(?:Find|FindOne|QueryAll|Query)|xpath\.Compile|navigator\.Compile)\s*\([^)]*${STR}\s*\+\s*\w+`, 'g'),
};

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

export function scanXPathInjection(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  let lang;
  if (/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(fp)) lang = 'js';
  else if (/\.java$/i.test(fp)) lang = 'java';
  else if (/\.kt$/i.test(fp)) lang = 'kt';
  else if (/\.py$/i.test(fp)) lang = 'py';
  else if (/\.(?:php|phtml)$/i.test(fp)) lang = 'php';
  else if (/\.cs$/i.test(fp)) lang = 'cs';
  else if (/\.rb$/i.test(fp)) lang = 'rb';
  else if (/\.go$/i.test(fp)) lang = 'go';
  else return [];

  const code = blankComments(raw, (lang === 'py' || lang === 'rb') ? 'py' : undefined);
  // Relevance gate: an XPath-ish API or an XPath expression literal must appear.
  if (!/\bxpath|XPath|\.xpath\(|DOMXPath|SelectNodes|SelectSingleNode|XPathNavigator|xmlpath|htmlquery|REXML|\/\/\w/i.test(code)) return [];
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
