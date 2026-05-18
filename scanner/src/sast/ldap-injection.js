import { blankComments } from './_comment-strip.js';
// LDAP injection.
//
// LDAP filters use a parens/operator syntax; concatenating user input into a
// filter lets a client smuggle additional `|(|(`-style clauses that return
// records they shouldn't see, or auth-bypass via `(uid=*)(uid=admin*)`.
//
// We catch:
//   - Node ldapjs:  client.search(base, { filter: "(uid=" + name + ")" })
//   - Java JNDI:    NamingEnumeration<SearchResult> ne = ctx.search(base, "(cn=" + name + ")", ...)
//   - Python ldap3: conn.search(base, "(uid=" + name + ")")

const FILTER_CONCAT_RE = {
  js:   /\bfilter\s*:\s*[`"']?\([^`"')]*\b(?:uid|cn|mail|sAMAccountName)\s*=\s*[`"']?\s*(?:\+|\$\{)/g,
  java: /\.search\s*\(\s*[^,]+,\s*"[^"]*\b(?:uid|cn|mail|sAMAccountName)\s*=[^"]*"\s*\+\s*\w+/g,
  py:   /\.search\s*\([^)]*\b(?:uid|cn|mail|sAMAccountName)\s*=[^)]*['"]?\s*\+\s*\w+/g,
};

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

export function scanLDAPInjection(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  let lang;
  if (/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(fp)) lang = 'js';
  else if (/\.java$/i.test(fp)) lang = 'java';
  else if (/\.py$/i.test(fp)) lang = 'py';
  else return [];

  const code = blankComments(raw, lang === 'py' ? 'py' : undefined);
  const re = new RegExp(FILTER_CONCAT_RE[lang].source, FILTER_CONCAT_RE[lang].flags);
  const findings = [];
  const seen = new Set();
  let m;
  while ((m = re.exec(code))) {
    const line = lineOf(raw, m.index);
    const id = `ldap-injection:${fp}:${line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    findings.push({
      id,
      file: fp, line,
      vuln: 'LDAP Injection: filter string built via concatenation',
      severity: 'high',
      cwe: 'CWE-90',
      stride: 'Tampering',
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
      remediation: 'Escape LDAP filter metacharacters (`*`, `(`, `)`, `\\`, NUL) before substitution, or use a parameterized API. Node ldapjs: build the filter from a typed object — `new EqualityFilter({ attribute: "uid", value: name })`. Java JNDI: use `Rdn.escapeValue(name)`. Python ldap3: `ldap3.utils.conv.escape_filter_chars(name)`.',
      parser: 'LDAP-INJECTION',
      confidence: 0.85,
    });
  }
  return findings;
}
