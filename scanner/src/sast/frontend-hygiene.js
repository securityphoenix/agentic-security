// Front-end security hygiene — additive, high-precision client-side checks
// that the engine did not previously cover. None of these change existing
// findings; each emits its own finding class.
//
//   1. Reverse tabnabbing (CWE-1022): `<a target="_blank">` without
//      `rel="noopener"` — the opened page can rewrite `window.opener.location`
//      and phish. (Modern browsers default to noopener, so: low.)
//   2. Missing Subresource Integrity (CWE-353): a cross-origin
//      `<script src="https://cdn…">` / `<link rel=stylesheet href="//…">`
//      with no `integrity=` — a compromised/MITM'd CDN executes in your origin.
//   3. Angular sanitizer bypass (CWE-79): `DomSanitizer.bypassSecurityTrust*`
//      with a non-literal argument explicitly disables Angular's built-in XSS
//      protection on attacker-influenced data.

import { blankComments } from './_comment-strip.js';

const MARKUP_RE = /\.(?:html?|jsx|tsx|vue|svelte|php|erb|ejs|hbs|handlebars|astro)$/i;
const SCRIPT_RE = /\.(?:ts|tsx|js|jsx|mjs|cjs)$/i;

const A_BLANK_RE   = /<a\b[^>]*\btarget\s*=\s*["']_blank["'][^>]*>/gi;
const REL_NOOPENER = /\brel\s*=\s*["'][^"']*\bno(?:opener|referrer)\b/i;

const EXT_SCRIPT_RE = /<script\b[^>]*\bsrc\s*=\s*["'](?:https?:)?\/\/[^"']+["'][^>]*>/gi;
const EXT_LINK_RE   = /<link\b[^>]*\bhref\s*=\s*["'](?:https?:)?\/\/[^"']+["'][^>]*>/gi;
const HAS_INTEGRITY = /\bintegrity\s*=/i;
const IS_STYLESHEET = /\brel\s*=\s*["'][^"']*\bstylesheet\b/i;

const NG_BYPASS_RE = /\.bypassSecurityTrust(?:Html|Script|Style|Url|ResourceUrl)\s*\(\s*([^)]*?)\)/g;
// A pure string literal argument is a developer-controlled constant — safe.
const PURE_LITERAL = /^\s*(['"`])(?:\\.|(?!\1).)*\1\s*$/;

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

export function scanFrontendHygiene(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  const isMarkup = MARKUP_RE.test(fp);
  const isScript = SCRIPT_RE.test(fp);
  if (!isMarkup && !isScript) return [];

  const findings = [];

  if (isMarkup) {
    // 1. Reverse tabnabbing.
    A_BLANK_RE.lastIndex = 0;
    let m;
    while ((m = A_BLANK_RE.exec(raw))) {
      if (REL_NOOPENER.test(m[0])) continue;
      findings.push({
        id: `tabnabbing:${fp}:${lineOf(raw, m.index)}`,
        severity: 'low', file: fp, line: lineOf(raw, m.index),
        vuln: 'Reverse tabnabbing (target="_blank" without rel="noopener")',
        cwe: 'CWE-1022', family: 'client-side', parser: 'SAST',
        description: 'A link opens a new tab with target="_blank" but no rel="noopener". The destination page receives a reference to window.opener and can redirect this tab to a phishing page.',
        remediation: 'Add rel="noopener noreferrer" (or rel="noopener") to every target="_blank" link.',
      });
    }
    // 2. Missing SRI on cross-origin <script>.
    EXT_SCRIPT_RE.lastIndex = 0;
    while ((m = EXT_SCRIPT_RE.exec(raw))) {
      if (HAS_INTEGRITY.test(m[0])) continue;
      findings.push({
        id: `missing-sri-script:${fp}:${lineOf(raw, m.index)}`,
        severity: 'medium', file: fp, line: lineOf(raw, m.index),
        vuln: 'Missing Subresource Integrity on cross-origin <script>',
        cwe: 'CWE-353', family: 'supply-chain', parser: 'SAST',
        description: 'A script is loaded from a third-party origin without an integrity= hash. If that host (or a CDN in front of it) is compromised or MITM\'d, arbitrary code runs in your origin.',
        remediation: 'Add an integrity="sha384-…" attribute and crossorigin="anonymous", or self-host the asset.',
      });
    }
    // 2b. Missing SRI on cross-origin stylesheet <link>.
    EXT_LINK_RE.lastIndex = 0;
    while ((m = EXT_LINK_RE.exec(raw))) {
      if (!IS_STYLESHEET.test(m[0])) continue;
      if (HAS_INTEGRITY.test(m[0])) continue;
      findings.push({
        id: `missing-sri-link:${fp}:${lineOf(raw, m.index)}`,
        severity: 'low', file: fp, line: lineOf(raw, m.index),
        vuln: 'Missing Subresource Integrity on cross-origin stylesheet',
        cwe: 'CWE-353', family: 'supply-chain', parser: 'SAST',
        description: 'A stylesheet is loaded from a third-party origin without an integrity= hash, so a compromised CDN can inject CSS-based exfiltration / UI redress.',
        remediation: 'Add integrity="sha384-…" + crossorigin="anonymous", or self-host the stylesheet.',
      });
    }
  }

  if (isScript) {
    // 3. Angular sanitizer bypass with a non-literal argument.
    const code = blankComments(raw);
    NG_BYPASS_RE.lastIndex = 0;
    let m;
    while ((m = NG_BYPASS_RE.exec(code))) {
      const arg = (m[1] || '').trim();
      if (!arg || PURE_LITERAL.test(arg)) continue; // constant → safe
      findings.push({
        id: `ng-sanitizer-bypass:${fp}:${lineOf(code, m.index)}`,
        severity: 'high', file: fp, line: lineOf(code, m.index),
        vuln: 'Angular sanitizer bypass on dynamic value (bypassSecurityTrust*)',
        cwe: 'CWE-79', family: 'xss', parser: 'SAST',
        description: 'DomSanitizer.bypassSecurityTrust* explicitly disables Angular\'s built-in XSS protection. Called on a non-constant value, attacker-influenced data reaches the DOM unsanitized.',
        remediation: 'Avoid bypassSecurityTrust* on dynamic data; bind trusted values only, or sanitize with DomSanitizer.sanitize() / a strict allow-list first.',
      });
    }
  }

  return findings;
}
