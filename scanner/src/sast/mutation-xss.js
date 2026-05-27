import { blankComments } from './_comment-strip.js';
// Mutation-based XSS (mXSS).
//
// mXSS happens when "safe-looking" HTML is re-serialized through the DOM and
// becomes unsafe. The canonical shape:
//
//   const safeHtml = sanitize(userHtml);
//   container.innerHTML = safeHtml;          // safe so far
//   const round = container.innerHTML;       // browser-serialized
//   otherEl.innerHTML = round;               // mutation point — re-parse can
//                                            // re-introduce script
//
// Less obvious shapes:
//   - DOMParser().parseFromString(s, "text/html").body.innerHTML  on user input
//   - new XMLSerializer().serializeToString(...) into innerHTML
//   - template re-render via .innerHTML after .innerHTML on user-controlled.

const RE_PARSE_THEN_INNERHTML = /new\s+DOMParser\s*\(\s*\)\s*\.parseFromString\s*\([^)]+\)\s*\.\s*body\s*\.\s*innerHTML/g;

const SERIALIZER_INTO_INNERHTML = /new\s+XMLSerializer\s*\(\s*\)\s*\.\s*serializeToString[^]*?\.innerHTML\s*=/g;

const ROUNDTRIP_RE = /(\w+)\s*\.\s*innerHTML\s*=\s*\w+[^]{0,200}\1\s*\.\s*innerHTML[^]{0,200}\.\s*innerHTML\s*=/g;

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

export function scanMutationXSS(fp, raw) {
  if (!/\.(?:js|jsx|ts|tsx|mjs|cjs|html|htm|vue|svelte)$/i.test(fp)) return [];
  if (!raw || raw.length > 500_000) return [];
  const code = blankComments(raw);
  const findings = [];
  const seen = new Set();
  const push = (f) => { if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); } };

  let m;
  const r1 = new RegExp(RE_PARSE_THEN_INNERHTML.source, RE_PARSE_THEN_INNERHTML.flags);
  while ((m = r1.exec(code))) {
    const line = lineOf(raw, m.index);
    push({
      id: `mxss-parse-roundtrip:${fp}:${line}`,
      file: fp, line,
      vuln: 'Mutation XSS: DOMParser → .body.innerHTML round-trip on potentially-tainted HTML',
      severity: 'medium',
      cwe: 'CWE-79',
      stride: 'Tampering',
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
      remediation: 'Re-serializing HTML through the DOM can re-introduce script via known mutation tricks (`<noscript>`, malformed comments, `<svg>` namespace confusion). If you must round-trip, sanitize the *output* of the round-trip with DOMPurify on the final string, not the input. Better: keep user content as text nodes (`textContent`) instead of HTML.',
      parser: 'MUTATION-XSS',
      confidence: 0.75,
    });
  }

  const r2 = new RegExp(SERIALIZER_INTO_INNERHTML.source, SERIALIZER_INTO_INNERHTML.flags);
  while ((m = r2.exec(code))) {
    const line = lineOf(raw, m.index);
    push({
      id: `mxss-serialize-into-innerhtml:${fp}:${line}`,
      file: fp, line,
      vuln: 'Mutation XSS: XMLSerializer output assigned to innerHTML',
      severity: 'medium',
      cwe: 'CWE-79',
      stride: 'Tampering',
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
      remediation: 'XML serialization re-parsed as HTML changes meaning — `<script xmlns="http://www.w3.org/1999/xhtml">` is inert as XML but live in HTML. Use `textContent` if the goal is plain text; use a typed templating engine if the goal is structured HTML.',
      parser: 'MUTATION-XSS',
      confidence: 0.80,
    });
  }

  const r3 = new RegExp(ROUNDTRIP_RE.source, ROUNDTRIP_RE.flags);
  while ((m = r3.exec(code))) {
    const line = lineOf(raw, m.index);
    push({
      id: `mxss-innerhtml-roundtrip:${fp}:${line}`,
      file: fp, line,
      vuln: 'Mutation XSS: read-back of innerHTML then re-assigned to another innerHTML',
      severity: 'medium',
      cwe: 'CWE-79',
      stride: 'Tampering',
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
      remediation: 'The DOM normalizes HTML on `.innerHTML` read; re-parsing the result on another element can re-introduce executable script. If you need to copy markup, use `el.cloneNode(true)` and `appendChild` instead of innerHTML round-trips.',
      parser: 'MUTATION-XSS',
      confidence: 0.65,
    });
  }

  // Email template XSS: user data rendered into HTML email body
  const emailSinkRe = /\b(?:sendMail|transporter\.sendMail|sg\.send|ses\.sendEmail|mailgun\.messages\.create|send_email|mail\.send)\s*\(/g;
  for (const em of code.matchAll(emailSinkRe)) {
    const after = code.slice(em.index, em.index + 500);
    if (!/\bhtml\s*:/i.test(after)) continue;
    const taintHint = /(?:req\.|request\.|params|body|query|user\.\w+|data\.\w+)/.test(after);
    const templateHint = /(?:ejs\.render|pug\.render|mustache\.render|handlebars\.compile|marked\.parse|render_template|Jinja2|\.render\s*\()/.test(after);
    if (!taintHint && !templateHint) continue;
    const line = lineOf(raw, em.index);
    push({
      id: `email-template-xss:${fp}:${line}`,
      file: fp, line,
      vuln: 'Email Template XSS — user data rendered into HTML email body',
      severity: 'high',
      cwe: 'CWE-79',
      family: 'email-template-xss',
      stride: 'Tampering',
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
      remediation: 'HTML-escape user-supplied data before inserting into email templates. Use the template engine\'s auto-escape mode. Consider rendering text-only emails for user-generated content.',
      parser: 'EMAIL-XSS',
      confidence: 0.65,
    });
  }

  // Markdown → HTML → innerHTML chain
  const markdownHtmlRe = /\bmarked\.parse\s*\([^)]*(?:req\.|request\.|params|body|query|user)/g;
  for (const mm of code.matchAll(markdownHtmlRe)) {
    const line = lineOf(raw, mm.index);
    push({
      id: `markdown-xss:${fp}:${line}`,
      file: fp, line,
      vuln: 'Markdown→HTML XSS — user-supplied Markdown rendered to HTML without sanitization',
      severity: 'high',
      cwe: 'CWE-79',
      family: 'xss',
      stride: 'Tampering',
      snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
      remediation: 'Pipe marked output through DOMPurify: `const html = DOMPurify.sanitize(marked.parse(userInput))`. Or use marked with `sanitize: true` option.',
      parser: 'MARKDOWN-XSS',
      confidence: 0.70,
    });
  }

  return findings;
}
