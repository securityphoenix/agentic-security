// Timing-safe comparison and type-coercion safety detector.
//
// Flags:
//   1. Direct === / == on HMAC/signature/token/OTP values (timing attack)
//   2. Loose == in authorization checks (type coercion)
//   3. Missing timingSafeEqual / hmac.compare_digest in verification functions

const TIMING_SENSITIVE = /\b(hmac|signature|digest|hash|mac|checksum|token|otp|apiKey|api_key|secret_key|webhook_secret|signing_key)\b/i;
const AUTH_CONTEXT = /\b(role|permission|isAdmin|is_admin|accessLevel|access_level|privilege|authorization|auth_level)\b/i;

function _line(raw, idx) { return raw.slice(0, idx).split('\n').length; }

export function scanComparisonSafety(fp, raw) {
  if (!fp || !raw || typeof raw !== 'string') return [];
  if (raw.length > 500_000) return [];
  if (!/\.(?:js|jsx|ts|tsx|mjs|cjs|py|go)$/i.test(fp)) return [];

  const findings = [];

  // 1. Timing-unsafe comparison: x === y where x or y is named like a secret
  for (const m of raw.matchAll(/(\w+)\s*===?\s*(\w+)/g)) {
    const left = m[1], right = m[2];
    if (!TIMING_SENSITIVE.test(left) && !TIMING_SENSITIVE.test(right)) continue;
    const line = _line(raw, m.index);
    const lineStart = raw.lastIndexOf('\n', m.index) + 1;
    const lineText = raw.slice(lineStart, raw.indexOf('\n', m.index));
    // Skip if timingSafeEqual or compare_digest is nearby
    const context = raw.slice(Math.max(0, m.index - 200), m.index + 200);
    if (/timingSafeEqual|compare_digest|ConstantTimeCompare|constant_time_compare/i.test(context)) continue;
    // Skip if inside a comment
    if (/^\s*\/\/|^\s*#|^\s*\*/.test(lineText)) continue;
    findings.push({
      id: `timing-unsafe:${fp}:${line}`,
      file: fp, line,
      vuln: 'Timing-Unsafe Comparison — secret/HMAC compared with === instead of timingSafeEqual',
      severity: 'medium',
      family: 'timing-attack',
      cwe: 'CWE-208',
      parser: 'COMPARISON',
      confidence: 0.70,
      description: `String === comparison on "${TIMING_SENSITIVE.exec(left + ' ' + right)?.[1] || 'secret'}" leaks timing information. An attacker can measure response times to guess the value byte-by-byte.`,
      remediation: 'Use crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)) in Node.js, hmac.compare_digest(a, b) in Python, or subtle.ConstantTimeCompare(a, b) in Go.',
      snippet: lineText.trim().slice(0, 100),
    });
  }

  // 2. Loose equality == in auth context
  for (const m of raw.matchAll(/(\w+)\s*==\s*(?!=)(\w+|['"][^'"]+['"])/g)) {
    const left = m[1], right = m[2];
    if (!AUTH_CONTEXT.test(left) && !AUTH_CONTEXT.test(right)) continue;
    const line = _line(raw, m.index);
    const lineStart = raw.lastIndexOf('\n', m.index) + 1;
    const lineText = raw.slice(lineStart, raw.indexOf('\n', m.index));
    if (/^\s*\/\/|^\s*#|^\s*\*/.test(lineText)) continue;
    // Only flag JS/TS (Python and Go use == for equality, not coercion)
    if (!/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(fp)) continue;
    findings.push({
      id: `loose-equality-auth:${fp}:${line}`,
      file: fp, line,
      vuln: 'Loose Equality in Auth Check — == allows type coercion bypass',
      severity: 'high',
      family: 'type-coercion',
      cwe: 'CWE-697',
      parser: 'COMPARISON',
      confidence: 0.65,
      description: `Loose equality (==) on "${AUTH_CONTEXT.exec(left + ' ' + right)?.[1] || 'auth field'}" allows type coercion. "1" == 1 is true; an attacker may bypass checks by sending a different type.`,
      remediation: 'Use strict equality (===) for all authorization checks.',
      snippet: lineText.trim().slice(0, 100),
    });
  }

  return findings;
}
