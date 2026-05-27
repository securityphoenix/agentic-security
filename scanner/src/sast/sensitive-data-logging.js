// Sensitive data logging detector.
//
// Flags PII-named variables sent to logging sinks without sanitization.
// Covers JS (console/winston/pino/bunyan), Python (logging/print),
// Go (log/fmt.Printf).

const PII_CONTEXT = /\b(email|ssn|password|phone|dob|date_of_birth|credit_card|card_number|social_security|passport|medical_record|ip_address|first_name|last_name|address|zip_code|bank_account)\b/i;

function _line(raw, idx) { return raw.slice(0, idx).split('\n').length; }

const LANG_SINKS = {
  js: {
    ext: /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i,
    sinks: [
      /\bconsole\.(?:log|warn|error|info|debug|trace)\s*\(/g,
      /\blogger\.(?:log|info|warn|error|debug|trace|fatal)\s*\(/g,
      /\b(?:winston|pino|bunyan|log4js)(?:\.\w+)*\.(?:info|warn|error|debug|log)\s*\(/g,
    ],
  },
  py: {
    ext: /\.py$/i,
    sinks: [
      /\blogging\.(?:info|warning|error|debug|critical)\s*\(/g,
      /\blogger\.(?:info|warning|error|debug|critical)\s*\(/g,
      /\bprint\s*\(/g,
    ],
  },
  go: {
    ext: /\.go$/i,
    sinks: [
      /\blog\.(?:Printf|Println|Print|Fatalf|Fatal)\s*\(/g,
      /\bfmt\.(?:Printf|Println|Print|Fprintf)\s*\(/g,
    ],
  },
};

export function scanSensitiveDataLogging(fp, raw) {
  if (!fp || !raw || typeof raw !== 'string') return [];
  if (raw.length > 500_000) return [];

  const findings = [];
  let lang = null;
  for (const v of Object.values(LANG_SINKS)) {
    if (v.ext.test(fp)) { lang = v; break; }
  }
  if (!lang) return [];

  for (const sinkRe of lang.sinks) {
    sinkRe.lastIndex = 0;
    for (const m of raw.matchAll(sinkRe)) {
      const lineNum = _line(raw, m.index);
      const lineEnd = raw.indexOf('\n', m.index);
      const lineText = raw.slice(m.index, lineEnd > 0 ? lineEnd : m.index + 200);
      if (!PII_CONTEXT.test(lineText)) continue;
      // Skip if the line contains redaction/masking
      if (/\b(?:redact|mask|sanitize|censor|scrub|\*{3,}|\.{3}|slice\s*\(\s*0\s*,\s*\d\s*\))\b/i.test(lineText)) continue;
      findings.push({
        id: `sensitive-log:${fp}:${lineNum}`,
        file: fp, line: lineNum,
        vuln: 'Sensitive Data Logged — PII-named variable sent to logger without sanitization',
        severity: 'medium',
        family: 'sensitive-data-logging',
        cwe: 'CWE-532',
        parser: 'PII-LOG',
        confidence: 0.70,
        description: 'A variable with a PII-related name (email, password, ssn, etc.) is logged without redaction. Log aggregators, crash reporters, and stdout can expose this data.',
        remediation: 'Redact sensitive fields before logging: logger.info("Login", { email: email.slice(0, 3) + "***" }). Never log passwords, SSNs, or credit card numbers.',
        snippet: lineText.trim().slice(0, 100),
      });
    }
  }
  return findings;
}
