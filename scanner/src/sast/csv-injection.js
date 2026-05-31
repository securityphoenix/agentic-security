// CSV / formula injection (CWE-1236) — additive detector.
//
// When user-controlled text is written into a CSV/spreadsheet cell that begins
// with `=`, `+`, `-`, `@`, or a tab/CR, a spreadsheet app (Excel, Sheets,
// LibreOffice) interprets it as a FORMULA on open — enabling data exfiltration
// (`=IMPORTXML(...)`), command execution via DDE, or credential phishing. The
// fix is to neutralize the leading character (prefix with `'`), not HTML/SQL
// escaping.
//
// High precision by construction: we only fire when (a) a CSV/spreadsheet
// WRITE API is on the line, (b) a user-derived value is referenced on the same
// statement, and (c) no formula-neutralization helper is present nearby.

import { blankComments } from './_comment-strip.js';

const JS_RE = /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i;
const PY_RE = /\.py$/i;

// CSV / spreadsheet write APIs worth flagging (JS + Python).
const CSV_WRITE = [
  /\bwriteRecords?\s*\(/,                 // csv-writer createObjectCsvWriter().writeRecords
  /\bcsv\s*\.\s*stringify\s*\(/,          // csv-stringify
  /\bstringify\s*\(\s*[^)]*\bcolumns\b/,  // csv-stringify with columns
  /\bcsvStringify\s*\(/,
  /\b(?:fastcsv|fast_csv|csvFormat)\s*\(/,
  /\bXLSX\s*\.\s*utils\s*\.\s*(?:json_to_sheet|aoa_to_sheet|sheet_add)/,
  /\bwriterow\s*\(|\bwriterows\s*\(|\bwriteheader\s*\(/,   // python csv module
  /\bcsv\s*\.\s*writer\s*\(/,
  /\bDictWriter\s*\(/,
];

// User-derived value hints on the same statement.
const TAINT_HINT =
  /\b(?:req\.|request\.|params\.|query\.|body\.|_GET|_POST|_REQUEST|getParameter|\.get\(|user\.|profile\.|\.fields\b|row\.|record\.)/;

// Formula-neutralization already applied → suppress.
const NEUTRALIZED =
  /escapeFormula|sanitizeCsv|sanitiseCsv|csvEscape|formulaEscape|stripFormula|['"`]\s*'\s*['"`]\s*\+|startsWith\(\s*['"`][=+\-@]|replace\(\s*\/\^\[=/;

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

export function scanCsvInjection(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  const isJs = JS_RE.test(fp), isPy = PY_RE.test(fp);
  if (!isJs && !isPy) return [];
  // Cheap pre-filter.
  if (!/csv|writeRecords|XLSX|writerow|DictWriter|stringify/i.test(raw)) return [];

  const code = blankComments(raw, isPy ? 'py' : undefined);
  const lines = code.split('\n');
  const findings = [];
  const seen = new Set();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!CSV_WRITE.some(re => re.test(line))) continue;
    if (!TAINT_HINT.test(line)) continue;
    // Look at the line plus a small window for an explicit neutralizer.
    const lo = Math.max(0, i - 4);
    const near = lines.slice(lo, i + 2).join('\n');
    if (NEUTRALIZED.test(near)) continue;
    if (seen.has(i + 1)) continue;
    seen.add(i + 1);
    findings.push({
      id: `csv-injection:${fp}:${i + 1}`,
      severity: 'medium',
      file: fp,
      line: i + 1,
      vuln: 'CSV / formula injection (untrusted data written to a spreadsheet cell)',
      cwe: 'CWE-1236',
      family: 'injection',
      parser: 'SAST',
      confidence: 0.55,
      description:
        'User-controlled text is written to a CSV/spreadsheet without neutralizing leading formula ' +
        'characters (= + - @ tab). A spreadsheet app will execute it as a formula on open, enabling ' +
        'data exfiltration (e.g. =IMPORTXML), DDE command execution, or phishing.',
      remediation:
        "Prefix any cell value that starts with = + - @ or a tab/CR with a single quote (or strip it), " +
        'using a dedicated CSV-escaping helper. HTML/SQL escaping does not address this.',
    });
  }
  return findings;
}
