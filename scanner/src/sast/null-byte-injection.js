// Null-byte and path normalization injection detector.
//
// Detects patterns where file extension checks can be bypassed via
// null-byte truncation (%00, \0) or missing path normalization before
// filesystem operations.

function _line(raw, idx) { return raw.slice(0, idx).split('\n').length; }

const EXT_CHECK_RE = /\.(?:endsWith|match|test|includes)\s*\(\s*['"]\.(?:jpg|jpeg|png|gif|pdf|doc|docx|csv|txt|zip|svg|webp|mp4)/gi;
const SPLITEXT_RE = /(?:path\.extname|os\.path\.splitext|filepath\.Ext|pathinfo)\s*\(/g;

const FS_SINK_RE = /(?:fs\.readFile|fs\.readFileSync|fs\.createReadStream|fs\.writeFile|fs\.writeFileSync|open\s*\(|os\.open|sendFile|send_file|send_from_directory|filepath\.Join|os\.path\.join|path\.join)\s*\(/g;

const NORMALIZATION_RE = /(?:path\.normalize|path\.resolve|os\.path\.abspath|os\.path\.realpath|filepath\.Clean|filepath\.Abs|realpath|basename)\s*\(/;
const NULL_STRIP_RE = /(?:replace\s*\(\s*\/\\0\/|replace\s*\(\s*['"]\\0['"]|\.replace\s*\(\s*\/\\x00\/|\.replace\s*\(\s*['"]%00['"])/;

export function scanNullByteInjection(fp, raw) {
  if (!fp || !raw || typeof raw !== 'string') return [];
  if (raw.length > 500_000) return [];
  if (!/\.(?:js|jsx|ts|tsx|mjs|cjs|py|go|rb|php|phtml)$/i.test(fp)) return [];

  const findings = [];
  const seen = new Set();

  // Pattern: extension check without null-byte stripping before FS operation
  for (const extMatch of raw.matchAll(EXT_CHECK_RE)) {
    const checkLine = _line(raw, extMatch.index);
    // Look ahead for FS operation within 15 lines
    const after = raw.slice(extMatch.index, extMatch.index + 1000);
    if (!FS_SINK_RE.test(after)) continue;
    // Check if normalization or null-byte stripping exists between check and sink
    const between = after.slice(0, after.search(FS_SINK_RE));
    if (NORMALIZATION_RE.test(between) || NULL_STRIP_RE.test(between)) continue;
    const id = `null-byte:${fp}:${checkLine}`;
    if (seen.has(id)) continue;
    seen.add(id);
    findings.push({
      id,
      file: fp, line: checkLine,
      vuln: 'Null-Byte Injection Risk — extension check without path normalization before FS operation',
      severity: 'medium',
      family: 'path-normalization',
      cwe: 'CWE-158',
      parser: 'NULL-BYTE',
      confidence: 0.60,
      description: 'A file extension check is performed, then the path is passed to a filesystem operation without normalization or null-byte stripping. An attacker can bypass the extension check with a null byte: "malicious.php%00.jpg" passes the .jpg check but the filesystem may truncate at the null byte.',
      remediation: 'Always normalize paths before extension checks: path.resolve(uploadsDir, path.basename(filename)). Strip null bytes: filename.replace(/\\0/g, ""). Validate the resolved path is within the expected directory.',
    });
  }

  // Pattern: splitext/extname without null-byte stripping
  for (const splitMatch of raw.matchAll(SPLITEXT_RE)) {
    const line = _line(raw, splitMatch.index);
    const context = raw.slice(Math.max(0, splitMatch.index - 200), splitMatch.index + 200);
    if (NULL_STRIP_RE.test(context) || NORMALIZATION_RE.test(context)) continue;
    // Only fire if user input is nearby
    if (!/(?:req\.|request\.|params|query|body|upload|file|filename|user_input|\$_FILES|\$_GET)/i.test(context)) continue;
    const id = `path-norm:${fp}:${line}`;
    if (seen.has(id)) continue;
    seen.add(id);
    findings.push({
      id,
      file: fp, line,
      vuln: 'Path Normalization Gap — extension extraction without null-byte/traversal sanitization',
      severity: 'medium',
      family: 'path-normalization',
      cwe: 'CWE-176',
      parser: 'NULL-BYTE',
      confidence: 0.55,
      description: 'Path extension is extracted from user-supplied input without prior normalization. Unicode normalization attacks or null-byte truncation can bypass the extension check.',
      remediation: 'Normalize the path first: const safeName = path.basename(userInput).replace(/\\0/g, ""); then check the extension.',
    });
  }

  return findings;
}
