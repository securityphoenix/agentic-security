// Dart / Flutter security audit.
//
// Coverage:
//   1. SharedPreferences used for token / secret storage
//   2. rawQuery / rawRawUpdate with $-interpolated user input
//   3. Uri.parse without tryParse + allow-list (deep link unsafe)
//   4. WebView with JavaScriptMode.unrestricted and no navigationDelegate
//   5. Cleartext HTTP URL in Dart source
//   6. Hardcoded API key
//   7. http.get / Dio without timeout (resource exhaustion + slow loris)
//   8. print(token) / debugPrint(password) (PII leak)

const _DART_RE = /\.dart$/i;

function _line(raw, idx) {
  return raw.slice(0, idx).split('\n').length;
}

const _CRED_RE = [
  { re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/, label: 'Anthropic API key' },
  { re: /\bsk-[A-Za-z0-9]{32,}\b/, label: 'OpenAI-style key' },
  { re: /\bghp_[A-Za-z0-9]{36}\b/, label: 'GitHub PAT' },
  { re: /\bAKIA[0-9A-Z]{16}\b/, label: 'AWS access key' },
];

export function scanDartFlutter(file, raw) {
  if (!file || !raw || typeof raw !== 'string') return [];
  if (!_DART_RE.test(file)) return [];
  if (raw.length > 200_000) return [];

  const findings = [];

  // 1. SharedPreferences for secrets — the string literal contains a secret-name substring.
  const spSecretRe = /\bSharedPreferences\b[\s\S]{0,500}?\.\s*(?:setString|setInt|setBool)\s*\(\s*['"][\w-]*(?:[tT]oken|[pP]assword|[Aa]pi[Kk]ey|api_key|jwt|bearer|secret|sessionKey)/g;
  for (const m of raw.matchAll(spSecretRe)) {
    findings.push({
      id: `dart:sharedprefs-secret:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'SharedPreferences used to store a secret (token / password / key)',
      severity: 'high',
      family: 'dart-insecure-storage',
      cwe: 'CWE-922',
      confidence: 0.85,
      description: 'SharedPreferences stores values plaintext on Android and in NSUserDefaults-equivalent on iOS — neither is encrypted at rest. Rooted Android devices and iOS backups extract the value trivially.',
      remediation: 'Use flutter_secure_storage (Keychain on iOS, EncryptedSharedPreferences on Android): final storage = FlutterSecureStorage(); await storage.write(key: "token", value: token).',
    });
  }

  // 2. rawQuery / rawUpdate with $-interpolation. Outer quote can be ' or ";
  // inner content may include the opposite quote (for SQL string literals).
  const sqlInjectRe = /\b(?:rawQuery|rawInsert|rawUpdate|rawDelete|execute)\s*\(\s*(?:"[^"]*\$\{?[A-Za-z_]|'[^']*\$\{?[A-Za-z_])/g;
  for (const m of raw.matchAll(sqlInjectRe)) {
    findings.push({
      id: `dart:sql-injection:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'sqflite/drift raw query with interpolated user input — SQL injection',
      severity: 'critical',
      family: 'dart-sql-injection',
      cwe: 'CWE-89',
      confidence: 0.9,
      description: 'String interpolation directly into the SQL string lets the attacker rewrite the query.',
      remediation: 'Use parameterized queries: db.query("users", where: "email = ?", whereArgs: [userInput]).',
    });
  }

  // 3. Uri.parse without tryParse + allow-list (heuristic: Uri.parse followed by direct navigation without scheme/host check)
  for (const m of raw.matchAll(/\bUri\.parse\s*\([^)]+\)(?![\s\S]{0,200}?\.(?:scheme|host)\s*==)/g)) {
    // skip if next 200 chars contain allow-list pattern
    const after = raw.slice(m.index + m[0].length, m.index + m[0].length + 400);
    if (/\b(?:allowedHosts|allowedPaths|allowedSchemes|\.host\s*==\s*['"][a-zA-Z]|\.scheme\s*==\s*['"][a-z])/.test(after)) continue;
    if (/context\.(?:go|push|pushNamed|pushReplacement)|Navigator\.(?:push|of\([^)]*\)\.push)/.test(after)) {
      findings.push({
        id: `dart:uri-parse-deeplink:${file}:${_line(raw, m.index)}`,
        file, line: _line(raw, m.index),
        vuln: 'Uri.parse() output passed to navigator without scheme/host allow-list',
        severity: 'high',
        family: 'dart-deeplink-unsafe',
        cwe: 'CWE-20',
        confidence: 0.65,
        description: 'A deep link is parsed and navigated to without validating scheme or host. Attackers can craft links that route the app to internal-only screens or pivot through a WebView.',
        remediation: 'Use Uri.tryParse(), then check uri.scheme == "https" && allowedHosts.contains(uri.host) && allowedPaths.contains(uri.path) before navigating.',
      });
    }
  }

  // 4. WebView with JavaScriptMode.unrestricted and no NavigationDelegate
  if (/\bWebViewController\b/.test(raw) || /\bWebView\b/.test(raw)) {
    if (/\bJavaScriptMode\.unrestricted\b/.test(raw) && !/\bNavigationDelegate\s*\(/.test(raw)) {
      const m = /\bJavaScriptMode\.unrestricted\b/.exec(raw);
      findings.push({
        id: `dart:webview-js-no-delegate:${file}:${_line(raw, m.index)}`,
        file, line: _line(raw, m.index),
        vuln: 'WebView with JavaScriptMode.unrestricted and no NavigationDelegate',
        severity: 'high',
        family: 'dart-webview-unsafe',
        cwe: 'CWE-829',
        confidence: 0.7,
        description: 'WebView with JS enabled and no NavigationDelegate accepts any URL. Combined with addJavaScriptChannel (or any JS-Dart bridge), this is a direct path to native code from attacker-controlled JS.',
        remediation: 'Assign a NavigationDelegate with onNavigationRequest that returns NavigationDecision.prevent for any URL outside your allow-list.',
      });
    }
  }

  // 5. Cleartext HTTP URL literal
  for (const m of raw.matchAll(/['"]http:\/\/(?!localhost|127\.0\.0\.1)[A-Za-z0-9.-]+/g)) {
    findings.push({
      id: `dart:cleartext-http:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'Cleartext HTTP URL literal in Dart source',
      severity: 'medium',
      family: 'dart-cleartext-http',
      cwe: 'CWE-319',
      confidence: 0.8,
      description: 'A hard-coded http:// URL ships cleartext on the wire.',
      remediation: 'Use https://. Set up network_security_config.xml on Android to block cleartext globally.',
      snippet: m[0].slice(0, 60),
    });
    break;     // one finding per file is enough — common case
  }

  // 6. Hardcoded credentials
  for (const { re, label } of _CRED_RE) {
    const m = re.exec(raw);
    if (!m) continue;
    findings.push({
      id: `dart:hardcoded-${label.toLowerCase().replace(/\s+/g, '-')}:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: `Hardcoded ${label} in Dart source`,
      severity: 'critical',
      family: 'dart-hardcoded-credential',
      cwe: 'CWE-798',
      confidence: 0.95,
      description: 'Flutter apps decompile easily (`flutter_extract` / `blutter`). Hardcoded credentials in source are extracted in seconds.',
      remediation: 'Use String.fromEnvironment("API_KEY") for non-secret config, flutter_secure_storage for runtime secrets fetched from a backend.',
    });
  }

  // 7. http.get / Dio without timeout
  for (const m of raw.matchAll(/\b(?:http\.(?:get|post|put|delete)|Dio\s*\(\s*\))/g)) {
    const after = raw.slice(m.index, m.index + 400);
    if (/\b(?:connectTimeout|receiveTimeout|sendTimeout|timeout)\b/.test(after)) continue;
    findings.push({
      id: `dart:no-http-timeout:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'HTTP client / request without timeout',
      severity: 'low',
      family: 'dart-no-timeout',
      cwe: 'CWE-400',
      confidence: 0.6,
      description: 'No connectTimeout / receiveTimeout set. A slow or unresponsive server will hang the request indefinitely, exhausting connection pool / blocking the UI thread.',
      remediation: 'Set BaseOptions(connectTimeout: Duration(seconds:10), receiveTimeout: Duration(seconds:30)) on Dio. For http: wrap in Future.timeout(...).',
    });
    break;     // one per file
  }

  // 8. print() / debugPrint() of secret values
  const debugLeakRe = /\b(?:print|debugPrint)\s*\([^)]*\b(?:token|password|api[kK]ey|jwt|bearer|secret)\b/g;
  for (const m of raw.matchAll(debugLeakRe)) {
    findings.push({
      id: `dart:debug-print-secret:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'print() / debugPrint() of a variable named token/password/apiKey/jwt',
      severity: 'medium',
      family: 'dart-secret-in-log',
      cwe: 'CWE-532',
      confidence: 0.75,
      description: 'Secrets sent to print/debugPrint end up in logcat (Android) / Console.app (iOS) and any crash-reporting integration. Even in release builds, debugPrint emits.',
      remediation: 'Remove the log statement, or redact the value: debugPrint("token=${token.substring(0, 6)}...").',
    });
  }

  return findings;
}
