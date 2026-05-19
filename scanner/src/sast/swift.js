// Swift / iOS application security audit.
//
// Covers the canonical Swift/iOS bugs from the rules/swift/security.md
// guidance:
//   1. UserDefaults used for secret storage (should be Keychain)
//   2. App Transport Security (ATS) disabled — looking for the code-side
//      `URLSession` patterns; the Info.plist bypass is caught by
//      mobile-manifest.js.
//   3. Force-unwrap on URL(string:) / URL.init(string:) → crash + bypass
//   4. WKWebView with JavaScript enabled and no navigation delegate
//   5. Deep-link handling without scheme / host / path allow-list
//   6. Cleartext HTTP in URLRequest URL string
//   7. Hardcoded API key / token literal

const _SWIFT_RE = /\.swift$/i;

function _line(raw, idx) {
  return raw.slice(0, idx).split('\n').length;
}

const _CRED_RE = [
  { re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/, label: 'Anthropic API key' },
  { re: /\bsk-[A-Za-z0-9]{32,}\b/, label: 'OpenAI-style key' },
  { re: /\bghp_[A-Za-z0-9]{36}\b/, label: 'GitHub PAT' },
  { re: /\bAKIA[0-9A-Z]{16}\b/, label: 'AWS access key' },
  { re: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/, label: 'Slack token' },
];

export function scanSwift(file, raw) {
  if (!file || !raw || typeof raw !== 'string') return [];
  if (!_SWIFT_RE.test(file)) return [];
  if (raw.length > 200_000) return [];

  const findings = [];

  // 1. UserDefaults for secrets — the variable name on the LHS is the clue.
  const udSecretRe = /\bUserDefaults(?:\.standard)?\.(?:set|setValue|setObject)\s*\([^)]*?\b(?:[tT]oken|[pP]assword|[aA]pi[kK]ey|apiKey|api_key|jwt|bearer|secret|credential|session[kK]ey)\b/g;
  for (const m of raw.matchAll(udSecretRe)) {
    findings.push({
      id: `swift:userdefaults-secret:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'UserDefaults used to store a secret (token / password / key)',
      severity: 'high',
      family: 'swift-insecure-storage',
      cwe: 'CWE-922',
      confidence: 0.8,
      description: 'UserDefaults stores values in plist files in the app sandbox; they\'re trivially extracted by anyone with the device or a backup. Keychain Services is the correct vault on iOS — encrypted-at-rest with hardware-backed access control on modern devices.',
      remediation: 'Use Keychain Services (Security.framework) — e.g., KeychainAccess library or the SecItemAdd/SecItemCopyMatching APIs directly. Set kSecAttrAccessible to kSecAttrAccessibleWhenUnlockedThisDeviceOnly for tokens.',
      snippet: m[0].slice(0, 80),
    });
  }

  // 2. URL force-unwrap — URL(string: ...)! pattern
  for (const m of raw.matchAll(/\bURL\s*\(\s*string\s*:\s*[^)]+\)\s*!/g)) {
    findings.push({
      id: `swift:url-force-unwrap:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'URL force-unwrap (URL(string:)! ) — crash or attacker-controlled URL',
      severity: 'medium',
      family: 'swift-force-unwrap',
      cwe: 'CWE-755',
      confidence: 0.75,
      description: 'Force-unwrapping URL(string:) crashes the app on a malformed URL. If the input comes from a deep link, the attacker can either crash the app or — paired with downstream logic — supply a URL the developer assumed would be validated.',
      remediation: 'Use guard let url = URL(string: input), url.scheme == "https" else { return } with explicit scheme/host validation.',
      snippet: m[0],
    });
  }

  // 3. WKWebView with JS enabled, no navigationDelegate visible
  if (/\bWKWebView\b/.test(raw) || /\bWKWebViewConfiguration\b/.test(raw)) {
    // Detect explicit `configuration.preferences.javaScriptEnabled = true` or
    // `defaultWebpagePreferences.allowsContentJavaScript = true` without
    // a corresponding navigationDelegate assignment in the file.
    const jsEnabledRe = /\b(?:javaScriptEnabled\s*=\s*true|allowsContentJavaScript\s*=\s*true)\b/;
    const hasNavDelegate = /\b(?:webView\.navigationDelegate\s*=|navigationDelegate\s*:\s*)/.test(raw);
    if (jsEnabledRe.test(raw) && !hasNavDelegate) {
      const m = jsEnabledRe.exec(raw);
      findings.push({
        id: `swift:webview-js-no-delegate:${file}:${_line(raw, m.index)}`,
        file, line: _line(raw, m.index),
        vuln: 'WKWebView with JavaScript enabled and no navigationDelegate to validate URLs',
        severity: 'high',
        family: 'swift-webview-unsafe',
        cwe: 'CWE-829',
        confidence: 0.7,
        description: 'WKWebView with JS enabled and no navigationDelegate accepts navigation to any URL. Deep-link or message-passing attacks can pivot the WebView to attacker pages and execute JS that bridges back to native via WKScriptMessageHandler.',
        remediation: 'Assign a navigationDelegate that vets webView(_:decidePolicyFor:decisionHandler:); allow-list the host and reject everything else with .cancel.',
      });
    }
  }

  // 4. Deep-link / universal-link handler without allow-list
  // Look for application(_:open:options:) or scene(_:openURLContexts:) that doesn't validate
  for (const m of raw.matchAll(/func\s+(?:application\s*\([^)]*open[^)]*\)|scene\s*\([^)]*openURLContexts[^)]*\))[^{]*\{([\s\S]{0,800}?)(?=\n\s*func\s|\}\n)/g)) {
    const body = m[1];
    if (!body) continue;
    // Skip if body validates host/scheme/path against allow-list constants.
    if (/\b(?:host\s*==|scheme\s*==|allowedHosts|allowedSchemes|allowedPaths)\b/.test(body)) continue;
    findings.push({
      id: `swift:deeplink-no-validate:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'Deep-link / universal-link handler does not validate URL scheme / host / path',
      severity: 'high',
      family: 'swift-deeplink-unsafe',
      cwe: 'CWE-20',
      confidence: 0.65,
      description: 'An openURL handler accepts the incoming URL without checking scheme / host / path against an allow-list. Attackers can route the app to internal screens, trigger sensitive flows, or chain into XSS via WebView.',
      remediation: 'Add guard let host = url.host, allowedHosts.contains(host), let path = ..., allowedPaths.contains(path) else { return false } at the top of the handler.',
    });
  }

  // 5. Cleartext HTTP URL literal
  for (const m of raw.matchAll(/\bURL\s*\(\s*string\s*:\s*['"]http:\/\/(?!localhost|127\.0\.0\.1)[^'"]+['"]/g)) {
    findings.push({
      id: `swift:cleartext-http:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'Cleartext HTTP URL literal in Swift source',
      severity: 'medium',
      family: 'swift-cleartext-http',
      cwe: 'CWE-319',
      confidence: 0.85,
      description: 'A hard-coded http:// URL ships cleartext on the wire. Even if ATS is enabled, this is an explicit bypass.',
      remediation: 'Use https://. If the endpoint genuinely lacks TLS, set up your own TLS-terminating proxy.',
      snippet: m[0].slice(0, 80),
    });
  }

  // 6. Hardcoded API keys
  for (const { re, label } of _CRED_RE) {
    const m = re.exec(raw);
    if (!m) continue;
    findings.push({
      id: `swift:hardcoded-${label.toLowerCase().replace(/\s+/g, '-')}:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: `Hardcoded ${label} in Swift source`,
      severity: 'critical',
      family: 'swift-hardcoded-credential',
      cwe: 'CWE-798',
      confidence: 0.95,
      description: 'Decompiling a Swift binary is trivial — `strings`, `class-dump`, Ghidra all extract literal credentials in seconds. Hardcoded keys in mobile apps are routinely scraped at scale.',
      remediation: 'Read from ProcessInfo.processInfo.environment["API_KEY"] (with .xcconfig for build-time config). For runtime secrets, fetch from a backend service authenticated by the user\'s session.',
      snippet: m[0].slice(0, 8) + '...' + m[0].slice(-4),
    });
  }

  // 7. NSAllowsArbitraryLoads = true in code (Info.plist is handled in mobile-manifest)
  for (const m of raw.matchAll(/NSAllowsArbitraryLoads\s*[:=]\s*true\b/g)) {
    findings.push({
      id: `swift:ats-bypass-code:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'NSAllowsArbitraryLoads = true — App Transport Security bypassed in code',
      severity: 'high',
      family: 'swift-ats-disabled',
      cwe: 'CWE-319',
      confidence: 0.95,
      description: 'NSAllowsArbitraryLoads=true disables ATS, allowing the app to make plaintext HTTP calls to arbitrary hosts.',
      remediation: 'Remove the bypass. If a specific domain needs HTTP, scope it via NSExceptionDomains in Info.plist; never use NSAllowsArbitraryLoads globally.',
    });
  }

  return findings;
}
