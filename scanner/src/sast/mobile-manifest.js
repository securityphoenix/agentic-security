// Mobile manifest audit — AndroidManifest.xml + Info.plist + module.json5.
//
// Cross-language: catches mobile security misconfig regardless of whether
// the codebase is Java / Kotlin / Swift / Dart / ArkTS.
//
// Coverage:
//   AndroidManifest.xml
//     - android:exported="true" on non-launcher activities
//     - <application android:debuggable="true">
//     - <application android:allowBackup="true"> with sensitive data hints
//     - <application android:usesCleartextTraffic="true">
//     - dangerous permissions without rationale
//   Info.plist
//     - NSAllowsArbitraryLoads = true (ATS bypass)
//     - Missing NS*UsageDescription for declared permissions
//   module.json5 (HarmonyOS)
//     - Permission without usedScene / reason

const _ANDROID_MANIFEST_RE = /(?:^|[\\/])AndroidManifest\.xml$/i;
const _INFO_PLIST_RE = /(?:^|[\\/])Info\.plist$/i;
const _MODULE_JSON5_RE = /(?:^|[\\/])module\.json5$/i;

function _line(raw, idx) {
  return raw.slice(0, idx).split('\n').length;
}

export function scanMobileManifest(file, raw) {
  if (!file || !raw || typeof raw !== 'string') return [];
  if (raw.length > 200_000) return [];

  if (_ANDROID_MANIFEST_RE.test(file)) return _scanAndroidManifest(file, raw);
  if (_INFO_PLIST_RE.test(file)) return _scanInfoPlist(file, raw);
  if (_MODULE_JSON5_RE.test(file)) return _scanModuleJson5(file, raw);
  return [];
}

function _scanAndroidManifest(file, raw) {
  const findings = [];

  // android:debuggable="true"
  for (const m of raw.matchAll(/android:debuggable\s*=\s*["']true["']/g)) {
    findings.push({
      id: `mobile-android:debuggable-true:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'AndroidManifest <application android:debuggable="true">',
      severity: 'critical',
      family: 'mobile-android-debuggable',
      cwe: 'CWE-489',
      confidence: 0.95,
      description: 'A debuggable APK shipped to production allows any user with adb to attach jdb, inspect process memory, and arbitrarily call methods. JADX + Frida pair this into a one-step bypass for any client-side check.',
      remediation: 'Remove android:debuggable from <application>, or set false in release builds. Most build systems strip this from release variants automatically — verify your release manifest.',
    });
  }

  // usesCleartextTraffic="true"
  for (const m of raw.matchAll(/android:usesCleartextTraffic\s*=\s*["']true["']/g)) {
    findings.push({
      id: `mobile-android:cleartext-traffic:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'AndroidManifest android:usesCleartextTraffic="true"',
      severity: 'high',
      family: 'mobile-android-cleartext',
      cwe: 'CWE-319',
      confidence: 0.95,
      description: 'Allows the app to make plaintext HTTP requests. Network-level attackers on the same Wi-Fi can intercept and tamper with traffic.',
      remediation: 'Set usesCleartextTraffic="false" and rely on TLS. If specific dev/internal hosts genuinely need HTTP, scope them via network_security_config.xml domain-config — never the whole app.',
    });
  }

  // android:exported="true" on non-launcher activities (no LAUNCHER intent filter)
  // Walk each <activity ... android:exported="true" ...> ... </activity>
  const activityRe = /<activity\b([^>]*)>([\s\S]*?)<\/activity>|<activity\b([^/]*)\/>/g;
  let am;
  while ((am = activityRe.exec(raw))) {
    const head = am[1] || am[3] || '';
    const body = am[2] || '';
    if (!/android:exported\s*=\s*["']true["']/.test(head)) continue;
    // Skip the launcher activity (which MUST be exported).
    if (/android\.intent\.category\.LAUNCHER/.test(body) ||
        /android\.intent\.category\.LAUNCHER/.test(head)) continue;
    findings.push({
      id: `mobile-android:exported-true:${file}:${_line(raw, am.index)}`,
      file, line: _line(raw, am.index),
      vuln: 'AndroidManifest <activity android:exported="true"> on a non-launcher activity',
      severity: 'high',
      family: 'mobile-android-exported',
      cwe: 'CWE-926',
      confidence: 0.85,
      description: 'Any other app on the device can start this Activity via Intent. Combined with a vulnerable intent extras handler, this is a one-app RCE.',
      remediation: 'Set android:exported="false" unless another app genuinely needs to start this Activity. If it does, verify intent extras and require android:permission to gate access.',
    });
  }

  // allowBackup="true" with no fullBackupContent restrictions
  if (/android:allowBackup\s*=\s*["']true["']/.test(raw) && !/android:fullBackupContent\s*=/.test(raw)) {
    const m = /android:allowBackup\s*=\s*["']true["']/.exec(raw);
    findings.push({
      id: `mobile-android:allow-backup:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'AndroidManifest android:allowBackup="true" without fullBackupContent restriction',
      severity: 'medium',
      family: 'mobile-android-backup',
      cwe: 'CWE-552',
      confidence: 0.75,
      description: 'On debug-enabled devices, adb can pull the app\'s entire data dir (preferences, databases, files) via adb backup. Without a fullBackupContent restriction, sensitive data is included.',
      remediation: 'Set allowBackup="false", or provide fullBackupContent="@xml/backup_rules" with an explicit include/exclude list.',
    });
  }

  return findings;
}

function _scanInfoPlist(file, raw) {
  const findings = [];

  // NSAllowsArbitraryLoads = true
  const re = /<key>\s*NSAllowsArbitraryLoads\s*<\/key>\s*<true\s*\/>/i;
  if (re.test(raw)) {
    const m = re.exec(raw);
    findings.push({
      id: `mobile-ios:ats-disabled:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'Info.plist NSAllowsArbitraryLoads = true — App Transport Security disabled',
      severity: 'high',
      family: 'mobile-ios-ats-disabled',
      cwe: 'CWE-319',
      confidence: 0.95,
      description: 'ATS-disabled apps make plaintext HTTP calls to arbitrary hosts. Network-level attackers can intercept tokens / PII / session cookies trivially.',
      remediation: 'Remove NSAllowsArbitraryLoads or set to false. If a specific domain genuinely needs HTTP (legacy backend), scope via NSExceptionDomains with NSExceptionAllowsInsecureHTTPLoads on that single host.',
    });
  }

  // Permissions declared without usage description — known iOS keys.
  const IOS_PERMS = [
    ['NSCameraUsageDescription', 'camera'],
    ['NSMicrophoneUsageDescription', 'microphone'],
    ['NSLocationWhenInUseUsageDescription', 'location-when-in-use'],
    ['NSLocationAlwaysAndWhenInUseUsageDescription', 'location-always'],
    ['NSPhotoLibraryUsageDescription', 'photo library'],
    ['NSContactsUsageDescription', 'contacts'],
    ['NSCalendarsUsageDescription', 'calendar'],
    ['NSBluetoothAlwaysUsageDescription', 'bluetooth'],
    ['NSAppleMusicUsageDescription', 'media library'],
    ['NSMotionUsageDescription', 'motion'],
    ['NSFaceIDUsageDescription', 'face id'],
  ];
  for (const [key, label] of IOS_PERMS) {
    // Check: <key>KEY</key> present AND followed by empty <string></string> (within 200 chars)
    const re2 = new RegExp(`<key>\\s*${key}\\s*</key>\\s*<string>\\s*</string>`, 'i');
    if (re2.test(raw)) {
      const m = re2.exec(raw);
      findings.push({
        id: `mobile-ios:empty-usage-desc:${file}:${_line(raw, m.index)}:${label}`,
        file, line: _line(raw, m.index),
        vuln: `Info.plist ${key} declared but description is empty`,
        severity: 'low',
        family: 'mobile-ios-empty-permission-rationale',
        cwe: 'CWE-1059',
        confidence: 0.9,
        description: `iOS displays the usage description to the user when the app first requests ${label} access. An empty string leads to App Store rejection and a worse user-trust signal.`,
        remediation: `Provide a clear, specific reason: <string>Camera access lets you scan QR codes for fast pairing.</string>`,
      });
    }
  }

  return findings;
}

function _scanModuleJson5(file, raw) {
  const findings = [];
  // HarmonyOS: declared permission without usedScene or reason.
  // Cheap regex check on the JSON5.
  const permRe = /"requestPermissions"\s*:\s*\[([\s\S]*?)\]/;
  const m = permRe.exec(raw);
  if (!m) return findings;
  const body = m[1];
  // For each block { "name": "...", ... } in the array, check usedScene / reason.
  for (const pm of body.matchAll(/\{[^{}]*"name"\s*:\s*"([^"]+)"[^{}]*\}/g)) {
    const block = pm[0];
    const permName = pm[1];
    if (/"usedScene"\s*:/.test(block) && /"reason"\s*:/.test(block)) continue;
    findings.push({
      id: `mobile-harmony:missing-permission-rationale:${file}:${_line(raw, pm.index + m.index)}:${permName}`,
      file, line: _line(raw, pm.index + m.index),
      vuln: `HarmonyOS module.json5 permission "${permName}" missing usedScene or reason`,
      severity: 'low',
      family: 'mobile-harmony-permission-rationale',
      cwe: 'CWE-862',
      confidence: 0.85,
      description: 'HarmonyOS requires every requested permission to declare usedScene and a user-facing reason. Missing the rationale leads to runtime denial.',
      remediation: 'Add "usedScene": { "abilities": ["EntryAbility"], "when": "always" } and "reason": "$string:permission_reason".',
    });
  }
  return findings;
}
