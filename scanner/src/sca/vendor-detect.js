// Vendored / copied library detection via version-string fingerprinting.
//
// Detects library code copied into src/ that bypasses SCA. Uses version
// string patterns (_.VERSION, jQuery.fn.jquery, etc.) and characteristic
// function signatures to identify vendored libraries.

const VERSION_FINGERPRINTS = [
  { pkg: 'lodash', ecosystem: 'npm', patterns: [
    { re: /\b(?:lodash|_)\.VERSION\s*=\s*['"](\d+\.\d+\.\d+)['"]/, versionGroup: 1 },
    { re: /\b__lodash_hash_undefined__\b/, version: null },
  ]},
  { pkg: 'jquery', ecosystem: 'npm', patterns: [
    { re: /jQuery\.fn\.jquery\s*=\s*['"](\d+\.\d+\.\d+)['"]/, versionGroup: 1 },
    { re: /\bjQuery\.fn\.init\b/, version: null },
  ]},
  { pkg: 'underscore', ecosystem: 'npm', patterns: [
    { re: /\b_\.VERSION\s*=\s*['"](\d+\.\d+\.\d+)['"]/, versionGroup: 1 },
  ]},
  { pkg: 'moment', ecosystem: 'npm', patterns: [
    { re: /\bmoment\.version\s*=\s*['"](\d+\.\d+\.\d+)['"]/, versionGroup: 1 },
    { re: /\bmoment\.(?:utc|parseZone|duration|locale)\b/, version: null },
  ]},
  { pkg: 'handlebars', ecosystem: 'npm', patterns: [
    { re: /\bHandlebars\.VERSION\s*=\s*['"](\d+\.\d+\.\d+)['"]/, versionGroup: 1 },
  ]},
  { pkg: 'backbone', ecosystem: 'npm', patterns: [
    { re: /\bBackbone\.VERSION\s*=\s*['"](\d+\.\d+\.\d+)['"]/, versionGroup: 1 },
  ]},
  { pkg: 'angular', ecosystem: 'npm', patterns: [
    { re: /\bangular\.version\s*=\s*\{[^}]*full\s*:\s*['"](\d+\.\d+\.\d+)['"]/, versionGroup: 1 },
  ]},
  { pkg: 'vue', ecosystem: 'npm', patterns: [
    { re: /\bVue\.version\s*=\s*['"](\d+\.\d+\.\d+)['"]/, versionGroup: 1 },
  ]},
  { pkg: 'react', ecosystem: 'npm', patterns: [
    { re: /\bReactVersion\s*=\s*['"](\d+\.\d+\.\d+)['"]/, versionGroup: 1 },
  ]},
  { pkg: 'dompurify', ecosystem: 'npm', patterns: [
    { re: /\bDOMPurify\.version\s*=\s*['"](\d+\.\d+\.\d+)['"]/, versionGroup: 1 },
  ]},
  { pkg: 'marked', ecosystem: 'npm', patterns: [
    { re: /\bmarked\.(?:defaults|setOptions|use|parse)\b[\s\S]{0,200}version\s*[:=]\s*['"](\d+\.\d+\.\d+)['"]/, versionGroup: 1 },
  ]},
  { pkg: 'axios', ecosystem: 'npm', patterns: [
    { re: /\baxios\.VERSION\s*=\s*['"](\d+\.\d+\.\d+)['"]/, versionGroup: 1 },
  ]},
  { pkg: 'socket.io-client', ecosystem: 'npm', patterns: [
    { re: /\bio\.protocol\s*=\s*(\d+)/, version: null },
  ]},
  { pkg: 'highlight.js', ecosystem: 'npm', patterns: [
    { re: /\bhljs\.versionString\s*=\s*['"](\d+\.\d+\.\d+)['"]/, versionGroup: 1 },
  ]},
  { pkg: 'chart.js', ecosystem: 'npm', patterns: [
    { re: /\bChart\.version\s*=\s*['"](\d+\.\d+\.\d+)['"]/, versionGroup: 1 },
  ]},
];

const SKIP_DIRS = /(?:^|[/\\])(?:node_modules|vendor|dist|build|\.next|__pycache__|\.git)[/\\]/;

export function detectVendoredLibraries(fileContents) {
  if (!fileContents || typeof fileContents !== 'object') return [];
  const detected = [];
  const seen = new Set();

  for (const [fp, content] of Object.entries(fileContents)) {
    if (!content || typeof content !== 'string') continue;
    if (SKIP_DIRS.test(fp)) continue;
    if (content.length < 500) continue;

    for (const lib of VERSION_FINGERPRINTS) {
      for (const pat of lib.patterns) {
        const m = content.match(pat.re);
        if (!m) continue;
        const version = pat.versionGroup ? m[pat.versionGroup] : null;
        const key = `${lib.pkg}:${fp}`;
        if (seen.has(key)) continue;
        seen.add(key);
        detected.push({
          name: lib.pkg,
          version: version || 'unknown',
          ecosystem: lib.ecosystem,
          file: fp,
          scope: 'vendored',
          isVendored: true,
        });
        break;
      }
    }
  }
  return detected;
}
