// 0.9.0 Feat-14: Container base image EOL detection — maps FROM lines to known-vulnerable distro versions.
//
// Two passes:
//   1. Parse `FROM <image>:<tag>` lines and check the tag against a vendored
//      base-images map (alpine/debian/ubuntu/node/python). Emit a finding for
//      EOL or floating tags.
//   2. Parse `RUN apt-get install` / `apk add` package lists and synthesize
//      lightweight components[] entries that the SCA OSV pipeline can query.
//
// All-local: no Docker registry pulls, no shell-out to docker. Just regex.

import { createRequire } from 'node:module';
const _require = createRequire(import.meta.url);
const _BASE_IMAGES = (() => {
  try {
    const raw = _require('./base-images.json');
    const out = {};
    for (const [k, v] of Object.entries(raw)) {
      if (k.startsWith('_')) continue;
      out[k] = v;
    }
    return out;
  } catch (_) {
    return null;
  }
})();

const _DOCKERFILE_RE = /(?:^|\/)(?:[Dd]ockerfile|[^/]+\.dockerfile)$/i;

// FROM <image>[:<tag>] [AS <stage>]
const _FROM_RE = /^\s*FROM\s+(?:--platform=\S+\s+)?([\w./-]+?)(?::([\w.\-]+))?(?:@sha256:[a-f0-9]{64})?(?:\s+AS\s+\S+)?\s*$/im;

// FROM <image>:<tag> covering all FROM lines in the file
const _ALL_FROM_RE = /^\s*FROM\s+(?:--platform=\S+\s+)?([\w./-]+?)(?::([\w.\-]+))?(?:@sha256:[a-f0-9]{64})?(?:\s+AS\s+\S+)?\s*$/img;

// `apt-get install -y pkg pkg pkg` / `apk add pkg pkg`
const _APT_INSTALL_RE = /\bapt(?:-get)?\s+install\b[^\n]*?(?:--?[\w-]+\s+)*((?:[a-z0-9][\w.+-]*(?:=[\w.+:-]+)?\s*)+)/gi;
const _APK_ADD_RE     = /\bapk\s+(?:--no-cache\s+)?(?:--update\s+)?add\b[^\n]*?(?:--?[\w-]+\s+)*((?:[a-z0-9][\w.+-]*(?:=[\w.+:-]+)?\s*)+)/gi;

function _scoreTag(image, tag) {
  if (!_BASE_IMAGES) return null;
  const m = _BASE_IMAGES[image];
  if (!m) return null;
  // Direct tag match
  if (m[tag]) return { ...m[tag], image, tag };
  // Major-only match: tag '20.04-slim' falls back to '20.04'
  for (const k of Object.keys(m)) {
    if (tag && tag.startsWith(k + '.')) return { ...m[k], image, tag };
    if (tag && tag.startsWith(k + '-')) return { ...m[k], image, tag };
    if (tag === k) return { ...m[k], image, tag };
  }
  // Tag missing entirely (e.g. "FROM alpine") → treat as 'latest'
  if (!tag && m.latest) return { ...m.latest, image, tag: 'latest' };
  return null;
}

export function scanContainer(fp, raw) {
  if (!_DOCKERFILE_RE.test(fp.replace(/\\/g, '/'))) return [];
  if (!raw || raw.length > 200_000) return [];
  const findings = [];
  const lines = raw.split('\n');
  let m;

  // Pass 1: FROM lines
  _ALL_FROM_RE.lastIndex = 0;
  while ((m = _ALL_FROM_RE.exec(raw))) {
    const image = m[1].split('/').pop(); // strip registry / namespace prefixes
    const tag = m[2] || '';
    const line = raw.substring(0, m.index).split('\n').length;
    const score = _scoreTag(image, tag);
    if (!score) continue;
    findings.push({
      id: `container-base:${fp}:${line}:${image}:${tag || 'latest'}`,
      kind: 'container', severity: score.sev,
      vuln: `Container base image: ${image}:${tag || 'latest'} ${score.eol ? '(EOL)' : '(floating tag)'}`,
      cwe: score.eol ? 'CWE-1104' : 'CWE-1357',
      stride: 'Tampering',
      file: fp, line, snippet: (lines[line - 1] || '').trim(),
      fix: score.message,
    });
  }

  // Pass 2: apt/apk packages — surface as components hint for the SCA pipeline.
  // We do NOT query OSV here (the engine's SCA pass owns that). Just collect names.
  const packages = [];
  _APT_INSTALL_RE.lastIndex = 0;
  while ((m = _APT_INSTALL_RE.exec(raw))) {
    for (const tok of m[1].split(/\s+/)) {
      const t = tok.trim();
      if (!t || t.startsWith('-')) continue;
      const [name, ver] = t.split('=', 2);
      if (/^[a-z0-9][\w.+-]*$/.test(name)) packages.push({ ecosystem: 'debian', name, version: ver || '' });
    }
  }
  _APK_ADD_RE.lastIndex = 0;
  while ((m = _APK_ADD_RE.exec(raw))) {
    for (const tok of m[1].split(/\s+/)) {
      const t = tok.trim();
      if (!t || t.startsWith('-')) continue;
      const [name, ver] = t.split('=', 2);
      if (/^[a-z0-9][\w.+-]*$/.test(name)) packages.push({ ecosystem: 'alpine', name, version: ver || '' });
    }
  }
  // Stash packages on the first finding so the engine can consume them downstream
  if (packages.length && findings.length) findings[0]._containerPackages = packages;
  return findings;
}
