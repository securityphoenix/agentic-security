// Shared version source — read from scanner/package.json at module load.
//
// Premortems 3R1.3 / 3R2.1: previously CURRENT_RULESET_VERSION and
// SARIF tool.driver.version were independently hardcoded constants that
// diverged from the actual scanner version on every release. This module
// reads the truth from package.json so the version is single-sourced.
//
// The bundled scanner is built via ncc into dist/agentic-security.mjs; ncc
// inlines the package.json import at build time, so this module returns the
// frozen version that was bundled with the build.

import { createRequire } from 'node:module';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

// Premortem 4R-7: silently falling back to 'unknown' meant downstream
// consumers (CI gate, telemetry, ruleset-version stamp) couldn't tell whether
// they were looking at a real version or a packaging failure. We now read
// the version eagerly and surface a clear stderr error when package.json
// isn't readable, instead of poisoning every report with 'unknown'. Tests can
// opt out of the eager assertion with AGENTIC_SECURITY_VERSION_UNCHECKED=1.
//
// Bundled mode (P1.3 follow-up): under ncc, `import.meta.url` resolves to
// `dist/agentic-security.mjs`, so `../../package.json` (relative to src/posture/)
// no longer maps to scanner/package.json. We probe a small set of likely
// paths so the bundle and the source tree both work.
function _readVersion() {
  const candidates = [];
  // 1. require('../../package.json') works in the source tree.
  candidates.push(() => {
    const require = createRequire(import.meta.url);
    return require('../../package.json');
  });
  // 2. Walk upward from the current file looking for any package.json that
  //    carries `@clear-capabilities/agentic-security-scanner`. Survives ncc.
  candidates.push(() => {
    let dir;
    try { dir = path.dirname(fileURLToPath(import.meta.url)); }
    catch { return null; }
    for (let i = 0; i < 6; i++) {
      const fp = path.join(dir, 'package.json');
      if (fs.existsSync(fp)) {
        const pkg = JSON.parse(fs.readFileSync(fp, 'utf8'));
        if (pkg && pkg.name && pkg.name.endsWith('agentic-security-scanner')) return pkg;
      }
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }
    return null;
  });
  for (const fn of candidates) {
    try {
      const pkg = fn();
      if (pkg && typeof pkg.version === 'string' && pkg.version) return pkg.version;
    } catch { /* try next */ }
  }
  throw new Error('scanner/package.json not found in any expected location');
}

let _version;
try {
  _version = _readVersion();
} catch (e) {
  _version = 'unknown';
  if (process.env.AGENTIC_SECURITY_VERSION_UNCHECKED !== '1') {
    process.stderr.write(
      `agentic-security: WARNING — could not resolve scanner version (${e.message}). ` +
      `Reports will carry version='unknown'. Set AGENTIC_SECURITY_VERSION_UNCHECKED=1 to silence.\n`
    );
  }
}

export const SCANNER_VERSION = _version;
