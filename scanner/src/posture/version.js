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

// Premortem 4R-7: silently falling back to 'unknown' meant downstream
// consumers (CI gate, telemetry, ruleset-version stamp) couldn't tell whether
// they were looking at a real version or a packaging failure. We now read
// the version eagerly and surface a clear stderr error when package.json
// isn't readable, instead of poisoning every report with 'unknown'. Tests can
// opt out of the eager assertion with AGENTIC_SECURITY_VERSION_UNCHECKED=1.
function _readVersion() {
  const require = createRequire(import.meta.url);
  const pkg = require('../../package.json');
  if (!pkg || typeof pkg.version !== 'string' || !pkg.version) {
    throw new Error('scanner/package.json has no `version` field');
  }
  return pkg.version;
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
