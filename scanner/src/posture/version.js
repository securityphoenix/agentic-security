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

let _version = 'unknown';
try {
  const require = createRequire(import.meta.url);
  const pkg = require('../../package.json');
  if (pkg && typeof pkg.version === 'string') _version = pkg.version;
} catch (_) { /* fall through to 'unknown' */ }

export const SCANNER_VERSION = _version;
