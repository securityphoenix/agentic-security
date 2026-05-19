// CWE ↔ family lookup tables for the PoC generator (P1.1).
//
// Kept separate from poc-generator.js so the templates can be ergonomic
// (small, focused) and the mapping table can grow independently as we add
// CWE coverage. Both files exported as a single contract.

export const CWE_TO_FAMILY = Object.freeze({
  'CWE-89':  'sql-injection',
  'CWE-78':  'command-injection',
  'CWE-79':  'xss',
  'CWE-22':  'path-traversal',
  'CWE-918': 'ssrf',
  'CWE-94':  'code-injection',
  'CWE-352': 'csrf',
  'CWE-601': 'open-redirect',
  'CWE-611': 'xxe',
  'CWE-502': 'insecure-deserialization',
});

export const FAMILY_TO_PRIMARY_CWE = Object.freeze(
  Object.fromEntries(Object.entries(CWE_TO_FAMILY).map(([k, v]) => [v, k]))
);

// Families for which v1 explicitly does NOT generate a PoC. The verifier
// marks these `unverified-by-design`. Documented here so the choice is
// auditable rather than buried in template absence. Read via the
// `isExplicitlyNoPoc()` helper; not exported directly.
const NO_POC_FAMILIES = Object.freeze(new Set([
  'timing-oracle',         // requires statistical analysis, not a single request
  'data-exposure',         // visual-inspection-shaped; no single demonstrable request
  'log-injection',         // sink is the log file; out-of-band verification needed
  'audit-logging',         // absence-of-a-thing; harder to PoC
  'header-hardening',      // configuration finding, not flow-based
  'hardcoded-secret',      // proof = grep, not a request
  'vulnerable-dep',        // proof = OSV lookup, not a runtime PoC
  'jwt-no-exp',            // requires waiting; not single-shot
  'orm-no-pagination',     // resource exhaustion shape; sandbox-unsafe to PoC
  'weak-rng',              // statistical; not a single request
  'weak-crypto',           // statistical; not a single request
]));

export function isPocSupported(familyOrCwe) {
  if (!familyOrCwe) return false;
  if (CWE_TO_FAMILY[familyOrCwe]) return true;
  if (FAMILY_TO_PRIMARY_CWE[familyOrCwe]) return true;
  return false;
}

export function isExplicitlyNoPoc(family) {
  return NO_POC_FAMILIES.has(family);
}
