// SentQL path-constraint predicate catalog.
//
// When a custom rule declares `path: { must_traverse: [...], must_not_traverse: [...] }`
// the runtime checks each predicate against the finding's path metadata (route
// reachability, sanitizer presence, auth-guard presence, etc.) and drops the
// finding when the constraint is violated.
//
// A predicate is a string identifier. The dispatch table below maps each
// identifier to a function `(finding) → bool` that tests the finding.
//
// New predicates can be added without changing the SentQL grammar — author
// names them in YAML, this file resolves the name.

// Each predicate returns TRUE iff the finding satisfies the predicate.
const PREDICATES = {
  // The finding's source is a route handler (HTTP entry point).
  is_http_route(f) {
    if (f.routeRooted === true) return true;
    if (f.source && f.source.category && /HTTP|URL|Form|DOM/i.test(f.source.category)) return true;
    return false;
  },
  // Inverse — finding doesn't come from a route handler.
  not_http_route(f) { return !PREDICATES.is_http_route(f); },

  // A sanitizer was detected on the path.
  is_sanitized(f) { return f.isSanitized === true; },
  not_sanitized(f) { return !PREDICATES.is_sanitized(f); },

  // An auth guard is present on the path.
  is_auth_guarded(f) { return Array.isArray(f.guards) && f.guards.length > 0; },
  not_auth_guarded(f) { return !PREDICATES.is_auth_guarded(f); },

  // Reachable from an unauthenticated route (engine annotation).
  has_unauth_route(f) {
    if (Array.isArray(f.exploitabilityFactors) && f.exploitabilityFactors.includes('unauth-route-reachable')) return true;
    return false;
  },

  // Cross-file taint chain (multi-hop, not single-file).
  is_cross_file(f) {
    if (f.isCrossFile === true) return true;
    const srcFile = f.source && f.source.file;
    const sinkFile = (f.sink && f.sink.file) || f.file;
    return !!(srcFile && sinkFile && srcFile !== sinkFile);
  },
  not_cross_file(f) { return !PREDICATES.is_cross_file(f); },

  // Reachable at all (call graph said yes).
  is_reachable(f) { return f.reachable === true; },
  not_reachable(f) { return f.reachable === false; },

  // Finding has a path / chain of length > 1.
  has_multi_step_path(f) {
    if (Array.isArray(f.chain) && f.chain.length > 1) return true;
    if (Array.isArray(f.pathSteps) && f.pathSteps.length > 1) return true;
    return false;
  },
};

// Drop findings whose path violates the rule's constraints.
//   - must_traverse: ALL predicates must return true
//   - must_not_traverse: NONE may return true
// Returns { kept: Finding[], dropped: SuppressionEntry[] }.
export function applyPathConstraints(findings) {
  const kept = [];
  const dropped = [];
  for (const f of (findings || [])) {
    const c = f && f._pathConstraints;
    if (!c) { kept.push(f); continue; }
    let drop = null;
    if (Array.isArray(c.mustTraverse) && c.mustTraverse.length) {
      for (const name of c.mustTraverse) {
        const pred = PREDICATES[name];
        // Unknown predicates fail-open: don't drop the finding just because the
        // rule named a predicate we don't know about. Log silently.
        if (!pred) continue;
        if (!pred(f)) { drop = `must-traverse-failed:${name}`; break; }
      }
    }
    if (!drop && Array.isArray(c.mustNotTraverse) && c.mustNotTraverse.length) {
      for (const name of c.mustNotTraverse) {
        const pred = PREDICATES[name];
        if (!pred) continue;
        if (pred(f)) { drop = `must-not-traverse-hit:${name}`; break; }
      }
    }
    if (drop) {
      dropped.push({
        vuln: f.vuln, file: f.file, line: f.line, snippet: f.snippet || '',
        reason: 'sentql-path-constraint:' + drop,
      });
      continue;
    }
    kept.push(f);
  }
  return { kept, dropped };
}

export const _internalPredicateNames = Object.keys(PREDICATES);
