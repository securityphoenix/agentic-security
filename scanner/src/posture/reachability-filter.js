// Reachability filter (FR-PREC-2).
//
// annotateReachability() in engine.js already sets f.reachable to true|false
// based on whether the finding sits in code reachable from an HTTP route. This
// module turns that signal into a precision lever: findings marked reachable=
// false are demoted to severity 'info' with f.unreachable = true.
//
// Disabled when scanRoot/--include-unreachable signals are present, or when
// AGENTIC_SECURITY_INCLUDE_UNREACHABLE=1 is set.

const SEVERITY_DEMOTE = {
  critical: 'medium',
  high: 'low',
  medium: 'low',
  low: 'info',
};

export function demoteUnreachable(findings, opts = {}) {
  if (!Array.isArray(findings)) return;
  if (opts.includeUnreachable || process.env.AGENTIC_SECURITY_INCLUDE_UNREACHABLE === '1') return;
  // The reachability signal is only informative when the project HAS route
  // handlers. A fixture file scanned in isolation has every finding marked
  // reachable=false by annotateReachability(); demoting all of them would
  // hide real bugs the user is trying to verify.
  const haveRoutes = Array.isArray(opts.routes) ? opts.routes.length > 0 : false;
  if (!haveRoutes) return;
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    if (f.reachable !== false) continue;
    if (f.type === 'vulnerable_dep') continue;
    if (f.unreachable) continue;
    // Source has an explicit HTTP/DOM/Form/URL category → engine is confident
    // it's a user-input source even though no route was linked. Don't demote.
    if (f.source && f.source.category && /HTTP|DOM|Form|URL|Query/i.test(f.source.category)) continue;
    const before = f.severity;
    const after = SEVERITY_DEMOTE[before];
    if (!after || before === after) continue;
    f.severity = after;
    f.unreachable = true;
    f._reachabilityDemoted = before;
  }
}
