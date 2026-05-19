// String-value abstract domain (P4.4).
//
// The taint engine treats every string as opaque — "tainted" or "clean."
// Real codebases have lots of strings that are KNOWN at compile time:
//
//   const url = "https://internal.example.com/health";
//   await fetch(url);
//
// `url` is constant. SSRF is *impossible*. The current engine doesn't fire
// (because the literal isn't tainted), but it ALSO doesn't actively prove
// safety — and when a project mixes constants with user-influenced fragments,
// the engine over-approximates conservatively.
//
// This module models strings with a three-element lattice:
//
//   Const(literal)         "https://internal.example.com"
//   Concat(parts)          "https://" + host + "/" + path
//   Unknown                anything we can't statically analyze
//
// And provides:
//   - abstract(expr) → returns the abstract value for an IR expression
//   - isSafeUrl(absVal, allowedHosts) → bool, prove the URL is safe
//   - join(a, b) → lattice meet (used at branch joins)
//
// v1: enough to handle the common SSRF / open-redirect "constant URL" case.
// v2 would add prefix/suffix analysis, regex membership, etc.

export const TOP = { kind: 'Unknown' };
export const BOTTOM = { kind: 'Const', value: '' };   // empty string = bottom of useful domain

export function makeConst(value) {
  if (typeof value !== 'string') return TOP;
  return { kind: 'Const', value };
}

export function makeConcat(parts) {
  // Optimize: if every part is Const, collapse to a single Const.
  if (parts.every(p => p && p.kind === 'Const')) {
    return makeConst(parts.map(p => p.value).join(''));
  }
  // If any part is Unknown, the whole concat is Unknown.
  if (parts.some(p => !p || p.kind === 'Unknown')) return TOP;
  return { kind: 'Concat', parts };
}

/**
 * Lattice join: a ⊔ b. Returns the least-upper-bound.
 *
 *   Const(s) ⊔ Const(s) = Const(s)
 *   Const(s) ⊔ Const(t) = Concat([Const(s), Const(t)])  if s !== t
 *   anything ⊔ Unknown = Unknown
 */
export function join(a, b) {
  if (!a) return b;
  if (!b) return a;
  if (a.kind === 'Unknown' || b.kind === 'Unknown') return TOP;
  if (a.kind === 'Const' && b.kind === 'Const') {
    if (a.value === b.value) return a;
    return TOP;     // distinct constants from two branches — be conservative
  }
  return TOP;
}

/**
 * Abstract an IR expression into a string-value abstract value. The engine
 * walks expressions during evaluation; this helper gives us the
 * `Const | Concat | Unknown` summary alongside the boolean taint check.
 */
export function abstract(expr) {
  if (!expr) return TOP;
  switch (expr.kind) {
    case 'literal':
      if (typeof expr.value === 'string') return makeConst(expr.value);
      return TOP;
    case 'tpl':
      if (Array.isArray(expr.parts)) return makeConcat(expr.parts.map(abstract));
      return TOP;
    case 'binary': {
      if (expr.op === '+' || expr.op === '+=') {
        return makeConcat([abstract(expr.left), abstract(expr.right)]);
      }
      return TOP;
    }
    default:
      return TOP;
  }
}

/**
 * Render an abstract string back to a textual form for diagnostics.
 *
 *   Const("hello") → "hello"
 *   Concat([Const("a"), Unknown, Const("b")]) → "a${...}b"
 *   Unknown → "${...}"
 */
export function render(absVal) {
  if (!absVal || absVal.kind === 'Unknown') return '${...}';
  if (absVal.kind === 'Const') return absVal.value;
  if (absVal.kind === 'Concat') {
    return absVal.parts.map(p => render(p)).join('');
  }
  return '${...}';
}

/**
 * SSRF guard: given an abstract URL value and a list of trusted hosts,
 * return true iff the URL is provably to one of the trusted hosts.
 *
 *   isProvablyToHost(makeConst("https://internal.example.com/x"), ["internal.example.com"]) → true
 *   isProvablyToHost(TOP, [...]) → false (can't prove anything about Unknown)
 *   isProvablyToHost(Concat(["https://" + Unknown]), [...]) → false
 */
export function isProvablyToHost(absVal, allowedHosts) {
  if (!absVal || absVal.kind !== 'Const') return false;
  if (!Array.isArray(allowedHosts) || !allowedHosts.length) return false;
  let url;
  try {
    url = new URL(absVal.value);
  } catch { return false; }
  return allowedHosts.includes(url.host);
}

/**
 * Open-redirect safe? An abstract URL value passed to res.redirect is safe
 * when it's either provably to an allowed host OR a relative path with no
 * scheme/host parts.
 */
export function isSafeRedirectTarget(absVal, allowedHosts) {
  if (!absVal) return false;
  if (absVal.kind === 'Const') {
    // Relative path starting with / and not //
    if (/^\/(?!\/)/.test(absVal.value)) return true;
    return isProvablyToHost(absVal, allowedHosts);
  }
  return false;
}

/**
 * Hash an abstract value for cache-key purposes.
 */
export function hashAbstract(absVal) {
  return render(absVal);
}
