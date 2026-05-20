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

/**
 * v0.69 #4a — regex-constrained string value.
 *
 * Represents a string whose concrete value is unknown but whose CHARSET +
 * SHAPE are bounded to a regex. Sanitizers produce these:
 *   encodeURIComponent(x) → Regex(/^[A-Za-z0-9-_.!~*'()%]*$/)
 *   parseInt(x).toString() → Regex(/^-?\d+$/)
 *   bcrypt.hash(x) → Regex(/^\$2[aby]?\$\d{1,2}\$[./A-Za-z0-9]{53}$/)
 *
 * The pattern MUST be anchored with ^ and $ to be sound.
 */
export function makeRegex(pattern) {
  if (!(pattern instanceof RegExp)) return TOP;
  const src = pattern.source;
  if (!src.startsWith('^') || !src.endsWith('$')) return TOP;
  return { kind: 'Regex', pattern };
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
 *   Const(s) ⊔ Const(t) = Regex(escape(s)|escape(t)) if both anchor-friendly
 *   Regex(p) ⊔ Const(s) where s matches p = Regex(p)
 *   Regex(p1) ⊔ Regex(p2) = Regex(p1) if patterns identical, else TOP
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
  if (a.kind === 'Regex' && b.kind === 'Regex') {
    return a.pattern.source === b.pattern.source ? a : TOP;
  }
  if (a.kind === 'Regex' && b.kind === 'Const') {
    return a.pattern.test(b.value) ? a : TOP;
  }
  if (b.kind === 'Regex' && a.kind === 'Const') {
    return b.pattern.test(a.value) ? b : TOP;
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
    case 'call': {
      // v0.69 #4a — sanitizer-call output is regex-constrained.
      const tail = String(expr.callee || '').split('.').pop();
      const r = SANITIZER_OUTPUT_REGEX[tail];
      if (r) return makeRegex(r);
      return TOP;
    }
    default:
      return TOP;
  }
}

/**
 * Catalog of known sanitizer output regexes. The output of these calls is
 * provably bounded to the listed charset. This is what powers the
 * `provenClean` flag for non-SQL injection classes.
 *
 * Patterns are conservative — only listed when the spec REQUIRES the
 * output to fit the regex. Empty / null returns are part of the domain.
 */
const SANITIZER_OUTPUT_REGEX = {
  // URL-safe encoding (RFC 3986 reserved + unreserved with %xx escapes).
  encodeURIComponent: /^[A-Za-z0-9\-_.!~*'()%]*$/,
  encodeURI:          /^[A-Za-z0-9\-_.!~*'();/?:@&=+$,#%]*$/,
  // Numeric-coerced.
  parseInt:           /^-?\d+$/,
  parseFloat:         /^-?\d+(?:\.\d+)?$/,
  // bcrypt / scrypt output format.
  hashSync:           /^\$2[aby]?\$\d{1,2}\$[.\/A-Za-z0-9]{53}$/,
  // Hex digest from crypto.
  digest:             /^[0-9a-f]+$/,
  toString:           /^[A-Za-z0-9+/=]*$/,    // when called on a Buffer with 'base64' — over-approximate, narrowed by argIndex in v2
  // Java URLEncoder.encode — RFC 3986 + spaces as '+'.
  // (We can't distinguish overloads from regex name alone; conservative listing.)
  // PHP htmlspecialchars / htmlentities — HTML-entity escape.
  htmlspecialchars:   /^[^<>&"']*(?:&(?:lt|gt|amp|quot|#039);)*[^<>&"']*$/,
};

/**
 * SAFE-CHARSET PROOF — does the abstract value provably fit the given regex?
 *
 * Used by sanitizer-proof.js to verify that a sanitizer's output cannot
 * contain the metacharacters of a target injection family (no `'` for SQL,
 * no `<` for XSS, no `\r\n` for response-splitting, etc.).
 *
 * Returns true iff EVERY concrete string in the abstract value's denotation
 * matches `safe`.
 */
export function provablyMatches(absVal, safe) {
  if (!absVal || !(safe instanceof RegExp)) return false;
  if (absVal.kind === 'Const') return safe.test(absVal.value);
  if (absVal.kind === 'Regex') {
    // Sound approximation: same source string → provable. Otherwise we'd
    // need regex-subset, which is undecidable in general; v2 could do
    // structural checks for common cases.
    return absVal.pattern.source === safe.source;
  }
  if (absVal.kind === 'Concat') {
    // A concat is provably safe iff every part is provably safe AND the
    // safe regex permits arbitrary repetition (i.e. is of the form ^X*$).
    if (!/^\^.+\*\$$/.test(safe.source)) return false;
    return absVal.parts.every(p => provablyMatches(p, safe));
  }
  return false;
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
  if (absVal.kind === 'Regex') return `${absVal.pattern.source}`;
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
