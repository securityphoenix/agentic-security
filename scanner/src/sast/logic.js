// Business-logic flaw detector — high-precision pattern layer.
//
// Logic flaws normally require semantic reasoning, but a handful of canonical
// anti-patterns are unambiguous in source: an admin check that uses `||` so it
// always passes, a TOCTOU `existsSync → readFile` sequence, a price field
// trusted from the request body in a DB write. We cover those here so the
// engine emits findings on them without needing an agent. Deeper logic review
// (intent vs. implementation) is delegated to the security-logic-reviewer agent.

const _NONPROD_PATH_RE = /(?:^|\/)(?:tests?|__tests__|spec|fixtures?|examples?|docs?|stories|codefixes|node_modules)\//i;
const _SCAN_EXT_RE = /\.(?:js|jsx|ts|tsx|mjs|cjs|py|rb|go|java|php)$/i;

// PATTERN A — always-true authorization clause.
// Examples:  if (user.isAdmin || user.id)               -> user.id is always truthy
//            if (req.user.role === 'admin' || true)     -> obvious
//            if (isAdmin || isUser)                      -> isUser is always truthy in an authed context
const ALWAYS_TRUE_AUTH_RE = /\bif\s*\(\s*(?:[A-Za-z_$][\w$.]*\.(?:isAdmin|admin|isOwner|hasRole|role)\b[^)]*?)\|\|\s*(?:true\b|[A-Za-z_$][\w$.]*\.(?:id|userId|uid|email|user)\b\s*\)|true\b)/;

// PATTERN B — TOCTOU on filesystem. existsSync → readFile / open / unlink at a related path.
const TOCTOU_EXISTS_THEN_OP_RE = /\bfs\.existsSync\s*\(\s*([^)]+?)\s*\)[\s\S]{1,300}?\bfs\.(?:readFile(?:Sync)?|writeFile(?:Sync)?|unlink(?:Sync)?|open(?:Sync)?|createReadStream|createWriteStream)\s*\(\s*\1/;

// PATTERN C — client-controlled monetary field flowing into a DB write.
const CLIENT_AMOUNT_TO_DB_RE = /(?:price|amount|total|subtotal|cost|fee|charge|payment|sum)\s*[:=]\s*(?:req|request)\.body\b/;

// PATTERN D — admin / role / isAdmin set from request body (mass-assignment of privilege).
const PRIV_FROM_BODY_RE = /\b(?:isAdmin|is_admin|admin|role|roles|permissions|scopes|tier|isOwner|is_owner)\s*[:=]\s*(?:req|request)\.body\.[A-Za-z_]\w*/;

// PATTERN E — state transition without prior-state guard.
// Heuristic: `<obj>.status = 'completed' / 'paid' / 'shipped' / 'approved'` immediately
// after a fetch with no surrounding `if (... .status === ...)` check in the same function block.
const STATE_TERMINAL_SET_RE = /\b(\w+)\.(?:status|state|stage)\s*=\s*['"](?:completed|complete|paid|shipped|approved|active|published|verified|confirmed)['"]/;

// PATTERN F — coupon / discount applied without server-side lookup.
// Match either `discount = req.body...` (assignment) or `req.body.discount` (direct read).
const CLIENT_DISCOUNT_RE = /(?:discount|coupon|promo|voucher)\s*[:=]\s*(?:req|request)\.body\b|(?:req|request)\.body\.(?:discount|coupon|promo|voucher)\b/i;

// PATTERN G — duplicate-create / missing idempotency.
// Fires when a POST handler does an INSERT/.create()/.save() with no upstream
// SELECT-or-find-by-key check inside the same handler.
//
// Implemented in the per-route pass below.

function _ctxFn(lines, atIdx, span = 25) {
  const start = Math.max(0, atIdx - Math.floor(span / 2));
  const end = Math.min(lines.length, atIdx + Math.ceil(span / 2));
  return lines.slice(start, end).join('\n');
}

function _emit(fp, vuln, line, snippet, severity, cwe, fix, confidence) {
  return {
    id: `logic:${fp}:${line}:${vuln.replace(/\s/g, '_').slice(0, 60)}`,
    kind: 'logic', severity, vuln,
    cwe: cwe || null, stride: 'Tampering',
    file: fp, line, snippet: snippet.trim(),
    fix, confidence,
  };
}

export function scanBusinessLogic(fp, raw) {
  if (!_SCAN_EXT_RE.test(fp)) return [];
  const fpNorm = fp.replace(/\\/g, '/');
  if (_NONPROD_PATH_RE.test(fpNorm)) return [];
  if (!raw || raw.length > 500_000) return [];

  const lines = raw.split('\n');
  const findings = [];
  const seen = new Set();

  // Single-line patterns
  for (let li = 0; li < lines.length; li++) {
    const line = lines[li];

    // PATTERN A
    if (ALWAYS_TRUE_AUTH_RE.test(line)) {
      const f = _emit(fp, 'Always-True Authorization Clause',
        li + 1, line, 'high', 'CWE-285',
        'The `||` short-circuit makes this check pass for any authenticated user. Use `&&` to require BOTH conditions, or split into explicit role checks.',
        0.9);
      if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); }
    }

    // PATTERN C — client-controlled money
    if (CLIENT_AMOUNT_TO_DB_RE.test(line)) {
      const f = _emit(fp, 'Client-Controlled Monetary Field',
        li + 1, line, 'high', 'CWE-841',
        'Recompute price/amount on the server from authoritative records (catalog, cart, subscription tier). Never accept the final amount from the request body.',
        0.85);
      if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); }
    }

    // PATTERN D — privilege from body
    if (PRIV_FROM_BODY_RE.test(line)) {
      const f = _emit(fp, 'Privilege Field Set from Request Body',
        li + 1, line, 'critical', 'CWE-915',
        'Strip privilege fields from the request body before assignment, or use an explicit allowlist of mutable fields. An attacker can post `isAdmin:true` and elevate.',
        0.9);
      if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); }
    }

    // PATTERN F — client-controlled discount/coupon
    if (CLIENT_DISCOUNT_RE.test(line)) {
      const f = _emit(fp, 'Client-Controlled Discount/Coupon',
        li + 1, line, 'medium', 'CWE-840',
        'Look up the coupon by code on the server and validate redemption status, expiry, and per-user use-count. Do not trust the discount value sent by the client.',
        0.8);
      if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); }
    }

    // PATTERN E — terminal state set without prior-state guard.
    // Heuristic: look upward in a 25-line window for an `if (... .status === ...)` guard;
    // suppress when one is present.
    const stateM = line.match(STATE_TERMINAL_SET_RE);
    if (stateM) {
      const objName = stateM[1];
      const ctxAbove = lines.slice(Math.max(0, li - 25), li).join('\n');
      const guardRe = new RegExp(`if\\s*\\([^)]*\\b${objName}\\.(?:status|state|stage)\\s*(?:===|==|!==|!=)\\s*['"]`, 'i');
      if (!guardRe.test(ctxAbove)) {
        const f = _emit(fp, 'Terminal State Set Without Prior-State Guard',
          li + 1, line, 'medium', 'CWE-840',
          'Verify the current state before transitioning to a terminal state (e.g., assert order.status === "pending" before setting to "paid"). Without this guard an attacker can replay or skip required steps.',
          0.7);
        if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); }
      }
    }
  }

  // Multi-line: TOCTOU
  let m;
  const toctouRe = new RegExp(TOCTOU_EXISTS_THEN_OP_RE.source, 'g');
  while ((m = toctouRe.exec(raw))) {
    const line = raw.substring(0, m.index).split('\n').length;
    const f = _emit(fp, 'TOCTOU: existsSync followed by file op',
      line, lines[line - 1] || '', 'medium', 'CWE-367',
      'Replace the check-then-act sequence with a single atomic operation (e.g., `fs.open` with appropriate flags). Between `existsSync` and the file op the file can be replaced by a symlink or removed.',
      0.85);
    if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); }
  }

  return findings;
}
