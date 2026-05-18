import { blankComments } from './_comment-strip.js';
// TOCTOU — time-of-check / time-of-use races.
//
// Two dominant shapes:
//   1. Filesystem race:  fs.access(p) → fs.open(p)
//                        os.access(p) → open(p)
//                        os.path.exists(p) → open(p)
//      The classic CWE-367. Whatever the check learned about `p` may not hold
//      by the time the use happens; an attacker who can swap symlinks wins.
//
//   2. Auth race:        if (!user.isAdmin) return; doSensitiveThing(user)
//                        if user.role != 'admin': return; do_sensitive(user)
//      Less concrete — these are gated on the check happening *first* — but
//      when the check value can be mutated by a concurrent request, we flag
//      it. Heuristic: between the guard and the use, the code awaits
//      something. The await is the race window.

const FS_CHECK_THEN_OPEN_JS = /\bfs\s*\.\s*(?:access|exists|stat|statSync|existsSync)\s*\(\s*([^,)]+?)\s*[,)][^]*?\bfs\s*\.\s*(?:open|openSync|readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream)\s*\(\s*\1/g;

const FS_CHECK_THEN_OPEN_PY = /\b(?:os\.access|os\.path\.exists|os\.path\.isfile|os\.stat)\s*\(\s*([^,)]+?)\s*\)[^]*?\b(?:open|os\.open|shutil\.copy|shutil\.move)\s*\(\s*\1/g;

const AUTH_CHECK_AWAIT_USE_JS = /\bif\s*\(\s*!?\s*\w+\s*(?:\.|->)\s*(?:isAdmin|isOwner|hasRole|role)\b[^)]*\)\s*[^]*?\bawait\b[^]*?\b(?:save|update|create|destroy|delete|withdraw|transfer|approve|grant)\s*\(/g;

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

export function scanTOCTOU(fp, raw) {
  if (!raw || raw.length > 500_000) return [];
  const findings = [];
  const seen = new Set();
  const push = (f) => { if (!seen.has(f.id)) { seen.add(f.id); findings.push(f); } };

  if (/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(fp)) {
    const code = blankComments(raw);
    let m;
    const r = new RegExp(FS_CHECK_THEN_OPEN_JS.source, FS_CHECK_THEN_OPEN_JS.flags);
    while ((m = r.exec(code))) {
      const line = lineOf(raw, m.index);
      push({
        id: `toctou-fs:${fp}:${line}`,
        file: fp, line,
        vuln: 'TOCTOU: file existence/permission check before open',
        severity: 'medium',
        cwe: 'CWE-367',
        stride: 'Tampering',
        snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
        remediation: 'Drop the existence/permission check and rely on `open()` to fail atomically — handle the resulting error. The check-then-open pattern is a TOCTOU race: an attacker who can swap symlinks between the check and the open wins. If you need a permission test, do it on the `open()` result\'s `fstat`, not on the path before opening.',
        parser: 'TOCTOU',
        confidence: 0.70,
      });
    }
    const ar = new RegExp(AUTH_CHECK_AWAIT_USE_JS.source, AUTH_CHECK_AWAIT_USE_JS.flags);
    while ((m = ar.exec(code))) {
      const block = m[0];
      // Heuristic: only flag if the guard variable is potentially re-read after await.
      // Approximation: guard uses `await` *between* check and side effect.
      if (!/await/.test(block)) continue;
      const line = lineOf(raw, m.index);
      push({
        id: `toctou-auth:${fp}:${line}`,
        file: fp, line,
        vuln: 'TOCTOU: auth check then await then sensitive action',
        severity: 'medium',
        cwe: 'CWE-367',
        stride: 'Elevation of Privilege',
        snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
        remediation: 'Re-fetch and re-check the authorization right before the sensitive action, ideally inside the same transaction. If the user\'s role can be revoked or downgraded mid-request, the check at the top of the handler is not load-bearing. Pattern: `BEGIN TX → SELECT FOR UPDATE → check role → side effect → COMMIT`.',
        parser: 'TOCTOU',
        confidence: 0.55,
      });
    }
  }

  if (/\.py$/i.test(fp)) {
    const code = blankComments(raw, 'py');
    let m;
    const r = new RegExp(FS_CHECK_THEN_OPEN_PY.source, FS_CHECK_THEN_OPEN_PY.flags);
    while ((m = r.exec(code))) {
      const line = lineOf(raw, m.index);
      push({
        id: `toctou-fs:${fp}:${line}`,
        file: fp, line,
        vuln: 'TOCTOU: file existence/permission check before open',
        severity: 'medium',
        cwe: 'CWE-367',
        stride: 'Tampering',
        snippet: (raw.split('\n')[line - 1] || '').trim().slice(0, 200),
        remediation: 'Use `try: open(...) except OSError` instead of the `if os.path.exists(...)` pre-check. The pre-check creates a TOCTOU window an attacker who can swap symlinks can exploit. For permission tests, use `os.open(path, os.O_RDONLY | os.O_NOFOLLOW)` then `os.fstat()`.',
        parser: 'TOCTOU',
        confidence: 0.70,
      });
    }
  }

  return findings;
}
