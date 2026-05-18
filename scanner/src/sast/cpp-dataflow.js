// Lightweight intra-procedural data-flow detectors for C/C++.
//
// Goal: catch real-world CVE patterns that the banned-API rules in cpp.js
// miss — bugs that don't have a single "bad function call" but show up as
// a sequence of operations on the same variable within a function body.
//
// Five detectors:
//   1. use-after-free      — free(p) ... deref/use of p downstream in same function
//   2. double-free         — free(p) ... free(p) again on the same path
//   3. missing-null-check  — p = malloc(); ... *p / p->x without `if (p)` guard
//   4. alloc-size-overflow — malloc(n * sizeof(T)) where n is not bounds-checked
//                            and comes from an untrusted source (param/recv/read)
//   5. off-by-one-loop     — for (i=0; i <= len; i++) access arr[i] when arr is
//                            sized [len] (inclusive bound on size-typed length)
//
// Architecture:
//   - parseFunctions(): naive brace-balanced split of a translation unit into
//     function bodies + their parameter lists. No tree-sitter; we use the
//     same brace-counting approach as findCppMethodSpans in the bench.
//   - Per-function: tokenise into a line stream and track interesting
//     "events" per variable (declared, assigned-from-alloc, freed, deref'd,
//     null-checked, used-in-arithmetic). Emit a finding when the sequence
//     matches one of the bug shapes.
//
// Gating: every detector requires multiple correlated events. A standalone
// `free(p)` is never enough — we need free + later use. This keeps FPs low
// on production code where free() is everywhere but UAF is rare.

const CPP_EXT_RE = /\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx)$/i;

// Parse-error counter — exposed via /status so silent failures are observable.
// Never resets between calls; intentionally process-lifetime so the counter
// accumulates across all files in a scan session.
export const _parseErrorCount = { value: 0 };

// Escape a string for safe interpolation into a RegExp source pattern.
// varNames come from C/C++ identifiers matched by [\w.->]+ — they can
// contain dots (struct member a.b) and arrow (a->b). Escape metacharacters
// so the caller's dynamic regex cannot catastrophically backtrack or mismatch.
function _esc(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

// Function-finder uses brace counting, NOT regex — the previous catch-all
// regex with nested `(?:...)+` quantifiers exhibited catastrophic backtracking
// on real-world C/C++ headers. See _findFunctions below.
//
// Keyword set that looks like a function call but isn't a definition.
const _NON_FN_KEYWORDS = new Set([
  'if', 'while', 'for', 'switch', 'sizeof', 'return', 'else', 'catch',
  'typedef', 'do', 'case', 'goto', 'throw', 'static_cast', 'dynamic_cast',
  'reinterpret_cast', 'const_cast', '__attribute__', '__asm__', 'asm',
  'decltype', 'alignof', 'alignas', 'noexcept', 'static_assert',
]);

// Tokens we recognise inside function bodies. Comments are pre-stripped.
const _FREE_CALL_RE = /\b(?:free|kfree|vfree|g_free|av_free|av_freep|sk_free)\s*\(\s*([\w.->]+)\s*\)/g;
const _ALLOC_ASSIGN_RE = /\b([A-Za-z_]\w*)\s*=\s*(?:\(\s*[\w\s*]+\s*\)\s*)?(?:malloc|calloc|realloc|kmalloc|kzalloc|kcalloc|g_malloc|g_malloc0|av_malloc|av_mallocz|xmalloc|strdup|strndup|memdup|fopen)\s*\(([^)]*)\)/g;
const _DEREF_RE = /(?:\*\s*([A-Za-z_]\w*)\b|\b([A-Za-z_]\w*)\s*->|\b([A-Za-z_]\w*)\s*\[)/g;
const _NULL_CHECK_RE = /\bif\s*\(\s*(?:!\s*([A-Za-z_]\w*)\b|([A-Za-z_]\w*)\s*(?:==|!=)\s*NULL|([A-Za-z_]\w*)\s*(?:==|!=)\s*0\b|([A-Za-z_]\w*)\s*(?:==|!=)\s*nullptr)/g;
const _ARRAY_ACCESS_RE = /\b([A-Za-z_]\w*)\s*\[\s*([A-Za-z_]\w*)\s*\]/g;
const _LOOP_FOR_RE = /\bfor\s*\(\s*(?:[\w\s*]+?\s+)?([A-Za-z_]\w*)\s*=\s*0\s*;\s*\1\s*(<=|<)\s*([A-Za-z_]\w*)\s*;\s*(?:\+\+\1|\1\s*\+\+|\1\s*\+=\s*1)\s*\)/g;
const _SIZEOF_INT_RE = /\b(?:malloc|calloc|kmalloc|kzalloc|g_malloc|g_malloc0|xmalloc)\s*\(\s*([A-Za-z_]\w*)\s*\*\s*sizeof\s*\(/g;
// Tainted-source identifiers — values coming from outside the function are
// suspect for size-overflow detection.
const _TAINT_SOURCE_RE = /\b(?:recv|recvfrom|read|readv|fread|fgets|getline|getenv|scanf|sscanf|fscanf|atoi|atol|strtol|strtoul|ntohl|ntohs|be32toh|le32toh)\b/;

// Strip C/C++ comments AND string/char literals. Replace each with same-length
// whitespace so line numbers and offsets stay correct.
function _blank(content) {
  let out = '', i = 0, n = content.length;
  while (i < n) {
    const ch = content[i];
    if (ch === '/' && content[i + 1] === '/') {
      while (i < n && content[i] !== '\n') { out += ' '; i++; }
      continue;
    }
    if (ch === '/' && content[i + 1] === '*') {
      out += '  '; i += 2;
      while (i < n - 1 && !(content[i] === '*' && content[i + 1] === '/')) {
        out += content[i] === '\n' ? '\n' : ' '; i++;
      }
      out += i < n ? '  ' : ''; i += 2;
      continue;
    }
    if (ch === '"' || ch === "'") {
      const q = ch; out += q; i++;
      while (i < n && content[i] !== q) {
        if (content[i] === '\\' && i + 1 < n) { out += '  '; i += 2; continue; }
        out += content[i] === '\n' ? '\n' : ' '; i++;
      }
      if (i < n) { out += q; i++; }
      continue;
    }
    out += ch; i++;
  }
  return out;
}

// Find each top-level function definition via brace counting.
// Walks the file char-by-char, tracking `{` depth. At each `{` that takes
// depth from 0→1, we look backwards from that `{` for the most recent
// `<name>(<args>)` pair that looks like a function declaration. Then we
// find the matching `}` and extract the body span.
//
// Bounds: hard-cap at 5000 functions per file to avoid pathological cases.
function _findFunctions(content) {
  const fns = [];
  const n = content.length;
  let depth = 0;
  let i = 0;
  const PARSE_LIMIT = 5000;
  while (i < n && fns.length < PARSE_LIMIT) {
    const ch = content[i];
    if (ch === '{') {
      if (depth === 0) {
        // depth 0→1 transition. Look backwards from i for the function
        // signature: skip whitespace, then expect `)`, scan back to matching
        // `(`, then identify the function name before `(`.
        let j = i - 1;
        while (j >= 0 && /\s/.test(content[j])) j--;
        // Optional const/noexcept/throw(...) before `{` (skip them).
        // Scan back up to ~200 chars for the closing `)`.
        const lookbackStart = Math.max(0, i - 200);
        const tail = content.substring(lookbackStart, i);
        const rparenIdx = tail.lastIndexOf(')');
        if (rparenIdx > 0) {
          // Find matching `(` by counting parens.
          let pdepth = 1, k = rparenIdx - 1;
          while (k >= 0 && pdepth > 0) {
            if (tail[k] === ')') pdepth++;
            else if (tail[k] === '(') pdepth--;
            if (pdepth === 0) break;
            k--;
          }
          if (k >= 0) {
            // Identifier just before `(` (after trimming whitespace).
            let nameEnd = k - 1;
            while (nameEnd >= 0 && /\s/.test(tail[nameEnd])) nameEnd--;
            let nameStart = nameEnd;
            while (nameStart >= 0 && /[A-Za-z0-9_]/.test(tail[nameStart])) nameStart--;
            nameStart++;
            const name = tail.substring(nameStart, nameEnd + 1);
            if (name && /^[A-Za-z_]\w*$/.test(name) && !_NON_FN_KEYWORDS.has(name)) {
              // Find matching `}` for this function body via brace counting.
              let bdepth = 1, bi = i + 1;
              while (bi < n && bdepth > 0) {
                const bc = content[bi];
                if (bc === '{') bdepth++;
                else if (bc === '}') bdepth--;
                bi++;
              }
              if (bdepth === 0) {
                const startLine = content.substring(0, i).split('\n').length + 1;
                const body = content.substring(i + 1, bi - 1);
                fns.push({ name, startLine, body });
                // Jump past this function body so we don't re-enter on nested `{`.
                depth = 0;
                i = bi;
                continue;
              }
            }
          }
        }
        // Not a recognised function signature; track depth normally.
        depth++;
      } else {
        depth++;
      }
    } else if (ch === '}') {
      if (depth > 0) depth--;
    }
    i++;
  }
  return fns;
}

// Position → line within a function body (1-based, relative to body start).
function _lineOfOffset(body, off) {
  let n = 1;
  for (let i = 0; i < off && i < body.length; i++) if (body[i] === '\n') n++;
  return n;
}

// ── Detector 1: use-after-free ─────────────────────────────────────────────
// Pattern: free(p) appears at line L1; later in the SAME function, p is
// dereferenced (*p, p->x, p[i]) or passed to another function — AND there is
// no intervening reassignment of p (e.g. p = NULL; or p = malloc()).
function _detectUseAfterFree(fnBody, fnStart) {
  const findings = [];
  // Collect every free(p) site.
  _FREE_CALL_RE.lastIndex = 0;
  let m;
  const frees = [];
  while ((m = _FREE_CALL_RE.exec(fnBody))) {
    frees.push({ varName: m[1], off: m.index, end: m.index + m[0].length, line: _lineOfOffset(fnBody, m.index) });
  }
  if (!frees.length) return findings;
  for (const f of frees) {
    // Track from end of free() call — starting 1 char in left `ree(p)` which
    // matched the "use" pattern. Use the stored end offset instead.
    const after = fnBody.substring(f.end);
    // Reassignment kills the dangling pointer.
    const ev = _esc(f.varName);
    const reassignRe = new RegExp(`\\b${ev}\\s*=\\s*(?!=)`);
    const reassignMatch = reassignRe.exec(after);
    const stopOff = reassignMatch ? reassignMatch.index : after.length;
    const scanRegion = after.substring(0, stopOff);
    // Look for any deref or call passing the var.
    const usePat = new RegExp(
      `(?:\\*\\s*${ev}\\b|\\b${ev}\\s*->|\\b${ev}\\s*\\[|[\\w]+\\s*\\(\\s*${ev}\\s*[,)])`,
    );
    const useMatch = usePat.exec(scanRegion);
    if (!useMatch) continue;
    // The free() at line L; the use is on line L_use. Emit on L_use.
    const useLineRel = _lineOfOffset(after, useMatch.index);
    const freeLineRel = _lineOfOffset(fnBody, f.off);
    const useLine = fnStart + freeLineRel + useLineRel - 1;
    findings.push({
      id: `cpp-flow:uaf:${useLine}`,
      severity: 'high',
      cwe: 'CWE-416',
      family: 'mem-unsafe',
      line: useLine,
      vuln: 'Use-after-free — pointer used after free() in same function',
      remediation: `Set the pointer to NULL after free() to fail loudly on later use: \`free(${f.varName}); ${f.varName} = NULL;\` or restructure so the use never occurs.`,
      _parser: 'CPP_DATAFLOW',
    });
  }
  return findings;
}

// ── Detector 2: double-free ───────────────────────────────────────────────
function _detectDoubleFree(fnBody, fnStart) {
  const findings = [];
  _FREE_CALL_RE.lastIndex = 0;
  const frees = [];
  let m;
  while ((m = _FREE_CALL_RE.exec(fnBody))) {
    frees.push({ varName: m[1], off: m.index, end: m.index + m[0].length, line: _lineOfOffset(fnBody, m.index) });
  }
  if (frees.length < 2) return findings;
  // Group by varName, look for two frees with no intervening reassignment.
  const byVar = new Map();
  for (const f of frees) {
    if (!byVar.has(f.varName)) byVar.set(f.varName, []);
    byVar.get(f.varName).push(f);
  }
  for (const [varName, list] of byVar) {
    if (list.length < 2) continue;
    for (let i = 0; i < list.length - 1; i++) {
      const a = list[i], b = list[i + 1];
      const between = fnBody.substring(a.off + 1, b.off);
      const reassignRe = new RegExp(`\\b${_esc(varName)}\\s*=\\s*(?!=)`);
      if (reassignRe.test(between)) continue;
      const line = fnStart + b.line - 1;
      findings.push({
        id: `cpp-flow:double-free:${line}`,
        severity: 'high',
        cwe: 'CWE-415',
        family: 'mem-unsafe',
        line,
        vuln: 'Double-free — same pointer freed twice without reassignment',
        remediation: `Set the pointer to NULL after the first free(): \`free(${varName}); ${varName} = NULL;\`. free(NULL) is a no-op, so the second free becomes safe.`,
        _parser: 'CPP_DATAFLOW',
      });
    }
  }
  return findings;
}

// ── Detector 3: missing-null-check before deref of allocator return ───────
// Pattern: p = malloc(...); ... *p or p->x or p[i] before any
//   if (p), if (!p), if (p == NULL), if (p != NULL).
function _detectMissingNullCheck(fnBody, fnStart) {
  const findings = [];
  _ALLOC_ASSIGN_RE.lastIndex = 0;
  let m;
  while ((m = _ALLOC_ASSIGN_RE.exec(fnBody))) {
    const varName = m[1];
    // Tail of function from after this allocation.
    const after = fnBody.substring(m.index + m[0].length);
    // Find first null-check OR deref, whichever comes first.
    const checkPat = new RegExp(
      `\\bif\\s*\\(\\s*(?:!\\s*${varName}\\b|${varName}\\s*(?:==|!=)\\s*(?:NULL|nullptr|0)\\b|\\(\\s*${varName}\\s*\\)\\s*(?:==|!=))`,
    );
    const derefPat = new RegExp(
      `(?:\\*\\s*${varName}\\b|\\b${varName}\\s*->|\\b${varName}\\s*\\[)`,
    );
    const checkMatch = checkPat.exec(after);
    const derefMatch = derefPat.exec(after);
    if (!derefMatch) continue;                       // never derefed → no risk visible
    if (checkMatch && checkMatch.index < derefMatch.index) continue; // checked first → ok
    const lineRel = _lineOfOffset(after, derefMatch.index);
    const allocLineRel = _lineOfOffset(fnBody, m.index);
    const line = fnStart + allocLineRel + lineRel - 1;
    findings.push({
      id: `cpp-flow:no-null-check:${line}`,
      severity: 'medium',
      cwe: 'CWE-476',
      family: 'mem-unsafe',
      line,
      vuln: 'Missing NULL check — allocator return dereferenced without verification',
      remediation: `Check ${varName} before use: \`if (!${varName}) return -1;\`. Allocators can return NULL on OOM; dereferencing yields a SIGSEGV on Linux/macOS and an exploitable crash on some kernels.`,
      _parser: 'CPP_DATAFLOW',
    });
  }
  return findings;
}

// ── Detector 4: allocation size overflow ──────────────────────────────────
// Pattern: malloc(n * sizeof(T)) where n appears to come from an untrusted
// source AND there is no `if (n > MAX)` bounds check before the malloc.
function _detectAllocSizeOverflow(fnBody, fnStart) {
  const findings = [];
  _SIZEOF_INT_RE.lastIndex = 0;
  let m;
  while ((m = _SIZEOF_INT_RE.exec(fnBody))) {
    const sizeVar = m[1];
    // Skip integer literals (handled by other rules).
    if (/^\d+$/.test(sizeVar)) continue;
    const before = fnBody.substring(0, m.index);
    const esv = _esc(sizeVar);
    // Heuristic 1: the size variable was assigned from a known tainted source
    // earlier in the function.
    const taintAssignRe = new RegExp(
      `\\b${esv}\\s*=\\s*[^;]*${_TAINT_SOURCE_RE.source}`,
    );
    if (!taintAssignRe.test(before)) continue;
    // Heuristic 2: there is no bound check on sizeVar before the malloc.
    const boundCheckRe = new RegExp(
      `\\bif\\s*\\(\\s*${esv}\\s*(?:>=?|<=?)\\s*\\w+`,
    );
    if (boundCheckRe.test(before)) continue;
    const lineRel = _lineOfOffset(fnBody, m.index);
    const line = fnStart + lineRel - 1;
    findings.push({
      id: `cpp-flow:alloc-size-overflow:${line}`,
      severity: 'high',
      cwe: 'CWE-190',
      family: 'buffer-overflow',
      line,
      vuln: 'Allocation size overflow — externally-derived count without bounds check',
      remediation: `Validate ${sizeVar} before allocation: \`if (${sizeVar} > MAX_COUNT) return -1;\`. A multiplied count from a 32-bit input can overflow size_t on 32-bit systems and wrap on 64-bit, returning a tiny buffer that downstream writes overflow.`,
      _parser: 'CPP_DATAFLOW',
    });
  }
  return findings;
}

// ── Detector 5: off-by-one loop bound on length-sized array ───────────────
// Pattern: for (i = 0; i <= len; i++) followed by access to arr[i]
// where arr is declared with size [len] or similar. Inclusive `<=` on a
// size-typed bound iterates one element past the end.
function _detectOffByOne(fnBody, fnStart) {
  const findings = [];
  _LOOP_FOR_RE.lastIndex = 0;
  let m;
  while ((m = _LOOP_FOR_RE.exec(fnBody))) {
    const cmp = m[2];
    if (cmp !== '<=') continue;          // only `<=` is the bug
    const idxVar = m[1], boundVar = m[3];
    // Find the loop body and check for `arr[idxVar]` access where the array
    // dim is `boundVar` or where `boundVar` looks like a length.
    // We don't track the declared array size precisely — instead, require the
    // bound var to be named *len, *count, *size, etc. (length-typed).
    if (!/^\w*(?:len|Len|count|Count|size|Size|length|Length|n)$/.test(boundVar)) continue;
    // Inclusive iteration over [0..len] is one-past-end on a [len]-sized
    // array. Emit if the loop body actually indexes some array with idxVar.
    const loopStart = m.index + m[0].length;
    // Bound the loop body to the next 1500 chars (conservative window).
    const tail = fnBody.substring(loopStart, Math.min(fnBody.length, loopStart + 1500));
    const idxAccessRe = new RegExp(`\\b\\w+\\s*\\[\\s*${_esc(idxVar)}\\s*\\]`);
    if (!idxAccessRe.test(tail)) continue;
    const lineRel = _lineOfOffset(fnBody, m.index);
    const line = fnStart + lineRel - 1;
    findings.push({
      id: `cpp-flow:off-by-one:${line}`,
      severity: 'medium',
      cwe: 'CWE-193',
      family: 'buffer-overflow',
      line,
      vuln: 'Off-by-one in loop bound — inclusive comparison against length-typed variable',
      remediation: `Use \`<\` instead of \`<=\` when iterating up to an array length: \`for (int ${idxVar} = 0; ${idxVar} < ${boundVar}; ${idxVar}++)\`. The inclusive form iterates one past the last valid index.`,
      _parser: 'CPP_DATAFLOW',
    });
  }
  return findings;
}

export function scanCppDataflow(file, raw) {
  // Feature flag: off by default until scanner/test/cpp-dataflow.test.js
  // passes and fixture pairs exist under scanner/test/fixtures/cpp-dataflow/.
  // Enable with: AGENTIC_SECURITY_CPP_DATAFLOW=1
  if (!process.env.AGENTIC_SECURITY_CPP_DATAFLOW) return [];
  if (!CPP_EXT_RE.test(file) || !raw) return [];
  if (raw.length > 500_000) return [];               // very large files: skip
  const stripped = _blank(raw);
  const fns = _findFunctions(stripped);
  if (!fns.length) {
    // No detected function bodies — apply detectors over the whole file as
    // one pseudo-function so we don't miss BigVul-style fragmented patches.
    fns.push({ name: '__file__', startLine: 1, body: stripped });
  }
  const all = [];
  for (const fn of fns) {
    try {
      all.push(..._detectUseAfterFree(fn.body, fn.startLine));
      all.push(..._detectDoubleFree(fn.body, fn.startLine));
      all.push(..._detectMissingNullCheck(fn.body, fn.startLine));
      all.push(..._detectAllocSizeOverflow(fn.body, fn.startLine));
      all.push(..._detectOffByOne(fn.body, fn.startLine));
    } catch (err) {
      // Count parse failures so /status can surface them; never rethrow.
      _parseErrorCount.value++;
    }
  }
  for (const f of all) {
    f.file = file;
    f.kind = 'sast';
    if (!f.snippet) {
      const lines = raw.split('\n');
      f.snippet = (lines[f.line - 1] || '').trim().slice(0, 200);
    }
  }
  return all;
}

export const _internals = {
  _blank, _esc, _findFunctions, _detectUseAfterFree, _detectDoubleFree,
  _detectMissingNullCheck, _detectAllocSizeOverflow, _detectOffByOne,
};
