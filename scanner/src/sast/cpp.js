// C / C++ memory-safety SAST module.
//
// Covers the OWASP C/C++ "banned-API" set: classic functions that are
// unsafe by design and have safer replacements. Patterns are syntactic —
// no taint analysis. Each rule has an optional `gate(ctx)` predicate that
// runs against the file/line context to suppress emissions outside the
// security-relevant context for that rule.
//
// Vuln families:
//   - buffer-overflow   strcpy, strcat, gets, sprintf (no `_s` / no `n`)
//   - format-string     printf/fprintf/syslog with a non-literal format arg
//   - command-injection system(<non-literal>) — userland exec via shell
//   - mem-unsafe        memcpy(dst, src, user_size) without bounds check
//                       alloca(user_size)
//   - rng-weak          rand() / srand(time(NULL)) for security
//   - hardcoded         hardcoded user/password in fopen / connect calls

import { blankComments } from './_comment-strip.js';

// ── context detectors ───────────────────────────────────────────────────────

// Files that #include any well-known crypto header — strong signal that
// rand()/srand() calls in this file are likely security-relevant.
const _CRYPTO_INCLUDE_RE = /#\s*include\s*[<"](?:openssl\/|sodium|sodium\.h|sodium\/|mbedtls\/|wolfssl\/|crypto\.h|gcrypt\.h|nettle\/|tomcrypt|bcrypt\.h|wincrypt\.h|bearssl|monocypher|s2n|botan)[^>"]*[>"]/i;

// Variable names that suggest the rand() output feeds something security-
// sensitive: tokens, keys, IVs, nonces, salts, session IDs, passwords.
// `\b` word boundaries so `iv` doesn't match `private`.
const _CRYPTO_VAR_RE = /\b(?:token|secret|password|passwd|pwd|cookie|session|sid|csrf|challenge|jwt|hmac|signature|sig|apikey|api_key|cryptoKey|cryptokey|encryption_key|cipher|nonce|salt|iv)\w*\b/i;

// Sensitive context for `rand()`: line-local evidence that the rand() value
// flows into a security-named target. Two acceptance conditions:
//   1. Same-line assignment: `token = ... rand()`, `key[i] = rand()`, etc.
//   2. Within 2 lines of the rand() call, a crypto-named variable receives
//      a value (handles `unsigned char *buf; for (...) buf[i] = rand();`
//      where `buf` is named cryptographically elsewhere).
//   3. File includes a crypto header AND window has crypto var hint.
// File-name signals are removed entirely — they over-fire on test corpora
// that happen to include "random"/"prng"/"crypto" in file or directory
// names, and they don't reflect whether THIS particular rand() call feeds
// crypto.
function _isCryptoContextRand(ctx) {
  const lines = ctx.raw.split('\n');
  // 5-line forward + 2-line back window from the rand() site. Forward
  // emphasis catches `int *buf = malloc(n); for (i=0;i<n;i++) buf[i] = rand();`
  // where the crypto-named target is declared above and used below.
  const startLine = Math.max(0, ctx.line - 3);
  const endLine = Math.min(lines.length, ctx.line + 5);
  const window = lines.slice(startLine, endLine).join('\n');
  // The rand call itself must appear in the window — sanity, since ctx.line
  // is 1-indexed.
  if (!/\b(?:rand|random|srand)\s*\(/.test(window)) return false;
  // Strong signal: an assignment in the window has a crypto-named LHS and
  // the same line also calls rand/random/srand. We check line-by-line.
  for (const line of window.split('\n')) {
    if (!/\b(?:rand|random|srand)\s*\(/.test(line)) continue;
    // Common shapes:
    //   token = rand();
    //   key[i] = rand() & 0xff;
    //   cookie = rand() % N;
    //   buf->token = rand();
    if (/\b(?:token|secret|password|passwd|pwd|cookie|session|sid|csrf|challenge|jwt|hmac|signature|sig|apikey|api_key|nonce|salt|iv|cipher|encryption_key|cryptoKey|cryptokey)\w*\s*(?:\[[^\]]*\]|\.\w+|->\w+)?\s*=/i.test(line)) {
      return true;
    }
  }
  // Medium signal: file includes a crypto header AND any crypto-named
  // identifier appears in the window (suggests flow into the crypto layer
  // even if not on the immediate lines).
  if (_CRYPTO_INCLUDE_RE.test(ctx.raw) && _CRYPTO_VAR_RE.test(window)) return true;
  return false;
}

// Defensive `sizeof(dst)` check on the destination of a strcpy/strcat. If the
// surrounding 3 lines guard the copy with `if (strlen(src) < sizeof(dst))` or
// equivalent, we can't say the call is unsafe.
const _SIZEOF_GUARD_RE = /\bsizeof\s*\(\s*\w+\s*\)|\bstrnlen\s*\(|\bsnprintf\s*\(/;
function _isStrcpyGuarded(ctx) {
  const lines = ctx.raw.split('\n');
  const start = Math.max(0, ctx.line - 4);
  const window = lines.slice(start, ctx.line).join(' ');
  return _SIZEOF_GUARD_RE.test(window);
}

// Format-string: only fire when the variable holding the format string was
// not assigned from a string literal earlier in the file.
function _isPrintfVarLiteral(ctx, varName) {
  if (!varName) return false;
  // Search for `varName = "literal"` or `const char *varName = "literal"` etc.
  const re = new RegExp(`\\b${varName}\\s*=\\s*"`, 'm');
  // Only consider assignments BEFORE the call (positional check).
  const before = ctx.raw.split('\n').slice(0, ctx.line - 1).join('\n');
  return re.test(before);
}

// ── rule table ──────────────────────────────────────────────────────────────

const FINDINGS = [
  // Banned string-handling: no upper bound. strcpy/strcat have safer _s
  // variants on Windows and strlcpy on BSD/macOS.
  {
    id: 'cpp-strcpy', severity: 'high', cwe: 'CWE-120', family: 'buffer-overflow',
    re: /\b(strcpy|strcat|gets|stpcpy|sprintf)\s*\(/g,
    vuln: 'Banned API — unbounded string copy/format (potential buffer overflow)',
    remediation: 'Replace with the bounded variant: strcpy → strlcpy / strcpy_s; strcat → strlcat / strcat_s; gets → fgets(buf, sizeof(buf), stdin); sprintf → snprintf(buf, sizeof(buf), "%s", v). The unbounded form will silently overflow on attacker-controlled input.',
    gate: (ctx) => !_isStrcpyGuarded(ctx),
  },
  {
    // printf/warn-family: format string is ARG 1.
    //   printf(fmt, ...)            ← fmt at position 1
    //   vprintf(fmt, ap)            ← fmt at position 1
    //   warn(fmt, ...)              ← BSD libc, fmt at position 1
    //   err(fmt, ...) / errx(fmt)   ← BSD libc, fmt at position 1
    id: 'cpp-printf-fmt', severity: 'high', cwe: 'CWE-134', family: 'format-string',
    re: /\b(?:printf|vprintf|warn(?:x)?|err(?:x)?)\s*\(\s*([a-zA-Z_]\w*|argv\[\d+\])\s*[,)]/g,
    vuln: 'Format string vulnerability — non-literal format argument',
    remediation: 'Always pass a literal format string: `printf("%s", user_input)` instead of `printf(user_input)`. A user-controlled `%n` / `%s` chain can read or write arbitrary memory.',
    gate: (ctx, m) => !_isPrintfVarLiteral(ctx, m && m[1]),
  },
  {
    // f-family: format string is ARG 2 — first arg is a FILE* or fd.
    //   fprintf(FILE*, fmt, ...)
    //   dprintf(fd, fmt, ...)
    //   vfprintf(FILE*, fmt, ap)
    //   vdprintf(fd, fmt, ap)
    // Match: function(<any-arg>, <fmt-var>, ...). The first arg can include
    // nested calls like `getstream()` — match anything up to the first
    // non-nested comma.
    id: 'cpp-fprintf-fmt', severity: 'high', cwe: 'CWE-134', family: 'format-string',
    re: /\b(?:fprintf|dprintf|vfprintf|vdprintf)\s*\(\s*[^,()]*(?:\([^)]*\))?[^,]*,\s*([a-zA-Z_]\w*|argv\[\d+\])\s*[,)]/g,
    vuln: 'Format string vulnerability — non-literal format argument',
    remediation: 'For fprintf/dprintf, the format string is the SECOND argument: pass a literal like `fprintf(stderr, "%s", user_input)` instead of `fprintf(stderr, user_input)`. A user-controlled `%n` / `%s` chain can read or write arbitrary memory.',
    gate: (ctx, m) => !_isPrintfVarLiteral(ctx, m && m[1]),
  },
  {
    // syslog/vsyslog: format string is ARG 2 — first arg is priority (int).
    //   syslog(priority, fmt, ...)
    //   vsyslog(priority, fmt, ap)
    id: 'cpp-syslog-fmt', severity: 'high', cwe: 'CWE-134', family: 'format-string',
    re: /\b(?:syslog|vsyslog)\s*\(\s*[^,]+,\s*([a-zA-Z_]\w*|argv\[\d+\])\s*[,)]/g,
    vuln: 'Format string vulnerability — non-literal format argument',
    remediation: 'For syslog, the format string is the SECOND argument: pass a literal like `syslog(LOG_INFO, "%s", user_input)` instead of `syslog(LOG_INFO, user_input)`.',
    gate: (ctx, m) => !_isPrintfVarLiteral(ctx, m && m[1]),
  },
  {
    // s-family: format string is ARG 2 for sprintf, ARG 3 for snprintf.
    //   sprintf(buf, fmt, ...)
    //   snprintf(buf, n, fmt, ...)
    //   vsprintf(buf, fmt, ap)
    //   vsnprintf(buf, n, fmt, ap)
    id: 'cpp-sprintf-fmt', severity: 'high', cwe: 'CWE-134', family: 'format-string',
    re: /\b(?:s(?:n)?printf|vs(?:n)?printf)\s*\(\s*[^,]+,(?:\s*[^,]+,)?\s*([a-zA-Z_]\w*|argv\[\d+\])\s*[,)]/g,
    vuln: 'Format string vulnerability — non-literal format argument',
    remediation: 'For sprintf/snprintf, the format string is the second/third argument: pass a literal format with placeholders rather than user-controlled data as the format itself.',
    gate: (ctx, m) => !_isPrintfVarLiteral(ctx, m && m[1]),
  },
  {
    id: 'cpp-system', severity: 'critical', cwe: 'CWE-78', family: 'command-injection',
    re: /\bsystem\s*\(\s*(?!["'])\w/g,
    vuln: 'Command Injection — system() with non-literal argument',
    remediation: 'Replace `system(cmd)` with `execve(...)` + fork(), passing the program and arguments as separate strings (no shell interpretation). When using system() with concatenated input, attacker-controlled `; rm -rf /` becomes literal shell.',
  },
  {
    id: 'cpp-popen', severity: 'critical', cwe: 'CWE-78', family: 'command-injection',
    re: /\bpopen\s*\(\s*(?!["'])\w/g,
    vuln: 'Command Injection — popen() with non-literal command',
    remediation: 'popen() invokes the shell. Use a fork()+execve() pattern with pipes instead, or use posix_spawn() with `posix_spawnattr_setflags(...)` and no shell.',
  },
  {
    id: 'cpp-memcpy-usersz', severity: 'high', cwe: 'CWE-787', family: 'mem-unsafe',
    // memcpy(dst, src, var) where var ends in _len/size/count and was assigned from input
    re: /\b(?:memcpy|memmove|bcopy)\s*\(\s*\w+\s*,\s*\w+\s*,\s*\w+(?:_len|_size|_count|Len|Size|Count|len|size|count)\s*\)/g,
    vuln: 'Memory-safety risk — memcpy/memmove with externally-controlled size',
    remediation: 'Validate the size against the destination buffer before copying: `if (n > sizeof(dst)) return -1;`. Better: use std::span (C++20) or use a typed copy that carries length, like strncpy_s with explicit destmax.',
  },
  {
    id: 'cpp-alloca', severity: 'medium', cwe: 'CWE-770', family: 'mem-unsafe',
    re: /\balloca\s*\(/g,
    vuln: 'Stack-allocation with user-controllable size (DoS / stack exhaustion)',
    remediation: 'alloca() allocates on the stack with no fault behaviour — a large or attacker-influenced size crashes the process or jumps the guard page. Use malloc()/free() or std::vector instead.',
  },
  {
    id: 'cpp-rand', severity: 'medium', cwe: 'CWE-338', family: 'weak-rng',
    re: /\b(?:rand|random|srand)\s*\(/g,
    vuln: 'Cryptographically weak PRNG (rand/random/srand)',
    remediation: 'rand() is a linear-congruential generator — predictable from a few outputs. For security use cases (tokens, IVs, salts), use a CSPRNG: getrandom() / RAND_bytes() / std::random_device + std::mt19937_64 seeded from /dev/urandom.',
    // Only fire in plausibly-cryptographic contexts. Outside crypto: rand()
    // is a normal language facility (test data, branch selection, jitter).
    gate: (ctx) => _isCryptoContextRand(ctx),
  },
  {
    id: 'cpp-srand-time', severity: 'high', cwe: 'CWE-338', family: 'weak-rng',
    re: /\bsrand\s*\(\s*time\s*\(\s*(?:NULL|nullptr|0)?\s*\)/g,
    vuln: 'Cryptographic randomness seeded from time() (fully predictable)',
    remediation: 'time() seeds are guessable to within ±1 second. For any security-sensitive RNG, seed from /dev/urandom or use OS-provided CSPRNG (getrandom() / BCryptGenRandom).',
    // Same gate — `srand(time(NULL))` outside a crypto context is just a
    // common (bad) example pattern, not a real vulnerability.
    gate: (ctx) => _isCryptoContextRand(ctx),
  },
];

function lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

export function scanCpp(fp, raw) {
  if (!/\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx)$/i.test(fp)) return [];
  if (!raw || raw.length > 500_000) return [];
  const code = blankComments(raw);
  // Skip pure header files that only declare functions / contain typedefs.
  // A header with no function calls is unlikely to be a useful target.
  if (/\.(?:h|hh|hpp|hxx)$/i.test(fp) && !/[A-Za-z_]\w*\s*\([^)]*\)\s*\{/.test(code)) return [];
  const out = [];
  const seen = new Set();
  for (const rule of FINDINGS) {
    const re = new RegExp(rule.re.source, rule.re.flags);
    let m;
    while ((m = re.exec(code))) {
      const line = lineOf(raw, m.index);
      const id = `${rule.id}:${fp}:${line}`;
      if (seen.has(id)) continue;
      seen.add(id);
      // Suppress when the match falls inside a #define macro line — those
      // are often re-declarations / wrappers in the same file.
      const lineText = (raw.split('\n')[line - 1] || '');
      if (/^\s*#\s*define\b/.test(lineText)) continue;
      // Per-rule contextual gate (Action 2). Suppress when the surrounding
      // file/line context shows the call is not security-relevant.
      if (typeof rule.gate === 'function') {
        try {
          if (!rule.gate({ file: fp, raw, line, lineText }, m)) continue;
        } catch { /* gate threw → fail open, keep finding */ }
      }
      out.push({
        id, file: fp, line,
        vuln: rule.vuln,
        severity: rule.severity,
        cwe: rule.cwe,
        stride: rule.family === 'buffer-overflow' || rule.family === 'mem-unsafe' ? 'Tampering'
              : rule.family === 'command-injection' ? 'Elevation of Privilege'
              : rule.family === 'format-string' ? 'Information Disclosure'
              : 'Spoofing',
        snippet: lineText.trim().slice(0, 200),
        remediation: rule.remediation,
        confidence: 0.85,
        parser: 'CPP',
      });
    }
  }
  return out;
}
