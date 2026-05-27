// Cache poisoning via tainted response headers.
//
// Detects reflected request headers in responses that CDNs/proxies key on.
// X-Forwarded-Host, X-Forwarded-Proto, X-Original-URL reflected into
// response headers or HTML body enables web cache poisoning attacks.

function _line(raw, idx) { return raw.slice(0, idx).split('\n').length; }

const CACHE_KEY_HEADERS = /x-forwarded-host|x-forwarded-proto|x-original-url|x-rewrite-url|x-forwarded-for|x-host/i;
const TAINT_SOURCES = /req\.headers|request\.headers|request\.META|getHeader|get_header|\$_SERVER/;

export function scanCachePoisoning(fp, raw) {
  if (!fp || !raw || typeof raw !== 'string') return [];
  if (raw.length > 500_000) return [];
  if (!/\.(?:js|jsx|ts|tsx|mjs|cjs|py|go|rb|php|phtml)$/i.test(fp)) return [];

  const findings = [];

  // Pattern 1: Reflected cache-key header in response
  // res.setHeader('X-Forwarded-Host', req.headers['x-forwarded-host'])
  const headerReflectRe = /(?:setHeader|set|header|add_header|Header\.Set|Header\.Add)\s*\(\s*['"]([^'"]+)['"]\s*,\s*[^)]*(?:req\.headers|request\.headers|request\.META|\$_SERVER)/g;
  for (const m of raw.matchAll(headerReflectRe)) {
    const headerName = m[1];
    if (!CACHE_KEY_HEADERS.test(headerName)) continue;
    const line = _line(raw, m.index);
    findings.push({
      id: `cache-poison-reflect:${fp}:${line}`,
      file: fp, line,
      vuln: `Cache Poisoning — ${headerName} reflected from request to response`,
      severity: 'high',
      family: 'cache-poisoning',
      cwe: 'CWE-349',
      parser: 'CACHE-POISON',
      confidence: 0.75,
      description: `The ${headerName} request header is reflected in the response. If a CDN or reverse proxy caches this response, an attacker can poison the cache for all users by sending a crafted ${headerName} value.`,
      remediation: `Don't reflect ${headerName} into the response. If you need the value for redirects, validate it against an allow-list of trusted hosts.`,
    });
  }

  // Pattern 2: Cache-Control or Vary set from user input
  const cacheControlTaintRe = /(?:Cache-Control|Vary)\s*['"]\s*,\s*[^)]*(?:req\.|request\.|params|query|body|\$_GET|\$_REQUEST)/g;
  for (const m of raw.matchAll(cacheControlTaintRe)) {
    const line = _line(raw, m.index);
    findings.push({
      id: `cache-poison-control:${fp}:${line}`,
      file: fp, line,
      vuln: 'Cache Poisoning — Cache-Control or Vary header set from user input',
      severity: 'high',
      family: 'cache-poisoning',
      cwe: 'CWE-349',
      parser: 'CACHE-POISON',
      confidence: 0.65,
      description: 'Cache-Control or Vary response header is derived from user input. An attacker can manipulate caching behavior to serve stale or poisoned content.',
      remediation: 'Set Cache-Control and Vary headers from server-side constants, never from user input.',
    });
  }

  // Pattern 3: Host header used in URL generation (redirect/link)
  const hostRedirectRe = /(?:req\.headers\.host|request\.get_host|request\.host|request\.META\s*\[\s*['"]HTTP_HOST['"])\s*[^;\n]*(?:redirect|location|href|url|link)/gi;
  for (const m of raw.matchAll(hostRedirectRe)) {
    const line = _line(raw, m.index);
    findings.push({
      id: `cache-poison-host:${fp}:${line}`,
      file: fp, line,
      vuln: 'Cache Poisoning — Host header used in URL/redirect generation',
      severity: 'medium',
      family: 'cache-poisoning',
      cwe: 'CWE-644',
      parser: 'CACHE-POISON',
      confidence: 0.60,
      description: 'The Host request header is used to generate URLs or redirects. Combined with caching, an attacker can redirect all cached users to a malicious host.',
      remediation: 'Use a server-configured base URL instead of the Host header. Validate Host against an allow-list.',
    });
  }

  return findings;
}
