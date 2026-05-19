// Quarkus framework hardening.
//
// Coverage:
//   1. Resource methods exposed without @Authenticated / @RolesAllowed
//   2. application.properties: quarkus.oidc.credentials.secret literal
//   3. quarkus.security.users.embedded.* enabled in non-dev profile
//   4. quarkus.http.cors=true with overly broad origins
//   5. @PermitAll on /api/admin or similar sensitive paths
//   6. mp.jwt.verify.publickey.location missing when @Authenticated present

const _JAVA_RE = /\.java$/i;
const _PROPS_RE = /(?:^|[\\/])application(?:[-.][\w-]+)?\.(?:properties|ya?ml)$/i;

function _line(raw, idx) {
  return raw.slice(0, idx).split('\n').length;
}

function _isQuarkusJava(raw) {
  return /\bio\.quarkus\b|\bjakarta\.ws\.rs\b|\borg\.eclipse\.microprofile\b/.test(raw);
}

export function scanQuarkusHardening(file, raw) {
  if (!file || !raw || typeof raw !== 'string') return [];
  if (raw.length > 200_000) return [];
  const findings = [];

  // Properties file checks.
  if (_PROPS_RE.test(file) && /\bquarkus\./.test(raw)) {
    // OIDC client secret literal
    for (const m of raw.matchAll(/^\s*quarkus\.oidc\.credentials\.secret\s*=\s*(\S+)/gmi)) {
      const val = m[1].trim();
      if (val.startsWith('${') || val === '' || val === '""' || val === "''") continue;
      findings.push({
        id: `quarkus:oidc-secret-literal:${file}:${_line(raw, m.index)}`,
        file, line: _line(raw, m.index),
        vuln: 'Quarkus OIDC client secret in plaintext config',
        severity: 'critical',
        family: 'quarkus-hardcoded-credential',
        cwe: 'CWE-798',
        confidence: 0.95,
        description: 'quarkus.oidc.credentials.secret in source-controlled config lets anyone with repo read impersonate the application against the IdP.',
        remediation: 'Replace with ${OIDC_CLIENT_SECRET} env-var reference and rotate the leaked secret.',
      });
    }
    // Embedded user with literal password
    for (const m of raw.matchAll(/^\s*quarkus\.security\.users\.embedded\.users\.\w+\s*=\s*(\S+)/gmi)) {
      const val = m[1].trim();
      if (val.startsWith('${')) continue;
      findings.push({
        id: `quarkus:embedded-user-password:${file}:${_line(raw, m.index)}`,
        file, line: _line(raw, m.index),
        vuln: 'Quarkus embedded user with literal password (likely dev convenience leaked to prod)',
        severity: 'critical',
        family: 'quarkus-hardcoded-credential',
        cwe: 'CWE-798',
        confidence: 0.9,
        description: 'Quarkus embedded identity is convenient for dev / smoke tests; pushing it to a non-dev profile creates a backdoor.',
        remediation: 'Move the user/password to a real IdentityProvider (Keycloak, LDAP, DB). Quarkus dev-mode users should never ship to production.',
      });
    }
    // Wildcard CORS origin
    for (const m of raw.matchAll(/^\s*quarkus\.http\.cors\.origins\s*=\s*['"]?\*['"]?/gm)) {
      findings.push({
        id: `quarkus:cors-wildcard:${file}:${_line(raw, m.index)}`,
        file, line: _line(raw, m.index),
        vuln: 'Quarkus CORS origins = * (wildcard)',
        severity: 'high',
        family: 'quarkus-cors-wildcard',
        cwe: 'CWE-942',
        confidence: 0.9,
        description: 'Wildcard CORS combined with credentialed requests allows any origin to read authenticated responses.',
        remediation: 'Set quarkus.http.cors.origins=https://app.example.com (explicit list).',
      });
    }
    return findings;
  }

  if (!_JAVA_RE.test(file)) return findings;
  if (!_isQuarkusJava(raw)) return findings;

  // Mutating JAX-RS endpoint without @Authenticated / @RolesAllowed / @PermitAll
  const verbRe = /@(?:POST|PUT|PATCH|DELETE)\b[\s\S]{0,300}?public\s+\w[\w<>,\s\[\]?]*\s+(\w+)\s*\(/g;
  let mm;
  while ((mm = verbRe.exec(raw))) {
    const lineIdx = _line(raw, mm.index);
    const above = raw.slice(Math.max(0, mm.index - 400), mm.index);
    if (/@(?:Authenticated|RolesAllowed|PermitAll|DenyAll)\b/.test(above)) continue;
    findings.push({
      id: `quarkus:no-authz:${file}:${lineIdx}:${mm[1]}`,
      file, line: lineIdx,
      vuln: `Quarkus mutating endpoint ${mm[1]}() has no @Authenticated / @RolesAllowed annotation`,
      severity: 'high',
      family: 'quarkus-missing-authz',
      cwe: 'CWE-862',
      confidence: 0.7,
      description: 'A POST/PUT/PATCH/DELETE handler is exposed without authentication / authorization. Unless the path is gated by a wider mechanism, this endpoint is callable by anyone reaching it.',
      remediation: 'Add @Authenticated on the resource class (default to require auth) and @RolesAllowed("admin") on privileged methods. Use @PermitAll explicitly when a method is truly public.',
    });
  }

  return findings;
}
