// Spring Boot framework hardening.
//
// Extends the general Java SAST with Spring-specific annotation-level
// audits. Targets controllers, security configurations, and the
// application.properties / application.yml that ship with Spring Boot apps.
//
// Coverage:
//   1. @RestController / @Controller class with mutating endpoints
//      (POST/PUT/PATCH/DELETE) missing @PreAuthorize / @Secured / @RolesAllowed
//   2. SecurityFilterChain with .permitAll() on /admin/** or /api/**
//   3. @CrossOrigin(origins = "*") (or allow-all credentials combo)
//   4. application.properties / application.yml with literal credentials
//   5. application.properties spring.security.user.password=
//   6. Missing @EnableMethodSecurity / @EnableGlobalMethodSecurity
//   7. JWT filter that skips signature verification (decodes only)
//   8. management.endpoints.web.exposure.include=* (Actuator exposed)

const _JAVA_RE = /\.java$/i;
const _SPRING_PROPS_RE = /(?:^|[\\/])application(?:[-.][\w-]+)?\.(?:properties|ya?ml)$/i;

const _SPRING_CTL_ANN_RE = /@(?:RestController|Controller)\b/;
const _SPRING_MAPPING_RE = /@(?:Get|Post|Put|Patch|Delete|Request)Mapping\b/;
const _MUTATING_RE = /@(?:Post|Put|Patch|Delete)Mapping\b/;
const _AUTHZ_ANN_RE = /@(?:PreAuthorize|PostAuthorize|Secured|RolesAllowed|PermitAll)\b/;

function _line(raw, idx) {
  return raw.slice(0, idx).split('\n').length;
}

function _isSpringJavaFile(raw) {
  return /\bimport\s+org\.springframework\b/.test(raw) || /\b@SpringBoot|@RestController|@Controller|@Service|@Repository\b/.test(raw);
}

export function scanSpringbootHardening(file, raw) {
  if (!file || !raw || typeof raw !== 'string') return [];
  if (raw.length > 300_000) return [];

  const findings = [];

  // ── application.properties / .yml checks ────────────────────────────────
  if (_SPRING_PROPS_RE.test(file)) {
    // spring.security.user.password= literal (default in-memory user with a real password)
    for (const m of raw.matchAll(/^\s*spring\.security\.user\.password\s*[=:]\s*(?!(?:\$\{|---|''|""|\s*$))(\S+)/gm)) {
      findings.push({
        id: `springboot:default-user-password:${file}:${_line(raw, m.index)}`,
        file, line: _line(raw, m.index),
        vuln: 'Spring Boot application.properties: spring.security.user.password set to a literal',
        severity: 'critical',
        family: 'springboot-hardcoded-credential',
        cwe: 'CWE-798',
        confidence: 0.9,
        description: 'Spring Security\'s in-memory default user is enabled with a hardcoded password. Anyone who reads the property file gets admin access in dev/staging — and these files frequently ship to production by mistake.',
        remediation: 'Use spring.security.user.password=${ADMIN_PASSWORD} pulled from env. Better: replace the default user with a real UserDetailsService backed by your identity store.',
      });
    }
    // OIDC client secret literal
    for (const m of raw.matchAll(/^\s*(?:quarkus\.oidc\.credentials\.secret|spring\.security\.oauth2\.client\.registration\.\w+\.client-secret)\s*[=:]\s*(\S{12,})/gm)) {
      const val = m[1];
      if (val.startsWith('${') || val === '""' || val === "''") continue;
      findings.push({
        id: `springboot:oidc-secret-literal:${file}:${_line(raw, m.index)}`,
        file, line: _line(raw, m.index),
        vuln: 'OIDC client secret in plaintext config',
        severity: 'critical',
        family: 'springboot-hardcoded-credential',
        cwe: 'CWE-798',
        confidence: 0.9,
        description: 'An OIDC / OAuth2 client secret is in a config file checked into source control. Anyone with repo read can impersonate the application against the IdP.',
        remediation: 'Replace with ${OIDC_CLIENT_SECRET} env-var reference. Rotate the leaked secret immediately at the IdP.',
      });
    }
    // Actuator endpoints exposed via wildcard
    if (/^\s*management\.endpoints\.web\.exposure\.include\s*[=:]\s*['"]?\*/.test(raw)) {
      const m = /^\s*management\.endpoints\.web\.exposure\.include\s*[=:]\s*['"]?\*/.exec(raw);
      findings.push({
        id: `springboot:actuator-exposed:${file}:${_line(raw, m.index)}`,
        file, line: _line(raw, m.index),
        vuln: 'Spring Actuator endpoints exposed via wildcard (management.endpoints.web.exposure.include=*)',
        severity: 'high',
        family: 'springboot-actuator-exposed',
        cwe: 'CWE-200',
        confidence: 0.95,
        description: 'Wildcard Actuator exposure makes /actuator/env, /heapdump, /threaddump, /loggers reachable. /env leaks process environment variables (including database passwords); /heapdump dumps the JVM heap.',
        remediation: 'Set management.endpoints.web.exposure.include=health,info (or whatever specific ones you need). Bind Actuator to a separate port behind a private network.',
      });
    }
    return findings;
  }

  // ── Java source checks ──────────────────────────────────────────────────
  if (!_JAVA_RE.test(file)) return [];
  if (!_isSpringJavaFile(raw)) return [];

  // 1. Controllers with mutating endpoints missing authz annotation
  if (_SPRING_CTL_ANN_RE.test(raw) && _MUTATING_RE.test(raw)) {
    // Find each method annotated with mutating mapping; check if @PreAuthorize / @Secured / @RolesAllowed sits above it.
    const methodRe = /(@(?:Post|Put|Patch|Delete)Mapping\b[^\n]*\n(?:[^\n]*\n){0,4})((?:[^{}]|\{[^{}]*\})*?)public\s+\w[\w<>,\s\[\]?]*\s+(\w+)\s*\(/g;
    let mm;
    while ((mm = methodRe.exec(raw))) {
      const block = mm[0];
      const methodName = mm[3];
      const lineIdx = _line(raw, mm.index);
      // Search 6 lines upward for an authz annotation
      const above = raw.slice(Math.max(0, mm.index - 400), mm.index);
      if (_AUTHZ_ANN_RE.test(above)) continue;
      // Skip GET-style "list" methods that might legitimately be public.
      // (We only matched mutating verbs anyway, so this is just for safety.)
      findings.push({
        id: `springboot:no-authz:${file}:${lineIdx}:${methodName}`,
        file, line: lineIdx,
        vuln: `Mutating endpoint ${methodName}() has no @PreAuthorize / @Secured / @RolesAllowed`,
        severity: 'high',
        family: 'springboot-missing-authz',
        cwe: 'CWE-862',
        confidence: 0.75,
        description: 'A POST/PUT/PATCH/DELETE handler is exposed without any authorization annotation. Unless the entire URL prefix is gated by SecurityFilterChain (and explicitly), this endpoint is callable by anyone who reaches it.',
        remediation: 'Add @PreAuthorize("hasRole(\'ADMIN\')") or @Secured("ROLE_ADMIN") above the method; or rely on a SecurityFilterChain rule and prove the path is covered.',
      });
      void block;
    }
  }

  // 2. SecurityFilterChain with permitAll() on /admin/** or /api/**
  for (const m of raw.matchAll(/\.requestMatchers\s*\(\s*['"]([^'"]*\/(?:admin|api|internal)\/[^'"]*)['"][^)]*\)[^)]*\.permitAll\s*\(\s*\)/g)) {
    findings.push({
      id: `springboot:permitAll-admin:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: `Spring Security permitAll() on a sensitive path: ${m[1]}`,
      severity: 'critical',
      family: 'springboot-permitall-sensitive',
      cwe: 'CWE-862',
      confidence: 0.9,
      description: 'A path matcher that looks like an administrative or API surface is being permitAll-ed in the security filter chain. Anyone reaching it bypasses auth entirely.',
      remediation: 'Replace .permitAll() with .hasRole(\'ADMIN\') (or whatever role applies). If the path is genuinely public, narrow the matcher so it cannot match real admin URLs.',
    });
  }

  // 3. @CrossOrigin(origins = "*")
  for (const m of raw.matchAll(/@CrossOrigin\s*\(\s*[^)]*origins\s*=\s*['"]?\*['"]?[^)]*\)/g)) {
    findings.push({
      id: `springboot:cors-wildcard:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: '@CrossOrigin(origins = "*") allows any origin',
      severity: 'high',
      family: 'springboot-cors-wildcard',
      cwe: 'CWE-942',
      confidence: 0.9,
      description: 'Wildcard CORS combined with credentialed requests means any origin can read authenticated responses. Even without credentials, it broadens the API\'s exposure to scraping and abuse.',
      remediation: 'Replace with origins = {"https://app.example.com"}. If credentials are involved, the wildcard is rejected by browsers anyway, so be explicit.',
    });
  }

  // 4. Missing @EnableMethodSecurity in @Configuration class that uses @PreAuthorize elsewhere
  if (/@Configuration\b/.test(raw) && _AUTHZ_ANN_RE.test(raw) &&
      !/@EnableMethodSecurity|@EnableGlobalMethodSecurity/.test(raw)) {
    const m = /@Configuration\b/.exec(raw);
    findings.push({
      id: `springboot:method-security-disabled:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'Spring @Configuration uses @PreAuthorize but @EnableMethodSecurity is not declared',
      severity: 'high',
      family: 'springboot-method-security-disabled',
      cwe: 'CWE-862',
      confidence: 0.6,
      description: 'Method-level authorization annotations (@PreAuthorize / @Secured / @RolesAllowed) are NO-OPS unless @EnableMethodSecurity (Spring Security 6+) or @EnableGlobalMethodSecurity (older) is on a @Configuration class.',
      remediation: 'Add @EnableMethodSecurity (Spring Security 6+) on a @Configuration class.',
    });
  }

  // 5. JWT decode without verify — JWT.decode(token) instead of JWT.require(...).build().verify(token)
  for (const m of raw.matchAll(/\bJWT\s*\.\s*decode\s*\(/g)) {
    findings.push({
      id: `springboot:jwt-decode-only:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'JWT.decode() used — does NOT verify the signature',
      severity: 'critical',
      family: 'springboot-jwt-no-verify',
      cwe: 'CWE-347',
      confidence: 0.85,
      description: 'JWT.decode() returns the decoded claims without verifying the signature. An attacker can craft a token with any claims they want — including elevated roles — and it will be accepted.',
      remediation: 'Use JWT.require(Algorithm.HMAC256(secret)).build().verify(token), or Spring Security\'s JwtDecoder / JwtAuthenticationToken.',
    });
  }

  return findings;
}
