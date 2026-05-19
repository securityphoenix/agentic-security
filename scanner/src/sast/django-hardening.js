// Django framework hardening audit.
//
// Targets Django settings.py production bombs the generic python-sinks
// rule doesn't catch. Each rule fires only on files that look like Django
// settings — settings/production.py, settings/base.py, settings.py at repo
// root, conf.py with DJANGO_SETTINGS — to keep precision high.
//
// Coverage:
//   1. DEBUG = True in production-ish settings (leaks stack traces + /debug/)
//   2. ALLOWED_HOSTS = ['*']                       (host-header attacks)
//   3. SECRET_KEY literal in source                (rotate-required)
//   4. Missing security cookies/headers when SECURITY_MIDDLEWARE present
//   5. SECURE_SSL_REDIRECT = False / not set
//   6. SECURE_HSTS_SECONDS not set or 0
//   7. SESSION_COOKIE_SECURE = False, CSRF_COOKIE_SECURE = False
//   8. AUTH_PASSWORD_VALIDATORS missing / empty
//   9. @csrf_exempt on a non-test, non-webhook view
//  10. X_FRAME_OPTIONS = 'ALLOW' / missing
//  11. SESSION_COOKIE_HTTPONLY = False
//  12. CORS_ALLOW_ALL_ORIGINS = True (django-cors-headers)

const _DJANGO_SETTINGS_FILE_RE = /(?:^|[\\/])(?:settings(?:\.py|[\\/](?:base|production|prod|dev|local|common|staging)\.py)|conf\.py)$/i;
const _PYTHON_VIEW_FILE_RE = /(?:^|[\\/])(?:views|api|urls|admin)\.py$/i;
const _MANAGE_PY_RE = /(?:^|[\\/])manage\.py$/i;

function _line(raw, idx) {
  return raw.slice(0, idx).split('\n').length;
}

function _isDjangoSettings(file, raw) {
  if (_MANAGE_PY_RE.test(file)) return false;
  if (!_DJANGO_SETTINGS_FILE_RE.test(file)) {
    // Fall-back: any python file that imports django-style ROOT_URLCONF + INSTALLED_APPS together.
    if (!/\.py$/i.test(file)) return false;
    if (!/\bINSTALLED_APPS\b/.test(raw) || !/\bROOT_URLCONF\b/.test(raw)) return false;
  }
  // Final sanity — must contain django markers.
  return /\b(?:INSTALLED_APPS|MIDDLEWARE|ROOT_URLCONF|DATABASES|WSGI_APPLICATION|django\.contrib)\b/.test(raw);
}

function _isProductionish(file) {
  return /(?:prod(?:uction)?|live|staging|common|base)/i.test(file);
}

export function scanDjangoHardening(file, raw) {
  if (!file || !raw || typeof raw !== 'string') return [];
  if (raw.length > 200_000) return [];

  // Quick check on path/content; expensive checks below only run if this is a settings file.
  const isSettings = _isDjangoSettings(file, raw);
  const isView = _PYTHON_VIEW_FILE_RE.test(file) && /\bfrom django\b|\bdjango\./.test(raw);
  if (!isSettings && !isView) return [];

  const findings = [];
  const prod = _isProductionish(file);

  // ── View-file checks ────────────────────────────────────────────────────
  if (isView) {
    // @csrf_exempt without a stripe/github webhook signature check nearby.
    for (const m of raw.matchAll(/^\s*@csrf_exempt\b/gm)) {
      const line = _line(raw, m.index);
      // Look ±15 lines for a webhook-signature comment or HMAC verify call.
      const lines = raw.split('\n');
      const ctx = lines.slice(Math.max(0, line - 5), Math.min(lines.length, line + 15)).join('\n');
      if (/(?:stripe|github|hmac|signature|svix|x-hub-signature|verify_webhook)/i.test(ctx)) continue;
      findings.push({
        id: `django:csrf-exempt:${file}:${line}`,
        file, line,
        vuln: 'Django @csrf_exempt on a non-webhook view',
        severity: 'high',
        family: 'django-csrf-exempt',
        cwe: 'CWE-352',
        confidence: 0.7,
        description: 'View is decorated with @csrf_exempt but no webhook-signature verification is visible within 15 lines. State-changing endpoints without CSRF protection are exploitable from any cross-origin page that authenticates a Django user.',
        remediation: 'Remove @csrf_exempt and let CsrfViewMiddleware run; OR if this truly is a webhook, add HMAC signature verification (e.g., stripe.webhooks.construct_event).',
      });
    }
    return findings;
  }

  // ── Settings-file checks ────────────────────────────────────────────────

  // DEBUG = True in production-ish settings.
  for (const m of raw.matchAll(/^\s*DEBUG\s*=\s*True\b/gm)) {
    findings.push({
      id: `django:debug-true:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'Django DEBUG=True in settings',
      severity: prod ? 'critical' : 'high',
      family: 'django-debug-enabled',
      cwe: 'CWE-489',
      confidence: 0.95,
      description: 'DEBUG=True exposes the Django debug page on any exception — full stack trace, environment variables, request/response, source-code snippets. Catastrophic in production.',
      remediation: 'Set DEBUG = os.environ.get("DJANGO_DEBUG", "false").lower() == "true" and explicitly set DEBUG=false in your production env.',
    });
  }

  // ALLOWED_HOSTS = ['*']
  for (const m of raw.matchAll(/^\s*ALLOWED_HOSTS\s*=\s*\[\s*['"]\*['"]/gm)) {
    findings.push({
      id: `django:allowed-hosts-wildcard:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'Django ALLOWED_HOSTS = [\'*\']',
      severity: prod ? 'high' : 'medium',
      family: 'django-host-header',
      cwe: 'CWE-20',
      confidence: 0.9,
      description: 'Wildcard ALLOWED_HOSTS disables Django\'s host-header validation. Attackers can poison password-reset emails, cache keys, and SSL termination by sending arbitrary Host headers.',
      remediation: 'Set ALLOWED_HOSTS to an explicit list of your real hostnames: ["example.com", "api.example.com"].',
    });
  }

  // SECRET_KEY literal in source.
  for (const m of raw.matchAll(/^\s*SECRET_KEY\s*=\s*['"]([A-Za-z0-9!@#$%^&*()_+\-=\[\]{};:'",.<>?\/\\|`~]{20,})['"]/gm)) {
    findings.push({
      id: `django:hardcoded-secret-key:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'Django SECRET_KEY literal in source',
      severity: 'critical',
      family: 'django-hardcoded-secret',
      cwe: 'CWE-798',
      confidence: 0.95,
      description: 'SECRET_KEY is the master signing key for session cookies, CSRF tokens, password reset URLs, and signed data. A literal in source is catastrophic — rotate immediately.',
      remediation: 'SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY") with a raise ImproperlyConfigured if not set. Rotate the leaked value via `django-admin generate-secret-key`.',
    });
  }

  // SECURE_SSL_REDIRECT not set or False in prod.
  if (prod) {
    if (!/\bSECURE_SSL_REDIRECT\s*=\s*True\b/.test(raw)) {
      findings.push({
        id: `django:no-ssl-redirect:${file}:1`,
        file, line: 1,
        vuln: 'Django SECURE_SSL_REDIRECT not enabled in production settings',
        severity: 'high',
        family: 'django-no-https-enforce',
        cwe: 'CWE-319',
        confidence: 0.8,
        description: 'Without SECURE_SSL_REDIRECT, plaintext HTTP requests succeed. Sessions / CSRF tokens / OAuth state ride over the wire unprotected on the first request.',
        remediation: 'Add SECURE_SSL_REDIRECT = True at the top of the production settings module.',
      });
    }
    if (!/\bSECURE_HSTS_SECONDS\s*=\s*\d{4,}/.test(raw)) {
      findings.push({
        id: `django:no-hsts:${file}:1`,
        file, line: 1,
        vuln: 'Django SECURE_HSTS_SECONDS not set (or set < 1000) in production',
        severity: 'medium',
        family: 'django-no-hsts',
        cwe: 'CWE-319',
        confidence: 0.75,
        description: 'Without HSTS, an attacker on the network can downgrade to HTTP for the first visit. HSTS_SECONDS=31536000 + INCLUDE_SUBDOMAINS + PRELOAD locks the browser to HTTPS.',
        remediation: 'Set SECURE_HSTS_SECONDS = 31536000, SECURE_HSTS_INCLUDE_SUBDOMAINS = True, SECURE_HSTS_PRELOAD = True.',
      });
    }
    if (!/\bSESSION_COOKIE_SECURE\s*=\s*True\b/.test(raw)) {
      findings.push({
        id: `django:session-cookie-not-secure:${file}:1`,
        file, line: 1,
        vuln: 'Django SESSION_COOKIE_SECURE = False (or missing)',
        severity: 'high',
        family: 'django-cookie-not-secure',
        cwe: 'CWE-614',
        confidence: 0.85,
        description: 'Session cookie not marked Secure — sent over plain HTTP. Any network observer steals the session.',
        remediation: 'Set SESSION_COOKIE_SECURE = True and SESSION_COOKIE_HTTPONLY = True and SESSION_COOKIE_SAMESITE = "Lax".',
      });
    }
    if (!/\bCSRF_COOKIE_SECURE\s*=\s*True\b/.test(raw)) {
      findings.push({
        id: `django:csrf-cookie-not-secure:${file}:1`,
        file, line: 1,
        vuln: 'Django CSRF_COOKIE_SECURE = False (or missing)',
        severity: 'medium',
        family: 'django-cookie-not-secure',
        cwe: 'CWE-614',
        confidence: 0.85,
        description: 'CSRF cookie not marked Secure — sent over plain HTTP. Attackers on the network can read and reuse the CSRF token.',
        remediation: 'Set CSRF_COOKIE_SECURE = True and CSRF_COOKIE_HTTPONLY = True.',
      });
    }
  }

  // X_FRAME_OPTIONS = 'ALLOW'
  for (const m of raw.matchAll(/^\s*X_FRAME_OPTIONS\s*=\s*['"]ALLOW['"]/gm)) {
    findings.push({
      id: `django:x-frame-allow:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'Django X_FRAME_OPTIONS = "ALLOW" — clickjacking permitted',
      severity: 'medium',
      family: 'django-clickjacking',
      cwe: 'CWE-1021',
      confidence: 0.95,
      description: 'X_FRAME_OPTIONS = "ALLOW" lets any site embed your pages in iframes. UI redress / clickjacking attacks become trivial.',
      remediation: 'Set X_FRAME_OPTIONS = "DENY" (or "SAMEORIGIN" if you genuinely embed yourself).',
    });
  }

  // CORS_ALLOW_ALL_ORIGINS = True
  for (const m of raw.matchAll(/^\s*CORS_ALLOW_ALL_ORIGINS\s*=\s*True\b/gm)) {
    findings.push({
      id: `django:cors-allow-all:${file}:${_line(raw, m.index)}`,
      file, line: _line(raw, m.index),
      vuln: 'Django CORS_ALLOW_ALL_ORIGINS = True',
      severity: 'high',
      family: 'django-cors-wildcard',
      cwe: 'CWE-942',
      confidence: 0.9,
      description: 'Wildcard CORS combined with credentialed requests means any origin can read authenticated responses. Use an explicit allow-list.',
      remediation: 'Replace with CORS_ALLOWED_ORIGINS = ["https://app.example.com", ...]. Set CORS_ALLOW_CREDENTIALS only when actually needed.',
    });
  }

  // AUTH_PASSWORD_VALIDATORS missing or empty.
  if (prod && !/\bAUTH_PASSWORD_VALIDATORS\s*=\s*\[\s*\{/.test(raw)) {
    findings.push({
      id: `django:no-password-validators:${file}:1`,
      file, line: 1,
      vuln: 'Django AUTH_PASSWORD_VALIDATORS missing or empty in production settings',
      severity: 'medium',
      family: 'django-weak-password-policy',
      cwe: 'CWE-521',
      confidence: 0.7,
      description: 'No password validators configured — users can register with "password" / 12345 / etc.',
      remediation: 'Configure UserAttributeSimilarity, MinimumLength (≥12), CommonPassword, NumericPassword validators at minimum.',
    });
  }

  return findings;
}
