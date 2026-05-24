---
description: Stack-specific security audits — db, auth, rate-limit, webhook, env, csp-cors, deploy, launch, llm-cost, prompt.
argument-hint: "--target db|auth|rate-limit|webhook|env|csp-cors|deploy|launch|llm-cost|prompt [--all]"
---

Run a targeted security audit for one area of your stack. Pass `--all` to run every target in sequence.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
TARGET=""
RUN_ALL=""
for arg in "$@"; do
  case "$arg" in
    --target) TARGET="next" ;;
    --all) RUN_ALL="1" ;;
    *)
      [ "$TARGET" = "next" ] && TARGET="$arg" && continue
      [ -z "$TARGET" ] && TARGET="$arg"
      ;;
  esac
done

if [ -z "$TARGET" ] && [ -z "$RUN_ALL" ]; then
  echo ""
  echo "Usage: /audit --target <area>"
  echo ""
  echo "  Areas:"
  echo "    db           Supabase RLS, SQL injection, exposed admin APIs"
  echo "    auth         Clerk / NextAuth / Auth0 / Lucia / OAuth misconfig"
  echo "    rate-limit   Endpoints missing rate limiting"
  echo "    webhook      Missing signature verification (Stripe, GitHub, Clerk…)"
  echo "    env          NEXT_PUBLIC_ leaks, .env hygiene, hardcoded fallbacks"
  echo "    csp-cors     Generate CSP + CORS headers for your stack"
  echo "    deploy       Platform-specific (Vercel / Railway / Fly / Netlify / CF)"
  echo "    launch       Pre-launch 10-item checklist"
  echo "    llm-cost     Missing max_tokens, rate-limit middleware, spend tracker"
  echo "    prompt       Prompt injection, LLM output → SQL/exec, system prompt contamination"
  echo ""
  echo "  Or: /audit --all   to run every target"
  echo ""
  exit 0
fi

node -e "
const fs = require('fs');
const cp = require('child_process');
const W = (s, c) => process.stdout.isTTY ? \`\x1b[\${c}m\${s}\x1b[0m\` : s;
const BOLD='1', DIM='2', GREEN='32', YELLOW='33', RED='31';
const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const sevColor = { critical: '31;1', high: '31', medium: '33', low: '36', info: '2' };

let scan = null;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json', 'utf8')); } catch {}

const target = process.env.TARGET || '';
const runAll = process.env.RUN_ALL === '1';
const targets = runAll
  ? ['db','auth','rate-limit','webhook','env','csp-cors','deploy','launch','llm-cost','prompt']
  : [target];

// ── Filters per target ──

const FILTERS = {
  db: {
    title: 'Database Security Audit',
    match: f => {
      const prefixes = ['db-rls:', 'sql-injection', 'nosql', 'orm-raw'];
      return prefixes.some(p => (f.id || '').startsWith(p) || (f.vuln || '').includes(p.replace(/[-:]/g, ' '))) ||
        /supabase|rls|row.level|service.role|bypass.*rls|postgres.*handler/i.test(f.title || f.vuln || '');
    },
    checks: ['Supabase service-role key exposure','NEXT_PUBLIC_ vars leaking service keys','auth.admin API client-side','bypassRowLevelSecurity()','SQL tables without RLS','Raw PostgreSQL in request handlers','SQL injection patterns'],
  },
  auth: {
    title: 'Auth Provider Security Audit',
    match: f => {
      const prefixes = ['auth-provider:', 'authz:', 'jwt-exp:'];
      return prefixes.some(p => (f.id || '').startsWith(p)) ||
        /jwt|session fixation|oauth|pkce|csrf|algorithm confusion|alg.none|trust.host|clerk|nextauth|auth.*secret|cookie.+secure/i.test(f.title || f.vuln || '');
    },
    checks: ['allowDangerousEmailAccountLinking','trustHost: true (CSRF bypass)','Missing NEXTAUTH_SECRET','Weak or hardcoded session secrets','Hardcoded OAuth client secrets','CSRF protection disabled','Clerk: sensitive routes in publicRoutes','Session cookies without secure/sameSite','JWT alg:none / missing algorithms option','JWT without expiry'],
  },
  'rate-limit': {
    title: 'Rate Limiting Audit',
    match: f => (f.id || '').startsWith('rate-limit:') ||
      /rate.?limit|brute.?force|RATE_LIMIT/i.test(f.vuln || f.title || ''),
    checks: ['Auth endpoints missing rate limiting','AI endpoints (cost explosion risk)','Payment endpoints (card-testing)','Contact/form endpoints (spam)'],
  },
  webhook: {
    title: 'Webhook Security Audit',
    match: f => (f.id || '').startsWith('webhook:') ||
      /webhook.*signature|missing.*signature.*verify|CWE-345/i.test(f.title || f.vuln || ''),
    checks: ['Stripe (constructEvent)','GitHub (X-Hub-Signature-256 HMAC)','Clerk (verifyWebhook)','Svix (wh.verify)','Resend (verifyWebhookSignature)','Twilio (validateRequest)','Generic HMAC signature patterns'],
  },
  env: {
    title: 'Environment Hygiene Check',
    match: f => (f.id || '').startsWith('env-hygiene:') ||
      /NEXT_PUBLIC.*secret|env.*example.*real|dotenv.*prod|hardcoded.*fallback/i.test(f.title || ''),
    checks: ['.env files in .gitignore','.env files not committed to git','NEXT_PUBLIC_ vars for secret names','.env.example with real values','Hardcoded fallbacks in source'],
    extra: () => {
      const results = [];
      const gitignore = (() => { try { return fs.readFileSync('.gitignore', 'utf8'); } catch { return ''; } })();
      const envPatterns = ['.env', '.env.local', '.env.production', '.env.development'];
      const missing = envPatterns.filter(p => !gitignore.includes(p) && fs.existsSync(p));
      if (missing.length) results.push({ severity: 'critical', label: '.env files not in .gitignore', detail: missing.join(', ') + ' exist but are not excluded' });
      try {
        const tracked = cp.execSync('git ls-files', { encoding: 'utf8', stdio: ['ignore','pipe','ignore'] }).split('\\n').filter(l => /^\\.env(\\.|$)/i.test(l.trim()));
        if (tracked.length) results.push({ severity: 'critical', label: '.env files committed to git', detail: tracked.join(', ') });
      } catch {}
      const envFiles = ['.env', '.env.local', '.env.production', '.env.development', '.env.staging'];
      for (const ef of envFiles) {
        try {
          const content = fs.readFileSync(ef, 'utf8');
          const sensitivePublic = content.match(/^NEXT_PUBLIC_\\w*(?:SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL|PRIVATE|SIGNING|WEBHOOK|SALT)\\w*\\s*=/gim) || [];
          if (sensitivePublic.length) results.push({ severity: 'critical', label: ef + ': NEXT_PUBLIC_ secret variable', detail: sensitivePublic.slice(0, 3).map(m => m.split('=')[0].trim()).join(', ') + ' will be bundled into client JavaScript' });
        } catch {}
      }
      return results;
    },
  },
  deploy: {
    title: 'Deployment Platform Security Audit',
    match: f => (f.id || '').startsWith('deploy-platform:') ||
      /vercel|railway|fly\\.io|netlify|cloudflare|render|amplify|healthcheck|security.header|force.https|preview.deploy/i.test(f.title || f.vuln || ''),
    checks: ['Vercel: security headers, public preview deployments','Railway: health check configuration','Fly.io: HTTPS enforcement','Netlify: security headers','Cloudflare: compatibility_date'],
  },
  prompt: {
    title: 'Prompt Injection Firewall Audit',
    match: f => (f.id || '').startsWith('prompt-firewall:') ||
      /prompt.*inject|system.*prompt.*user|max.token|llm.*output.*sql|llm.*output.*exec|output.*validat|prompt.injection|LLM.*inject|user.*input.*prompt/i.test(f.title || f.vuln || ''),
    checks: ['User input in system prompts','Missing max_tokens cap','LLM output used as SQL/shell/eval input','Missing output schema validation','Prompt injection vectors'],
  },
};

// ── Generic renderer ──

function renderTarget(t) {
  const cfg = FILTERS[t];
  if (!cfg) return;

  console.log('');
  console.log(W(cfg.title, BOLD));
  console.log('');

  if (!scan) {
    console.log(W('  No scan found.', YELLOW) + ' Run /scan --all first, then /audit --target ' + t);
    return;
  }

  let findings = (scan.findings || []).filter(cfg.match);
  let extraIssues = cfg.extra ? cfg.extra() : [];

  if (findings.length === 0 && extraIssues.length === 0) {
    console.log(W('  ✓  No ' + t + ' security issues detected.', GREEN));
    if (cfg.checks) {
      console.log('');
      console.log('  Checked:');
      cfg.checks.forEach(c => console.log('  • ' + c));
    }
    console.log('');
    return;
  }

  findings.sort((a, b) => (sevOrder[a.severity] ?? 4) - (sevOrder[b.severity] ?? 4));

  for (const f of findings) {
    const color = sevColor[f.severity] || '0';
    console.log(W('[' + (f.severity || '?').toUpperCase() + ']', color) + '  ' + (f.title || f.vuln));
    console.log('  ' + f.file + (f.line ? ':' + f.line : ''));
    if (f.description) console.log('  ' + W(f.description.slice(0, 200), DIM));
    console.log('');
    if (f.remediation) console.log('  Fix: ' + f.remediation.slice(0, 300));
    console.log('');
  }

  for (const issue of extraIssues) {
    const c = sevColor[issue.severity] || '0';
    console.log(W('[' + (issue.severity || '?').toUpperCase() + ']', c) + '  ' + issue.label);
    if (issue.detail) console.log('  ' + W(issue.detail, DIM));
    console.log('');
  }

  const all = [...findings, ...extraIssues.map(e => ({ severity: e.severity }))];
  const crit = all.filter(f => f.severity === 'critical').length;
  const high = all.filter(f => f.severity === 'high').length;
  console.log(W('Summary', BOLD));
  console.log('  ' + all.length + ' finding(s) — ' + crit + ' critical, ' + high + ' high');
  console.log('');
}

// ── csp-cors is different: outputs JSON for Claude to generate policies ──

function renderCspCors() {
  console.log('');
  console.log(W('CSP & CORS Generator', BOLD));
  console.log('');
  const pkg = (() => { try { return JSON.parse(fs.readFileSync('package.json','utf8')); } catch { return null; } })();
  const deps = pkg ? { ...(pkg.dependencies||{}), ...(pkg.devDependencies||{}) } : {};
  const d = n => Object.keys(deps).some(k => k.toLowerCase().includes(n.toLowerCase()));
  const sources = {
    stripe: d('stripe'), supabase: d('@supabase'), clerk: d('clerk') || d('@clerk'),
    resend: d('resend'), openai: d('openai'), anthropic: d('@anthropic-ai'),
    google: d('@google'), mapbox: d('mapbox'), twilio: d('twilio'),
    analytics: d('@segment') || d('mixpanel') || d('posthog') || d('@vercel/analytics'),
    sentry: d('@sentry'),
  };
  console.log('Stack detected:');
  Object.entries(sources).filter(([,v])=>v).forEach(([k])=>console.log('  • ' + k));
  console.log('');
  console.log(JSON.stringify({
    framework: d('next') ? 'nextjs' : d('express') ? 'express' : d('fastify') ? 'fastify' : d('hono') ? 'hono' : 'unknown',
    externalServices: Object.entries(sources).filter(([,v])=>v).map(([k])=>k),
    hasNextConfig: fs.existsSync('next.config.js') || fs.existsSync('next.config.ts') || fs.existsSync('next.config.mjs'),
  }, null, 2));
}

// ── launch is different: 10-item checklist ──

function renderLaunch() {
  console.log('');
  console.log(W('Pre-launch checklist (10 items)', BOLD));
  console.log('');
  if (!scan) { console.log(W('No scan yet.', YELLOW) + ' Run /scan --all first.'); return; }

  const findings = scan.findings || [];
  const routes = scan.routes || [];
  const pkg = (() => { try { return JSON.parse(fs.readFileSync('package.json','utf8')); } catch { return null; } })();
  const allDeps = pkg ? { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) } : {};
  const hasDep = n => Object.keys(allDeps).some(k => k.toLowerCase() === n.toLowerCase());
  const gitignore = (() => { try { return fs.readFileSync('.gitignore', 'utf8'); } catch { return ''; } })();
  const envInGit = (() => { try { return cp.execSync('git ls-files', { encoding: 'utf8', stdio: ['ignore','pipe','ignore'] }).split('\\n').some(l => /^\\.?env(\\..*)?\$/.test(l.trim())); } catch { return null; } })();
  const fm = m => findings.filter(f => m.test(f.vuln || '') || m.test(f.cwe || ''));

  const checks = [];
  const hardcoded = fm(/CWE-798|hardcoded.+(secret|key|token|password)/i).length;
  checks.push({ ok: hardcoded === 0, label: 'No hardcoded secrets in source', detail: hardcoded === 0 ? 'No API keys/tokens/passwords found.' : hardcoded + ' hardcoded credential(s). Move to env vars and rotate.' });
  const envIgnored = /^\\s*\\.?env(\\..*)?\$/m.test(gitignore) || /^\\s*\\*\\.env/m.test(gitignore);
  checks.push({ ok: envIgnored, label: '.env is in .gitignore', detail: envIgnored ? '.env is excluded from git.' : 'Add .env to .gitignore.' });
  checks.push({ ok: envInGit === false, warn: envInGit === null, label: '.env not committed', detail: envInGit === false ? 'No .env files are tracked.' : envInGit ? '.env files ARE tracked in git.' : 'Could not check.' });
  const sensitiveUnauth = routes.filter(r => !r.hasAuth && r.method !== 'GET' && r.method !== 'HEAD').length;
  checks.push({ ok: sensitiveUnauth === 0, warn: sensitiveUnauth > 0 && sensitiveUnauth <= 2, label: 'State-changing routes require auth', detail: sensitiveUnauth === 0 ? 'All state-changing endpoints have auth.' : sensitiveUnauth + ' POST/PUT/DELETE route(s) without auth.' });
  const rlIssues = fm(/rate.?limit/i).length;
  const hasRL = hasDep('express-rate-limit') || hasDep('@upstash/ratelimit') || hasDep('rate-limiter-flexible');
  checks.push({ ok: hasRL || rlIssues === 0, warn: !hasRL && rlIssues > 0, label: 'Rate limiting on auth endpoints', detail: hasRL ? 'Rate-limit library detected.' : rlIssues > 0 ? rlIssues + ' route(s) flagged.' : 'No auth routes detected.' });
  const hasHelmet = hasDep('helmet') || hasDep('@fastify/helmet');
  const isWebApp = allDeps.express || allDeps.koa || allDeps.fastify || allDeps.hono;
  checks.push({ ok: hasHelmet || !isWebApp, warn: !hasHelmet && !!isWebApp, label: 'Security headers (Helmet)', detail: hasHelmet ? 'Helmet configured.' : !isWebApp ? 'Not a web app server.' : 'No helmet. npm install helmet.' });
  const cookieIssues = fm(/cookie.+(secure|httponly|samesite|missing flag)/i).length;
  checks.push({ ok: cookieIssues === 0, label: 'Cookies use Secure/HttpOnly/SameSite', detail: cookieIssues === 0 ? 'No cookie flag issues.' : cookieIssues + ' cookie(s) missing flags.' });
  const permissiveCORS = fm(/cors.+(permissive|wildcard|origin.+\\*)/i).length;
  checks.push({ ok: permissiveCORS === 0, label: 'CORS restricted to allow-list', detail: permissiveCORS === 0 ? 'No permissive CORS.' : permissiveCORS + ' route(s) with CORS \"*\".' });
  const kevFindings = findings.filter(f => f.kev === true).length;
  checks.push({ ok: kevFindings === 0, label: 'No actively-abused CVEs (CISA KEV)', detail: kevFindings === 0 ? 'No KEV-listed CVEs.' : kevFindings + ' CVE(s) being weaponized.' });
  const crit = findings.filter(f => f.severity === 'critical').length;
  checks.push({ ok: crit === 0, label: 'No critical findings', detail: crit === 0 ? 'Zero critical findings — safe to ship.' : crit + ' critical finding(s).' });

  let pass = 0, warn = 0, fail = 0;
  for (const c of checks) {
    let icon, color;
    if (c.ok) { icon = '✓'; color = GREEN; pass++; }
    else if (c.warn) { icon = '⚠'; color = YELLOW; warn++; }
    else { icon = '✗'; color = RED; fail++; }
    console.log('  ' + W(icon, color) + '  ' + c.label);
    console.log('       ' + W(c.detail, DIM));
    console.log('');
  }
  console.log(W('Summary', BOLD));
  const verdict = fail === 0 && warn === 0 ? W('Ready to ship ✓', GREEN) : fail === 0 ? W('Ship with caution', YELLOW) + ' — ' + warn + ' warning(s)' : W('Not ready', RED) + ' — ' + fail + ' blocker(s)';
  console.log('  Passing: ' + pass + '/' + checks.length + '. ' + verdict + '.');
  console.log('');
  if (fail === 0 && warn === 0) {
    try {
      const sp = '.agentic-security/streak.json';
      let s = {}; try { s = JSON.parse(fs.readFileSync(sp, 'utf8')); } catch {}
      s.launchCheckPassedAt = new Date().toISOString();
      s.achievements = Array.from(new Set([...(s.achievements || []), 'launch-ready']));
      fs.mkdirSync('.agentic-security', { recursive: true });
      fs.writeFileSync(sp, JSON.stringify(s, null, 2));
    } catch {}
  }
}

// ── llm-cost is different: delegates to Python script ──

function renderLlmCost() {
  console.log('');
  console.log(W('LLM Cost Ceiling Audit', BOLD));
  console.log('');
  console.log('This target audits your LLM calls for missing max_tokens caps.');
  console.log('');
  console.log(JSON.stringify({
    target: 'llm-cost',
    modes: ['--audit (default)', '--apply (auto-patch)', '--generate-middleware', '--generate-tracker --daily-cap 50'],
  }, null, 2));
}

// ── Dispatch ──

for (const t of targets) {
  if (t === 'csp-cors') renderCspCors();
  else if (t === 'launch') renderLaunch();
  else if (t === 'llm-cost') renderLlmCost();
  else if (FILTERS[t]) renderTarget(t);
  else {
    console.log(W('Unknown target: ' + t, RED));
    console.log('  Valid targets: db, auth, rate-limit, webhook, env, csp-cors, deploy, launch, llm-cost, prompt');
  }
}

console.log('');
console.log('  Fix all:    /fix --all');
console.log('  Fix one:    /fix --one <finding-id>');
console.log('  Validate:   /validate-findings <finding-id>');
console.log('');
" TARGET="$TARGET" RUN_ALL="${RUN_ALL:-0}"
```

For `--target csp-cors`: Using the JSON above, generate a Content-Security-Policy header value and CORS configuration tailored to the detected stack. Output copy-paste-ready code blocks for the framework (Next.js `headers()`, Express `cors()`, or `vercel.json` `headers` array).

For `--target llm-cost`: Run `python3 ${CLAUDE_PLUGIN_ROOT}/scripts/llm-cost-ceiling.py` with the user's flags. Offer to auto-patch uncapped calls with `--apply`.

Review each finding carefully. Critical findings should be fixed before the next deploy.
