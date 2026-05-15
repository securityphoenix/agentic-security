// Blast-radius and cost framing.
//
// Decorates each finding with a plain-English narrative of who/what is
// affected if it's exploited. Uses signals already extractable from the
// scan target — no LLM call, no network. The point is to translate
// "SQL Injection in /api/users" into "could leak ~all user records;
// est. fraud / breach cost $50k–$500k for ~5k users."
//
// Decoration shape:
//   blastRadius: {
//     scope: 'paying-users' | 'all-users' | 'admin-only' | 'public',
//     dataAtRisk: ['PII', 'payment', 'auth-tokens'],
//     userCount: 5000,         // estimated, may be null
//     dollarLow: 50000,
//     dollarHigh: 500000,
//     narrative: "SQL Injection on /api/users could leak ~5k user records ..."
//   }

import * as fs from 'node:fs';
import * as path from 'node:path';

// ── project-signal collection ────────────────────────────────────────────────

function readSafe(p) { try { return fs.readFileSync(p, 'utf8'); } catch { return ''; } }
function existsAny(root, files) { return files.some(f => fs.existsSync(path.join(root, f))); }

export function collectProjectSignals(scanRoot) {
  const sig = {
    hasStripe: false,
    hasAuth: false,
    hasUserTable: false,
    hasS3: false,
    hasPaymentRoute: false,
    hasAdminRoute: false,
    hasPII: false,
    hasPHI: false,
    hasSecrets: false,
    estimatedUsers: null,
    dependencies: new Set(),
  };

  // Manifest sweep — check what's actually installed.
  const manifests = [
    'package.json', 'requirements.txt', 'pyproject.toml',
    'Gemfile', 'go.mod', 'composer.json', 'Cargo.toml',
  ];
  for (const m of manifests) {
    const text = readSafe(path.join(scanRoot, m));
    if (!text) continue;
    if (/stripe|paddle|chargebee|square|braintree/i.test(text)) sig.hasStripe = true;
    if (/clerk|next-auth|@auth\/|lucia-auth|passport|firebase-auth|auth0|supabase/i.test(text)) sig.hasAuth = true;
    if (/aws-sdk|@aws-sdk\/client-s3|boto3|google-cloud-storage|@google-cloud\/storage/i.test(text)) sig.hasS3 = true;
    // Pull out a coarse dep list for dependency-aware framing.
    for (const m2 of text.matchAll(/"([\w@/-]+)"\s*:/g)) sig.dependencies.add(m2[1]);
  }

  // Schema/table heuristic — look at the first few likely files.
  for (const f of ['schema.prisma', 'prisma/schema.prisma', 'db/schema.ts', 'db/schema.js',
                   'supabase/migrations', 'migrations']) {
    const fp = path.join(scanRoot, f);
    if (!fs.existsSync(fp)) continue;
    let text = '';
    try {
      const stat = fs.statSync(fp);
      if (stat.isDirectory()) {
        const files = fs.readdirSync(fp).slice(0, 20);
        for (const sub of files) text += readSafe(path.join(fp, sub));
      } else text = readSafe(fp);
    } catch {}
    if (/\b(?:User|users|profiles?|accounts?)\b/.test(text)) sig.hasUserTable = true;
    if (/\b(?:email|phone|address|ssn|date_of_birth|dob)\b/i.test(text)) sig.hasPII = true;
    if (/\b(?:diagnosis|medical|patient|prescription|hipaa)\b/i.test(text)) sig.hasPHI = true;
    if (/\b(?:card|payment|invoice|charge|subscription|stripe_customer)\b/i.test(text)) sig.hasStripe = true;
  }

  // Secrets present in repo? Check .env files (we don't read values).
  for (const f of ['.env', '.env.local', '.env.production']) {
    if (fs.existsSync(path.join(scanRoot, f))) sig.hasSecrets = true;
  }

  return sig;
}

// ── narrative builder ────────────────────────────────────────────────────────

const VULN_DAMAGE = {
  'SQL Injection':                { scope: 'all-users', data: ['PII'], baseLow: 50_000, baseHigh: 500_000 },
  'NoSQL Injection':              { scope: 'all-users', data: ['PII'], baseLow: 30_000, baseHigh: 300_000 },
  'Command Injection':            { scope: 'all-users', data: ['secrets', 'PII'], baseLow: 100_000, baseHigh: 2_000_000 },
  'Path Traversal':               { scope: 'all-users', data: ['secrets', 'config'], baseLow: 20_000, baseHigh: 200_000 },
  'XSS':                          { scope: 'paying-users', data: ['auth-tokens'], baseLow: 10_000, baseHigh: 100_000 },
  'SSRF':                         { scope: 'all-users', data: ['cloud-metadata', 'internal-services'], baseLow: 50_000, baseHigh: 1_000_000 },
  'IDOR':                         { scope: 'all-users', data: ['PII', 'payment'], baseLow: 30_000, baseHigh: 300_000 },
  'Broken Authentication':        { scope: 'all-users', data: ['auth-tokens', 'PII'], baseLow: 50_000, baseHigh: 500_000 },
  'Broken Access Control':        { scope: 'all-users', data: ['PII', 'payment'], baseLow: 30_000, baseHigh: 300_000 },
  'Hardcoded Secret':             { scope: 'all-users', data: ['credentials'], baseLow: 20_000, baseHigh: 200_000 },
  'Insecure Deserialization':     { scope: 'all-users', data: ['rce'], baseLow: 100_000, baseHigh: 2_000_000 },
  'Prompt Injection':             { scope: 'all-users', data: ['model-behavior'], baseLow: 5_000, baseHigh: 100_000 },
  'Mass Assignment':              { scope: 'all-users', data: ['privilege-escalation'], baseLow: 20_000, baseHigh: 200_000 },
  'Open Redirect':                { scope: 'paying-users', data: ['phishing'], baseLow: 5_000, baseHigh: 50_000 },
  'Webhook Signature Missing':    { scope: 'paying-users', data: ['payment'], baseLow: 10_000, baseHigh: 500_000 },
  'Rate Limit Missing':           { scope: 'all-users', data: ['llm-cost', 'fraud'], baseLow: 1_000, baseHigh: 100_000 },
};

function vulnRow(vuln) {
  if (!vuln) return null;
  for (const k of Object.keys(VULN_DAMAGE)) {
    if (vuln.toLowerCase().includes(k.toLowerCase())) return { name: k, ...VULN_DAMAGE[k] };
  }
  return null;
}

function severityMultiplier(sev) {
  return { critical: 2.5, high: 1.5, medium: 1.0, low: 0.4, info: 0.1 }[sev] || 1.0;
}

function fmtMoney(n) {
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `$${Math.round(n / 1_000)}k`;
  return `$${n}`;
}

function buildNarrative(finding, signals) {
  const v = vulnRow(finding.vuln);
  if (!v) return null;
  const mult = severityMultiplier(finding.severity);
  let scope = v.scope;
  const data = [...v.data];

  // Refine scope using signals.
  if (signals.hasStripe && data.includes('payment')) scope = 'paying-users';
  if (signals.hasUserTable && (data.includes('PII') || data.includes('auth-tokens'))) {
    if (scope === 'paying-users' && !signals.hasStripe) scope = 'all-users';
  }
  if (signals.hasPHI) data.push('PHI');
  const file = (finding.file || '').toLowerCase();
  if (/admin|internal|backoffice/.test(file)) scope = 'admin-only';

  const dollarLow = Math.round(v.baseLow * mult);
  const dollarHigh = Math.round(v.baseHigh * mult);

  const userCount = signals.estimatedUsers || (scope === 'paying-users' ? 500 : scope === 'all-users' ? 5_000 : 100);

  // Build a one-line narrative the vibecoder can read.
  const dataPhrase =
    data.includes('rce') ? 'full server compromise (remote code execution)' :
    data.includes('payment') ? `payment data for ~${userCount.toLocaleString()} ${scope === 'paying-users' ? 'paying ' : ''}users` :
    data.includes('PII') ? `PII for ~${userCount.toLocaleString()} users` :
    data.includes('credentials') ? 'production credentials and API keys' :
    data.includes('auth-tokens') ? `session/auth tokens for ~${userCount.toLocaleString()} users` :
    data.includes('llm-cost') ? 'unbounded LLM API spend' :
    `${data[0]} exposure`;

  const line = finding.line || finding.source?.line || finding.sink?.line || 0;
  const narrative =
    `${v.name} on \`${finding.file}:${line}\` could ${data.includes('rce') ? 'lead to' : 'leak'} ${dataPhrase}. ` +
    `Estimated cost if exploited: ${fmtMoney(dollarLow)}–${fmtMoney(dollarHigh)} ` +
    `(breach response, regulatory, customer churn).`;

  return {
    scope,
    dataAtRisk: data,
    userCount,
    dollarLow,
    dollarHigh,
    narrative,
  };
}

// Decorate every finding (in scan.findings, scan.secrets, scan.supplyChain) in place.
export function enrichWithBlastRadius(scan, scanRoot) {
  const signals = collectProjectSignals(scanRoot || process.cwd());
  let decorated = 0;
  for (const bucket of ['findings', 'secrets', 'logicVulns', 'supplyChain']) {
    for (const f of (scan[bucket] || [])) {
      const br = buildNarrative(f, signals);
      if (br) { f.blastRadius = br; decorated++; }
    }
  }
  scan.blastRadiusSignals = {
    hasStripe: signals.hasStripe,
    hasAuth: signals.hasAuth,
    hasUserTable: signals.hasUserTable,
    hasPII: signals.hasPII,
    hasPHI: signals.hasPHI,
    hasS3: signals.hasS3,
  };
  return { decorated, signals };
}
