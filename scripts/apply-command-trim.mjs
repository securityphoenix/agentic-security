#!/usr/bin/env node
// One-shot rewrite of command frontmatter to hit the 120/200 caps.
// Tier 1 of the slash-command audit. Run once; the lint script keeps it
// honest going forward. Each rewrite preserves the verb + key value;
// detail moves to the body where it already lives.
//
// Usage:
//   node scripts/apply-command-trim.mjs           # dry-run report
//   node scripts/apply-command-trim.mjs --apply   # write the changes

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..');
const apply = process.argv.includes('--apply');

const REWRITES = {
  'commands/adversary.md': {
    description: 'Run the bounded-budget adversary-agent against ONE finding. Produces a hash-chained transcript of the attack run.',
  },
  'commands/ai-bodyguard.md': {
    description: 'Real-time AI-coding bodyguard. Intercepts insecure code AS the AI writes it, before disk. High-precision rules.',
  },
  'commands/archaeology.md': {
    description: 'Pre-incident archaeology — walks git history to answer "when did this codebase first become vulnerable?"',
  },
  'commands/attack-surface.md': {
    description: 'Plain-English narrative of your app\'s top attack scenarios. Written for builders, not security engineers.',
  },
  'commands/auth-audit.md': {
    description: 'Deep-audit your auth provider — Clerk / NextAuth / Auth0 / Lucia / generic OAuth for flags, secrets, CSRF gaps.',
  },
  'commands/bounty.md': {
    description: 'Predicted bug-bounty USD per finding (HackerOne / Bugcrowd / Immunefi shape). Scaled down for mitigations.',
  },
  'commands/compliance-fix.md': {
    description: 'Route every Not-Compliant control from /compliance-report to the command that closes it. Ordered, deduped.',
  },
  'commands/concurrency-bugs.md': {
    description: 'Surface concurrency bugs — missed unlocks, fire-and-forget async, 2-lock deadlock cycles. Go/Java/JS-TS/Py.',
  },
  'commands/csp-cors.md': {
    description: 'Generate exact CSP and CORS headers for your stack — reads your deps + config, outputs copy-paste headers.',
  },
  'commands/cve-alerts.md': {
    description: 'Real-time CVE push alerts for your dependency tree via Slack / Discord / webhook when a new CVE drops.',
  },
  'commands/daily-checkin.md': {
    description: 'Post a daily security digest to Slack / Discord / webhook. Async indie-builder security awareness.',
  },
  'commands/db-audit.md': {
    description: 'Audit DB security — Supabase RLS, raw SQL injection, exposed admin APIs, RLS-bypassing direct connections.',
  },
  'commands/dep-alternatives.md': {
    description: 'Identify heavy / high-risk deps with lighter native or actively-maintained alternatives. Shrinks attack surface.',
  },
  'commands/dep-pinning.md': {
    description: 'Audit dep manifests for loose version ranges that allow silent supply-chain injection. All ecosystems.',
  },
  'commands/deploy-check.md': {
    description: 'Platform-specific deploy checklist — Vercel / Railway / Fly.io / Render / Netlify / Cloudflare Workers.',
  },
  'commands/destructive-guard.md': {
    description: 'Intercept destructive Bash before it runs. Catches rm -rf, DROP TABLE, supabase db reset, force-push, more.',
  },
  'commands/diff-scan.md': {
    description: 'Differential scanner — run two scanner versions on the same tree and report the delta. Catches regressions.',
  },
  'commands/disaster-playbook.md': {
    description: 'Generate a stack-specific incident-response playbook BEFORE you get hacked. DISASTER.md with the right URLs.',
  },
  'commands/env-check.md': {
    description: 'Audit env-var hygiene — NEXT_PUBLIC_ leaks, real values in .env.example, hardcoded fallbacks, .gitignore.',
  },
  'commands/explain.md': {
    description: 'Explain a finding in plain English — what it means, how attackers abuse it, worst case, how to fix. --narrative for the story shape.',
    'argument-hint': '[--finding <id>] [--narrative]',
  },
  'commands/find-and-fix-everything.md': {
    description: 'Full /scan --all then /fix --all --low in one command. The vibecoder "just make it safe" path.',
  },
  'commands/fix.md': {
    description: 'Remediate findings. --one <id> patches one, --all batch-fixes by severity, --pr bundles into a pull request.',
  },
  'commands/harden.md': {
    description: 'One-command security hardening — safe infra fixes (security headers, .gitignore, cookie flags, npm audit).',
  },
  'commands/help.md': {
    description: 'List every command, ICP-segmented (Vibecoder / Pro / Both). Pick the lane that matches your role.',
  },
  'commands/install-hooks.md': {
    description: 'Install pre-commit + pre-push git hooks that run scoped scans. Blocks on new critical findings by default.',
  },
  'commands/install-script-audit.md': {
    description: 'Audit every npm package (direct + transitive) for postinstall / preinstall scripts — the supply-chain vector.',
  },
  'commands/jailbreak-detector.md': {
    description: 'Test an LLM endpoint against known jailbreak families (DAN, base64, role-play, authority, multilingual).',
  },
  'commands/launch-check.md': {
    description: 'Pre-deploy checklist of the 10 things beginners typically miss. Each item: green / yellow / red + one line.',
  },
  'commands/llm-cost-ceiling.md': {
    description: 'Audit LLM calls, auto-patch missing max_tokens, generate rate-limit middleware, emit daily $-spend tracker.',
  },
  'commands/llm-eval.md': {
    description: 'Generate a promptfoo-style YAML eval suite for an LLM endpoint. CI-ready with red-team prompts pre-loaded.',
  },
  'commands/llm-redteam.md': {
    description: 'Red-team your LLM endpoint — promptfoo-style adversarial tests across 30+ harm categories + 7 mutations.',
  },
  'commands/personas.md': {
    description: 'Per-attacker-persona prioritization — what script-kiddie / opportunistic / APT / insider would target first.',
  },
  'commands/playbook.md': {
    description: 'Pre-built attack playbooks for high+ findings — curl one-liners, Nuclei templates, multi-step probes.',
  },
  'commands/posture-management.md': {
    description: 'Posture management — SBOM, AI-BOM, API inventory, license policy, drift, MTTR. One flag per surface.',
    'argument-hint': '[--sbom | --aibom | --api | --license | --drift | --mttr]',
  },
  'commands/predeploy-gate.md': {
    description: 'Block production deploys when critical findings or KEV-listed deps are present. Wraps vercel/fly/wrangler.',
  },
  'commands/privacy-docs.md': {
    description: 'Generate a privacy-policy template + cookie banner from YOUR stack. Detects every third-party processor.',
  },
  'commands/prompt-firewall.md': {
    description: 'Audit LLM/AI app security — user input in system prompts, missing max_tokens, LLM output → SQL / code.',
  },
  'commands/query.md': {
    description: 'SentQL prompt — write a security check in natural language; assistant emits the YAML rule + preview.',
  },
  'commands/rate-limit-check.md': {
    description: 'Find API endpoints missing rate-limiting — auth / AI / payment / contact routes that can be abused.',
  },
  'commands/report-card.md': {
    description: 'Single letter-grade (A–F) of your project\'s security posture, with one explanation + one next action.',
  },
  'commands/risk-in-dollars.md': {
    description: 'Translate every finding into $ exposure (low / likely / high). Money language, not CVSS jargon.',
  },
  'commands/rotate-secret.md': {
    description: 'Rotate a leaked secret — guided steps for the detected provider. --auto runs the revoke + scrub end-to-end.',
    'argument-hint': '[--auto] [--scrub-history]',
  },
  'commands/scan-baseline.md': {
    description: 'Finding-level diff between two scan JSON outputs. Independent of scanner version. "What did this PR break?"',
  },
  'commands/scan.md': {
    description: 'Run the scanner. --all gives a one-screen verdict. Focused modes per surface; --show-X for supplementary blocks.',
    'argument-hint': '[path] [--all|--sca|--secrets|--authz|--mcp|--pipeline|--logic|--diff|--uncommitted] [--show-personas|--show-bounty|--show-playbook]',
  },
  'commands/security-onepager.md': {
    description: 'Customer-facing "How we keep your data safe" one-pager from your scan posture. For enterprise prospects.',
  },
  'commands/security-tests.md': {
    description: 'Generate failing security tests per finding + passing tests that prove the fix. In your project\'s framework.',
  },
  'commands/security-trend.md': {
    description: 'Regression scorecard — finding counts over time, intro vs fixed since last scan, which files regressed.',
  },
  'commands/self-test.md': {
    description: 'Adversarial self-test — scanner attacks itself. Mutates known-vuln fixtures and surfaces detector gaps.',
  },
  'commands/show-findings.md': {
    description: 'Triage + view findings. --all opens HTML report; --kev for weaponized CVEs; --chains for attack chains.',
    'argument-hint': '[--all|--kev|--chains|--threat-model [--stride|--llm]]',
  },
  'commands/social-media.md': {
    description: 'Copy-paste social posts about security progress (Twitter/X, LinkedIn, Discord/Slack). One command, three formats.',
  },
  'commands/spec-drift.md': {
    description: 'Spec-drift detector — functions whose names claim behavior the body doesn\'t deliver. validateOwnership(), sanitize().',
  },
  'commands/spof.md': {
    description: 'Single-point-of-failure analysis — which auth / sanitizer / CSRF middleware, if removed, exposes the most.',
  },
  'commands/stack-playbook.md': {
    description: 'Security playbook for your exact stack — opinionated copy-paste steps for the libraries you actually use.',
  },
  'commands/status.md': {
    description: 'One-screen project + plugin health snapshot — version, last scan, cache size, hook activation, suppressions.',
  },
  'commands/supply-chain-check.md': {
    description: 'One-screen supply-chain verdict. Rolls up dep CVE + KEV + pinning + install scripts + vendored code + freshness.',
    'argument-hint': '[--show pinning|freshness|alternatives|install-scripts|vendored]',
  },
  'commands/threat-model.md': {
    description: 'Auto-derived STRIDE threat model from last scan — assets, trust boundaries, per-category counts, top findings.',
  },
  'commands/three-agent-review.md': {
    description: 'Three-agent review of ONE finding — red (attack) / blue (hardening) / auditor. Hash-chained transcript trio.',
  },
  'commands/triage.md': {
    description: 'Interactive triage. Mark each finding TP / FP / wontfix. Feeds the active-learning loop for next scan.',
  },
  'commands/trust-boundary.md': {
    description: 'Auto-generated Mermaid diagram of trust boundaries — routes, queues, gRPC, DB edges, IaC, with findings overlaid.',
  },
  'commands/trust-page.md': {
    description: 'Generate /.well-known/security.txt + /security page showing LIVE posture (crit/high counts, streak, last scan).',
  },
  'commands/tutorial.md': {
    description: 'First-time-user walkthrough. Picks ONE real finding, explains, walks through fixing it together.',
  },
  'commands/validate-findings.md': {
    description: 'Validate a finding: build a PoC + regression test, optionally execute, emit a risk-context bundle. Refuses off-tree.',
    'argument-hint': '[--finding <id>] [--all] [--junit] [--execute]',
  },
  'commands/vault-wizard.md': {
    description: 'Guided migration from scattered env vars to a secrets vault (Doppler / Infisical / platform-native).',
  },
  'commands/vendor-audit.md': {
    description: 'Find copy-pasted / bundled third-party code vendored into the repo. Never updates; invisible to dep scanners.',
  },
  'commands/webhook-audit.md': {
    description: 'Audit webhook handlers for missing signature verification — Stripe, GitHub, Clerk, Svix, Resend, generic.',
  },
  'commands/why-fired.md': {
    description: 'Provenance graph for ONE finding — which detector, which rule, what evidence, which suppressions considered.',
  },
  'commands/why-not.md': {
    description: 'Recall spot-check for a CWE — show what the engine considered and why nothing fired. Surfaces catalog gaps.',
  },
  'skills/add-scan-rule/SKILL.md': {
    description: 'Walk through the six-step recipe for adding a new SAST detector — pick the module, export scan*(), wire, fixture, test.',
  },
  // ────────────────────────────────────────────────────────────────────────
  // Commands targeted by Tier 2 merges. We trim their descriptions here too
  // so the post-Tier-1 state is clean; the merge step then deletes / aliases
  // them in a separate pass.
  // ────────────────────────────────────────────────────────────────────────
  'commands/ci-gate.md': {
    description: 'Generate a CI security gate that fails the build on critical/high findings. --provider for GitLab/CircleCI/Buildkite/Jenkins.',
    'argument-hint': '[--provider github|gitlab|circleci|buildkite|jenkins] [--apply]',
  },
  'commands/ci-gate-multi.md': {
    description: 'Deprecated alias — use /ci-gate --provider <name>. Kept one release for muscle-memory.',
  },
  'commands/rotate-key-auto.md': {
    description: 'Deprecated alias — use /rotate-secret --auto. Kept one release for muscle-memory.',
  },
  'commands/story-explain.md': {
    description: 'Deprecated alias — use /explain --narrative. Kept one release for muscle-memory.',
  },
  'commands/trim-dead-code.md': {
    description: 'Find unused code — exports w/ zero callers, files w/ zero inbound imports. Multi-language. SAFE/CAUTION/DANGER tiers.',
  },
  'commands/trim-dependencies.md': {
    description: 'Find + remove installed deps never imported in source. Shrinks attack surface. --include-dead-code for both.',
    'argument-hint': '[--include-dead-code] [--apply]',
  },
};

function _trimFrontmatter(body, edits) {
  // Naive line-by-line replace inside frontmatter. We do NOT use a YAML
  // library — frontmatter here is single-line scalars by convention; full
  // YAML would over-engineer.
  if (!body.startsWith('---\n')) return { body, changed: false, reason: 'no-frontmatter' };
  const close = body.indexOf('\n---', 4);
  if (close < 0) return { body, changed: false, reason: 'unterminated-frontmatter' };
  const head = body.slice(0, close);
  const tail = body.slice(close);
  const lines = head.split('\n');
  let changed = false;
  for (let i = 0; i < lines.length; i++) {
    const m = /^([A-Za-z_][\w-]*)\s*:\s*(.*)$/.exec(lines[i]);
    if (!m) continue;
    const key = m[1];
    if (!(key in edits)) continue;
    const newVal = edits[key];
    // Preserve quoting style if the original had quotes. Otherwise emit bare.
    const orig = m[2].trim();
    const wasQuoted = (orig.startsWith('"') && orig.endsWith('"')) || (orig.startsWith("'") && orig.endsWith("'"));
    const quoteChar = wasQuoted ? orig[0] : '';
    const safeVal = quoteChar ? newVal.replace(new RegExp(quoteChar, 'g'), '\\' + quoteChar) : newVal;
    const rendered = quoteChar ? `${quoteChar}${safeVal}${quoteChar}` : newVal;
    lines[i] = `${key}: ${rendered}`;
    changed = true;
  }
  return { body: lines.join('\n') + tail, changed };
}

const report = [];
for (const [rel, edits] of Object.entries(REWRITES)) {
  const fp = path.join(REPO, rel);
  if (!fs.existsSync(fp)) { report.push({ rel, status: 'missing' }); continue; }
  const orig = fs.readFileSync(fp, 'utf8');
  const r = _trimFrontmatter(orig, edits);
  if (!r.changed) { report.push({ rel, status: r.reason || 'no-change' }); continue; }
  if (apply) {
    fs.writeFileSync(fp, r.body);
    report.push({ rel, status: 'applied' });
  } else {
    report.push({ rel, status: 'dry-run', dlen: edits.description?.length || 0 });
  }
}

console.log('\nRewrites:');
for (const r of report) console.log(`  ${r.status.padEnd(10)} ${r.rel}${r.dlen ? '  (desc=' + r.dlen + ')' : ''}`);
console.log(`\n${report.length} entries; ${apply ? 'applied' : 'dry-run only (pass --apply to write)'}.`);
