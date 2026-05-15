# agentic-security

### The Claude Code Plugin that Catches what your AI Assistant Misses.

> Built by **[Clear Capabilities](https://www.clearcapabilities.com/products/agentic-security)**

[![License](https://img.shields.io/badge/license-PolyForm--Internal--Use-blue)](./LICENSE)
[![Tests](https://img.shields.io/badge/tests-96%2F96-brightgreen)]()
[![F1](https://img.shields.io/badge/F1%20benchmark-100%25-brightgreen)]()
[![Bundle](https://img.shields.io/badge/bundle-2.30MB-orange)]()
[![Version](https://img.shields.io/badge/version-0.35.0-blue)]()

---

## Why you need this

Your AI is fast. It's also writing security bugs.

This morning Claude wrote your login route in 9 seconds. Beautiful code. Tests pass.

It also lets anyone in the world log in as admin with a single line of curl.

You don't know this yet. Neither does Claude.

**One command finds it. One command fixes it.**

That command lives inside Claude Code, runs locally on your laptop, and explains every finding in plain English.

---

## Install

In **Claude Code** (recommended — gets you the slash commands):

```
/plugin marketplace add https://github.com/Clear-Capabilities/agentic-security
```

That's it. Type `/agentic-security:scan --all` to confirm it's working.

For **CI, terminal, or any project anywhere** (no Claude Code required):

```bash
npx @clearcapabilities/agentic-security-scanner scan .
```

The scanner runs entirely on your machine. Nothing leaves your laptop. No signups, no API keys, no cloud.

---

## Two modes. One tool.

Both modes run the same engine. They differ in how much you see and how much you can configure.

### 🎨 Easy Mode

Four commands. The whole product. The default for everyone.

---

#### `/agentic-security:scan --all` runs 12 different scans to secure your code:

```
       Pillar         What we scan
       ─────────────────────────────────────────────────────────────
       SAST           Taint analysis (regex + AST for JS/TS), Java
                      rule pack, Python helpers. 25+ language-specific
                      modules covering SQL injection, XSS, command
                      injection, XXE, JNDI, deserialization, zip-slip,
                      JWT flaws, auth misconfig, Supabase RLS, rate-
                      limit gaps, env hygiene, webhook verification,
                      React client-side XSS, and LLM prompt firewall.
       SCA            OSV + CISA KEV + EPSS, function-level
                      reachability, dep confusion, typosquat,
                      deprecated packages (npm, PyPI, Packagist,
                      crates.io, RubyGems, pub.dev).
       Secrets        60+ credential patterns, high-entropy heuristic,
                      allowlist-aware.
       IaC            Dockerfile, docker-compose, GitHub Actions,
                      Kubernetes manifests.
       LLM            OWASP LLM Top 10 (2025): prompt injection,
                      sensitive disclosure, supply chain, data/model
                      poisoning, improper output handling, excessive
                      agency, system prompt leakage, vector & embedding
                      weakness, misinformation prompts, unbounded
                      consumption. Benchmarked against AIGoat + LLMGoat.
       MCP            Agent-tool audit for over-privileged MCP servers.
       Pipeline       GitHub Actions integrity: floating tags,
                      secret echoes, OIDC misconfig.
       Auth/AuthZ     Broken access control, IDOR, mass assignment,
                      session fixation, OAuth/PKCE, multi-tenant scope.
       Container      Base-image EOL, exposed ports, runtime mode.
       Deploy         Vercel, Railway, Fly.io, Netlify, Cloudflare —
                      security headers, HTTPS, preview deployments.
       Stack          Opinionated security playbook for Next.js,
                      Supabase, Stripe, Clerk, Prisma, OpenAI, and 10+
                      more frameworks — specific to what you actually use.
       Trend          Rolling scan history — fixed vs. introduced delta
                      across every commit, sparkline view.
```

A one-screen verdict. Either you're safe to ship, or you have a short list of things to fix.

```
─────────────────────────────────────────
  ✅  Safe to deploy
─────────────────────────────────────────
```

…or, when there's work to do:

```
─────────────────────────────────────────
  ❌  Not safe to deploy
─────────────────────────────────────────
  • 31 critical · 73 high · 149 advisory

  How many do you want to fix?

     1. Critical only                (31 fixes)
     2. Critical + High              (104 fixes)
     3. Critical + High + Medium     (253 fixes)

  Reply with 1, 2, or 3.

  Or pick a single one:
     /agentic-security:show-findings --all  see every finding in HTML
     /agentic-security:fix --one <id>       fix exactly one
```

---

#### `/agentic-security:show-findings --all`

Writes a self-contained HTML report to `reports/findings-<timestamp>.html` and opens it in your default browser. Severity charts, filterable findings list, per-finding evidence with offending code snippet, and the proposed fix template. No external assets, no network required — works offline.

---

#### `/agentic-security:fix --all`

Pick a severity tier; `/fix --all` dispatches the security-fixer agent on every finding at or above it. Tiers are **cumulative** — `--high` patches critical + high. Sequential, test-aware, codebase-context-aware (detects your auth library, ORM, and framework before writing the fix).

| Flag | Fixes |
|---|---|
| `--critical` (default) | Critical only |
| `--high` | Critical + High |
| `--medium` | Critical + High + Medium |
| `--low` | Everything |

---

#### `/agentic-security:find-and-fix-everything`

Runs `/scan --all` then immediately `/fix --all --low` — scanning and fixing every finding at every severity tier in one shot.

---

### ⚙️ Developer Mode

Beyond the four Easy Mode commands, the toolkit splits into two audiences. Pick the section that matches you.

---

### 🎨 For Vibecoders / Builders

You're shipping fast with an AI assistant. You don't have a security team. You want plain English, one-button fixes, and someone yelling at you before you push a `.env` to GitHub.

#### Understand what's wrong (in English)

| Command | Description |
|---|---|
| `/agentic-security:secure` | Smart router. Inspects project state and tells you the single best next action — no menu, no choice paralysis. Add `--launch` for pre-deploy intent. |
| `/agentic-security:explain` | Plain-English explanation of a finding — what it means, how an attacker abuses it, worst case, and the fix. |
| `/agentic-security:story-explain` | "Meet Mallory. She visits `/api/users`, changes `?id=1` to `?id=2`…" 4-act narrative with attacker, timeline, payloads, and fix line. |
| `/agentic-security:attack-surface` | 3–5 realistic attack scenarios written like stories. No CVE IDs. |
| `/agentic-security:risk-in-dollars` | Each finding's best/likely/worst-case $ exposure, sourced from real incident settlements. Cites GDPR / CCPA / HIPAA / NIST AI 600-1 fines. |
| **Blast-radius narrative** (auto-on) | Every finding stamped with who's affected, what data is at risk, and a $-cost band — inferred from your actual stack signals (Stripe, auth, schema). |
| `/agentic-security:report-card` | Single A–F letter grade with one concrete next action. |
| `/agentic-security:tutorial` | First-run walkthrough: picks one real finding from your project, explains it, walks you through fixing it, verifies it. |

#### Fix things, safely

| Command | Description |
|---|---|
| `/agentic-security:fix --all` | Pick a tier (`--critical` / `--high` / `--medium` / `--low`); the security-fixer agent patches each one, sequential, test-aware, codebase-context-aware. |
| `agentic-security fix --finding <id> --preview` | Unified-diff preview before any write. `--apply` writes and backs up the original. |
| `agentic-security undo [--all\|--list]` | Atomic revert for the most recent applied fix. Safer than `git stash` for partial rollbacks. |
| `/agentic-security:harden` | One-command hardening: security headers, `.gitignore`, `SECURITY.md`, `npm audit` script. Idempotent. |
| `/agentic-security:rotate-secret` | Detects which provider owns a leaked key, finds every reference, gives platform-specific rotation steps. |
| `/agentic-security:rotate-key-auto` | Goes further: actually revokes, scrubs the value across files, and pushes the replacement to Vercel/Fly/Railway/Cloudflare env vars via CLI. |
| `/agentic-security:vault-wizard` | Guided migration from `.env` to Doppler, Infisical, or platform-native secrets. |

#### Hardening for the stack you actually use

| Command | Description |
|---|---|
| `/agentic-security:stack-playbook` | Copy-paste-ready security checklist for Next.js, Supabase, Stripe, Clerk, OpenAI, Prisma, and 10+ more — specific to your combination. |
| `/agentic-security:db-audit` | Supabase RLS audit — service-role exposure, `auth.admin` client-side, missing RLS. |
| `/agentic-security:auth-audit` | Clerk / NextAuth / Auth0 / Lucia — public-route leaks, `trustHost`, missing `NEXTAUTH_SECRET`, CSRF gaps. |
| `/agentic-security:rate-limit-check` | Find auth, AI, payment, and contact endpoints missing rate limits. Copy-paste `@upstash/ratelimit` setup included. |
| `/agentic-security:webhook-audit` | Webhook handlers missing signature verification — Stripe, GitHub, Clerk, Svix, Resend, Twilio. |
| `/agentic-security:env-check` | `NEXT_PUBLIC_` leaks, `.env.example` with real values, hardcoded fallbacks, `.env` not gitignored. |
| `/agentic-security:csp-cors` | Generates exact CSP + CORS headers for your stack from your actual dependency list. |
| `/agentic-security:prompt-firewall` | LLM app gaps: user input in system prompts, missing `max_tokens`, LLM-output→SQL, no output validation. |
| `/agentic-security:llm-cost-ceiling` | Auto-patches missing `max_tokens`; generates rate-limit middleware + daily $-spend tracker that throws when capped. |
| `/agentic-security:deploy-check` | Vercel / Railway / Fly / Netlify / Cloudflare Workers — security headers, HTTPS enforcement, preview-deployment leaks. |
| `/agentic-security:launch-check` | The 10 things builders typically miss before going live. |

#### Real-time bodyguards

Set once. Run forever. Active protection at the moment code is written or commands are run.

| Command | Description |
|---|---|
| `/agentic-security:ai-bodyguard` | PreToolUse hook that intercepts insecure AI-generated code BEFORE it hits disk. SQLi-via-concat, hardcoded API keys, `eval` on user input, `jwt.decode()` without verify, service-role on the client, LLM calls without `max_tokens`. Modes: `off` / `warn` / `block`. |
| `/agentic-security:destructive-guard` | PreToolUse hook on `Bash` blocking foot-guns: `rm -rf` on parents, `DROP TABLE`, `git push --force` to main, `curl \| bash`, `chmod 777`, and 8+ more. Plain-English why + safer alternative on every refusal. |
| `/agentic-security:predeploy-gate` | Blocks production deploys when critical findings or KEV-listed deps are present. Bash hook + sourced shell wrapper. |
| `/agentic-security:cve-alerts` | Daily CVE push to Slack/Discord when new vulnerabilities drop for your dependencies. |
| `/agentic-security:daily-checkin` | Daily digest of what changed since yesterday — new, resolved, KEV alerts. Slack / Discord / generic webhook. |

#### Things to hand a customer or investor

| Command | Description |
|---|---|
| `/agentic-security:security-badge` | Shields.io badge for your README + due-diligence-ready security posture paragraph. |
| `/agentic-security:security-onepager` | Customer-facing "How we keep your data safe" page generated from your real posture. PDF-ready. |
| `/agentic-security:privacy-docs` | Detects every third-party data processor (Stripe, Supabase, Clerk, Sentry, OpenAI, …) and generates a tailored `PRIVACY.md` + cookie-consent component. Jurisdiction-aware. |
| `/agentic-security:trust-page` | Writes `/.well-known/security.txt` (RFC 9116) + a `/security` page with your live posture. Framework-aware. |
| `/agentic-security:disaster-playbook` | Stack-specific `DISASTER.md` with EXACT commands you'll need if you get hacked tomorrow. Bookmark it BEFORE the incident. |
| `/agentic-security:social-media` | Copy-paste-ready posts (Twitter/X, LinkedIn, Discord/Slack) about your security progress. |

---

### 🔧 For Security Pros / Engineers

You triage findings for a living. You need depth, customization, integration into your existing workflow, and audit-defensible artifacts.

#### Deep scanning, validation, and reporting

| Command | Description |
|---|---|
| `/agentic-security:scan` | Full SAST + SCA + secrets sweep. Focused modes: `--sca`, `--secrets`, `--authz`, `--mcp`, `--pipeline`, `--logic`, `--diff`. SARIF + JSON + CSV written every scan. |
| `agentic-security scan --pr [ref]` | Diff-aware: only scan files changed since the PR base. Auto-detects GitHub / GitLab / Buildkite / Bitbucket env vars. |
| `agentic-security scan --deterministic` | Reproducible mode: stable-sorts findings, zeros timing/scanId, forces `--no-network`, verifies `rules.lock.json`. Required for byte-stable CI baselines. |
| `agentic-security rules lock` | Pin the active rule-pack hash + scanner version in `.agentic-security/rules.lock.json`. |
| `/agentic-security:show-findings` | Triage UI. `--all` opens an interactive HTML report. `--kev` filters to weaponized CVEs, `--chains` shows attack chains, `--threat-model [--stride\|--llm]` builds a model. |
| `/agentic-security:validate-findings` | Build a PoC + regression test that proves a vulnerability before fixing. Emits `PROBABLE_FP` when no PoC can be constructed. |
| **EPSS enrichment** (auto-on) | Every CVE finding decorated with EPSS score + percentile (FIRST.org). Percentile ≥ 95% gets `exploited-now` tag and one-tier severity bump. Disable with `--no-epss`. |

#### Customization and rule authoring

| Command | Description |
|---|---|
| `agentic-security rule list \| test <glob>` | Author custom YAML rules in `.agentic-security/rules/*.yml` (Semgrep-lite: regex / allOf / notMatch / window). The `rule test` harness reports PASS / FAIL on `vulnerable/` + `clean/` fixture pairs. |
| `agentic-security rules validate` | Lint `.agentic-security/rules.yml` for schema errors, invalid regex, severity overrides, disabled rules. |
| `agentic-security packs list` | Curated rule packs: `owasp-top-10`, `cwe-top-25`, `llm-security`, `supply-chain`. Activate with `--pack`. |

#### Integrations and workflow

| Command | Description |
|---|---|
| `agentic-security tickets sync --provider github\|linear\|jira` | Two-way sync findings ↔ tickets. Creates issues for new findings, closes tickets when findings drop. State in `.agentic-security/tickets.json`. Supports `--dry-run`. |
| `/agentic-security:fix --pr` | Bundle fixes into a feature branch and open a PR. Default dry-run; `--apply` to commit. Skips tests-failing fixes; never amends or force-pushes. |
| `/agentic-security:ci-gate` | Generates `.github/workflows/security.yml` — runs on every PR, uploads SARIF to GitHub Security tab, posts PR comments, fails on critical/high. |
| `agentic-security org-scan --repos <list>` | Fleet scan across N repos with bounded concurrency. Per-repo + rolled-up JSON output. |
| `agentic-security triage list \| assign \| transition \| trend` | Per-finding state machine with MTTR + opened/closed deltas. Persists to `.agentic-security/triage.json`. |
| `/agentic-security:security-trend` | Rolling trend line: fixed vs. introduced delta across scans, sparkline, regression detection. |

#### LLM red-teaming

| Command | Description |
|---|---|
| `/agentic-security:llm-redteam` | Send 30+ adversarial prompts (security, privacy, harmful, bias, misinformation, agentic, coding-agent) through your LLM endpoint with 7 attack-strategy mutations (DAN, base64, ROT13, role-play, authority, hypothetical, multilingual, chained-context). Static `--scan` mode catches missing defenses without making any LLM calls. |
| `/agentic-security:jailbreak-detector` | Faster focused subset — runs the canonical "make this harmful" prompt through each known jailbreak family. Reports DEFENDED / JAILBROKEN / PARTIAL per family. |
| `/agentic-security:llm-eval` | Generate a [promptfoo](https://www.promptfoo.dev)-compatible YAML eval suite committable to your repo as a CI gate. |

#### Dependency, supply chain, and posture

| Command | Description |
|---|---|
| `/agentic-security:posture-management` | SBOM, AI-BOM, API inventory, license policy, drift, MTTR / SLA tracking. |
| `/agentic-security:compliance-report` | Auditor-ready attestation for NIST AI 600-1, OWASP ASVS, or OWASP LLM Top 10 (2025). |
| `/agentic-security:trim-dependencies` | Find and remove packages installed but never imported. |
| `/agentic-security:dep-freshness` | Score how stale your direct dependencies are across all ecosystems. |
| `/agentic-security:dep-pinning` | Audit manifests for loose version ranges that allow silent supply-chain injection. |
| `/agentic-security:dep-alternatives` | Lighter-weight, more actively maintained alternatives to heavy or high-risk dependencies. |
| `/agentic-security:install-script-audit` | Every npm package's postinstall/preinstall scripts — the primary supply-chain attack vector. |
| `/agentic-security:vendor-audit` | Copy-pasted third-party code vendored directly into the repo — invisible to dependency scanners. |
| `/agentic-security:security-tests` | Generate failing security regression tests + passing fix-validation tests for each finding (Jest / Vitest / pytest). |
| `/agentic-security:status` | One-screen plugin & project health snapshot — version, last scan, finding counts, cache size, hook activation. |
| `/agentic-security:help` | Full command catalog with one-line descriptions and example invocations. |

To learn more read the **[Developer Documentation](https://github.com/Clear-Capabilities/agentic-security/blob/main/docs/developer-documentation-guide.md)**.

---

## F1 benchmark

The scanner is evaluated against the OWASP Benchmark (2,740 Java test cases), 33 real-world vulnerable apps (NodeGoat, Juice Shop, DVWA, and more), and an adversarial LLM/AI suite. Every rule ships with a `vulnerable/` + `clean/` fixture pair.

### Two F1 numbers — both honest, both reported

| Scoring mode | What it measures | Score |
|---|---|---|
| **Wildcard-relaxed** (default) | "Does the scanner find at least one finding in each vulnerability family this app contains?" — i.e. family-level coverage. This is the mode most published security tool benchmarks use. | **100% on 35/35 benchmarks** |
| **Strict line-level** (`--no-wildcards`) | "Does each emitted finding land on the exact file:line the upstream ground truth labels?" — a much harder bar. | **100% on 34/35** benchmarks. **87.9%** on OWASP Benchmark (via OWASP-shape suppressors). **54.8%** on SARD Juliet Java (via cross-file source chaining). **7.0%** on juliet-c-cpp (incidental-CWE precision artifact dominates). |

Why the gap on the remaining 3? OWASP Benchmark uses `real=true / real=false` labels that hinge on constant-folded if-branches, inner-class flow, and List/Map index obfuscation that regex+AST engines can't reliably distinguish — would need full collection-semantics modeling. SARD Juliet's remaining recall gap (sql-injection at 26%, xss at 18%) is in DataflowThruInnerClass / Vector / Stream variants where the BadSource hides behind multiple call frames; precise AST taint analysis is the next lift. juliet-c-cpp's 7.0% reflects engine emissions on test files whose primary CWE doesn't match what the engine detects (e.g. `rand()` fires on every PRNG site even in non-crypto tests).

Reproduce either number:

```bash
cd scanner
npm run bench:realworld                           # wildcard-relaxed (default)
node test/benchmark/realworld/bench-realworld.js --all --no-wildcards   # strict
```

Full strict-baseline breakdown per app, plus the roadmap to raise each one, is documented in [`scanner/test/benchmark/STRICT-F1-BASELINE.md`](scanner/test/benchmark/STRICT-F1-BASELINE.md).

---

## License

Full legal terms in [LICENSE](./LICENSE). The short version: don't resell, don't reverse-engineer, otherwise enjoy.
