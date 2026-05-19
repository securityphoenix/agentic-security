---
description: List every command, ICP-segmented (Vibecoder / Pro / Both). Pick the lane that matches your role.
---

Print the full agentic-security command catalog, segmented by ICP.

```
       ╭───╮ ╭───╮
       │ ◉ │ │ ◉ │        agentic-security  ·  by Clear Capabilities Inc.
       ╰─┬─╯ ╰─┬─╯        Tiny. Bright. Watching.
      ╭──┴─────┴──╮       https://clearcapabilities.com
      │  ·  ⌣  ·  │
      ╰───────────╯

agentic-security commands

EASY MODE — four commands. The whole product.
  /scan --all                One-screen "safe to deploy?" verdict
  /show-findings --all       Triage FPs then open interactive HTML report
  /fix --all                 Batch-fix every finding at or above --severity
  /find-and-fix-everything   Scan + fix every finding at every severity in one shot

═══════════════════════════════════════════════════════════════
🎨 VIBECODER / BUILDER LANE
═══════════════════════════════════════════════════════════════
You ship features fast. You want plain English, $-cost framing, one-button
fixes, and bodyguards that prevent foot-guns BEFORE they hit production.

  Smart entry
    /secure                    Routes you to the right next action
    /tutorial                  First-run walkthrough with one real finding

  Scan & fix (vibecoder framing)
    /scan --uncommitted        Scan only files you've changed since last commit
    /supply-chain-check        One-screen "is npm install safe?" verdict
    /find-and-fix-everything   Scan + fix every severity in one shot
    /report-card               A–F letter grade + one concrete next action
    /risk-in-dollars           Each finding's $ exposure (best/likely/worst)

  Understand it
    /explain                   Plain-English explanation of one finding
    /explain --narrative       4-act attack story (was /story-explain)
    /attack-surface            3-5 realistic attack scenarios as narrative

  Bodyguards (set once, run forever)
    /ai-bodyguard              Intercept insecure AI code BEFORE it hits disk
    /destructive-guard         Block rm -rf, DROP TABLE, force push to main…
    /predeploy-gate            Block vercel --prod / fly deploy on findings
    /cve-alerts                Daily Slack/Discord ping on new CVE in your deps

  Secrets (the panic button)
    /rotate-secret             Provider-aware rotation guide
    /rotate-secret --auto      Revoke + scrub + push replacement (was /rotate-key-auto)
    /vault-wizard              Migrate .env to Doppler / Infisical / platform

  Stack-specific
    /stack-playbook            Copy-paste security checklist for your stack
    /harden                    Headers + .gitignore + SECURITY.md + audit hook
    /db-audit                  Supabase RLS, service-role exposure
    /auth-audit                Clerk / NextAuth / Auth0 / Lucia misconfig
    /rate-limit-check          Find unrate-limited auth/AI/payment endpoints
    /webhook-audit             Stripe/GitHub/Clerk signature verification
    /env-check                 NEXT_PUBLIC_ leaks, hardcoded fallbacks
    /csp-cors                  Generate CSP + CORS headers for your stack
    /llm-cost-ceiling          Auto-patch max_tokens + $-spend tracker
    /prompt-firewall           LLM defense gaps (user input in system prompt)
    /deploy-check              Vercel/Railway/Fly/Netlify/CF checklist
    /launch-check              10 things builders typically miss

  Customer / investor artifacts
    /security-attestation                    Default: README badge (was /security-badge)
    /security-attestation --format onepager  "How we keep your data safe" doc (was /security-onepager)
    /security-attestation --format page      /.well-known/security.txt + /security page (was /trust-page)
    /privacy-docs              PRIVACY.md + cookie banner from your stack
    /disaster-playbook         DISASTER.md with the commands you'll need
    /social-media              X / LinkedIn / Discord posts about progress

═══════════════════════════════════════════════════════════════
🔧 PRO / APPLICATION SECURITY LANE
═══════════════════════════════════════════════════════════════
You triage findings for a living. You need depth, integration with the stack
you already run, customization, and audit-defensible output.

  Deep scanning
    /scan --all                Full SAST + SCA + secrets sweep
    /scan --sca                OSV-backed dep CVE audit
    /scan --secrets            60+ provider patterns + entropy
    /scan --authz              JWT, OAuth/PKCE, IDOR, multi-tenant scope
    /scan --mcp                MCP server config audit
    /scan --pipeline           GitHub Actions integrity
    /scan --logic              Semantic business-logic review (subagent)
    /scan --diff [--since ref] Architectural-risk score on git diff
    agentic-security scan --pr [ref]    Diff-aware: only changed files
    agentic-security scan --deterministic  Byte-stable for CI baselines

  Validation & triage
    /validate-findings         Build a PoC + regression test for one finding
    /show-findings --all       Interactive HTML triage report
    /show-findings --kev       Filter to actively-exploited CVEs
    /show-findings --chains    Multi-finding attack chains
    /show-findings --threat-model [--stride|--llm]

  Rule authoring & customization
    agentic-security rule list             List custom YAML rules
    agentic-security rule test <glob>      Test rules against fixtures
    agentic-security rules validate        Lint rules.yml
    agentic-security rules lock            Pin rule-pack hash
    agentic-security packs list            Curated rule packs

  Integrations
    /ci-gate                   GitHub Actions workflow + SARIF upload
    /fix --pr                  Bundle fixes into a feature branch + PR
    agentic-security tickets sync --provider github|linear|jira
    agentic-security org-scan --repos <list>   Fleet scan across N repos
    agentic-security triage list|assign|transition|trend
    /security-tests            Generate failing security regression tests

  Posture & compliance
    /posture-management --sbom   CycloneDX 1.6 / SPDX 2.3 SBOM
    /posture-management --aibom  AI/ML BOM — models, prompts, frameworks
    /posture-management --api    API surface with auth + data classes
    /posture-management --license  License allow/deny enforcement
    /posture-management --drift  Compare two scans
    /posture-management --mttr   Findings exceeding SLA thresholds
    /security-trend            Rolling history + regression detection
    /compliance-report [nist|asvs|llm]   Auditor-ready attestation

  Pro framing of dual-ICP commands
    /explain --narrative --post-mortem    Past-tense narrative for incident write-ups
    /rotate-secret --auto --scrub-history git filter-repo / BFG history rewrite

  LLM red-teaming
    /llm-redteam               30+ adversarial prompts × 7 mutations
    /jailbreak-detector        Canonical jailbreak families, per-family verdict
    /llm-eval                  Generate promptfoo YAML eval suite

═══════════════════════════════════════════════════════════════
🆕 NEXT-GEN (v3) — production-aware + adversary-grade
═══════════════════════════════════════════════════════════════
The v3 PRD additions. These read .agentic-security/last-scan.json — run /scan first.

  Production-aware filters (compose with any /scan mode)
    /scan --exposed-only            Only findings prod controls don't already block
    /scan --mitigated-only          Inverse — findings your WAF/auth/network handles
    /scan --persona apt-nation-state    Filter by attacker class

  Attacker-grade output
    /threat-model              Auto-derived STRIDE — assets, boundaries, findings
    /personas                  Per-persona priority matrix (5 adversary classes)
    /playbook                  Copy-paste attack scripts (curl / Nuclei / multi-step)
    /bounty                    Predicted HackerOne / Immunefi USD payouts
    /adversary --finding <id> --target <url>    Multi-step LLM exploit agent

  Defensive-posture views
    /spof                      Single-point-of-failure controls (counterfactual)
    /trust-boundary            Auto-Mermaid architecture diagram with findings
    /scan --concurrency        Data races, missed unlocks, deadlock cycles
    /scan --spec-drift         Function name vs. body intent-drift detector

  Engineering / forensics
    /archaeology --finding <id>      When did our codebase first become vulnerable?
    /why-fired --finding <id>        Full provenance graph for one finding
    /diff-scan --baseline <bin> --candidate <bin>     FR-SDLC-10 scanner-vs-scanner
    /self-test                 Adversarial self-test — scanner attacks itself

═══════════════════════════════════════════════════════════════
🤝 BOTH LANES USE THESE
═══════════════════════════════════════════════════════════════

  Dependency depth
    /supply-chain-check                       Roll-up verdict across six dep audits
    /supply-chain-check --show pinning        Was /dep-pinning
    /supply-chain-check --show freshness      Was /dep-freshness
    /supply-chain-check --show alternatives   Was /dep-alternatives
    /install-script-audit                     postinstall / preinstall hooks
    /vendor-audit                             Copy-pasted third-party code (invisible to SCA)
    /trim                                     deps + dead code in one pass (was /trim-dependencies + /trim-dead-code)
    /trim --what deps                         deps only
    /trim --what code                         dead code only

  CI integration
    /ci-gate                                  GitHub Actions workflow + SARIF upload
    /ci-gate --provider gitlab|circleci|buildkite|jenkins   Other providers (was /ci-gate-multi)

  Project meta
    /status                    Plugin & project health snapshot
    /help                      This command
    /find-and-fix-everything   The "I have 10 min" mode

═══════════════════════════════════════════════════════════════
🪦 RENAMED / MERGED COMMANDS
═══════════════════════════════════════════════════════════════
Eleven commands have been folded into their canonical forms. The old slashes
still work for one release as deprecated aliases so muscle memory doesn't
break — but the lines above use the new forms.

  /ci-gate-multi      →  /ci-gate --provider <name>
  /rotate-key-auto    →  /rotate-secret --auto
  /trim-dead-code     →  /trim --what code
  /trim-dependencies  →  /trim --what deps (or just /trim for both)
  /story-explain      →  /explain --narrative
  /security-badge     →  /security-attestation                       (default)
  /security-onepager  →  /security-attestation --format onepager
  /trust-page         →  /security-attestation --format page
  /dep-pinning        →  /supply-chain-check --show pinning
  /dep-freshness      →  /supply-chain-check --show freshness
  /dep-alternatives   →  /supply-chain-check --show alternatives

USAGE NOTES
  - Every command works as /agentic-security:<name> too (the long form).
  - Most commands accept a [path] argument to limit scope.
  - First run /scan once. Most other commands read its output
    from .agentic-security/last-scan.json.
  - PostToolUse hook scans every Edit/Write automatically. Throttled per-file
    to one scan / 5s.
  - Set AGENTIC_SECURITY_OFFLINE=1 to skip all outbound calls (OSV, EPSS, KEV).

WHERE THINGS LIVE
  Project state:  .agentic-security/last-scan.json, rules.yml, license-policy.yml
  CVE cache:      ~/.claude/agentic-security/osv-cache/  (24h–7d TTL)
  Plugin bundle:  ~/.claude/plugins/cache/clearcapabilities/agentic-security/
```

Print the entire block above verbatim. The user wants the full catalog as a single screen, not a follow-up question. Do not summarize.
