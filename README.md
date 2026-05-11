# agentic-security

### The Claude Code Plugin that Catches what your AI Assistant Misses.

> Built by **[ClearCapabilities.Com](https://clearcapabilities.com)** · Runs inside Claude Code

[![License](https://img.shields.io/badge/license-PolyForm--Internal--Use-blue)](./LICENSE)
[![Tests](https://img.shields.io/badge/tests-75%2F75-brightgreen)]()
[![Bundle](https://img.shields.io/badge/bundle-2.16MB-orange)]()
[![Version](https://img.shields.io/badge/version-0.18.0-blue)]()

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
/plugin install agentic-security
```

That's it. Type `/scan-all` to confirm it's working.

For **CI, terminal, or any project anywhere** (no Claude Code required):

```bash
npx @clearcapabilities/agentic-security-scanner scan .
```

The scanner runs entirely on your machine. Nothing leaves your laptop. No signups, no API keys, no cloud.

---

## Two modes. One tool.

Both modes run the same engine. They differ in how much you see and how much you can configure.

### 🎨 Easy Mode

Three commands. The whole product. The default for everyone.

---

#### `/scan-all` — daily, before deploy

**What `/scan-all` scans every run — nine pillars, no configuration required:**

```
       Pillar         What we scan
       ─────────────────────────────────────────────────────────────
       SAST           Taint analysis (regex + AST for JS/TS), Java
                      rule pack, Python helpers.
       SCA            OSV + CISA KEV + EPSS, function-level
                      reachability, dep confusion, typosquat.
       Secrets        50+ credential patterns, high-entropy heuristic,
                      allowlist-aware.
       IaC            Dockerfile, docker-compose, GitHub Actions,
                      Kubernetes manifests.
       LLM            OWASP LLM Top 10 (2025): prompt injection,
                      sensitive disclosure, system prompt leakage.
       MCP            Agent-tool audit for over-privileged MCP servers.
       Pipeline       GitHub Actions integrity: floating tags,
                      secret echoes, OIDC misconfig.
       Auth/AuthZ     Broken access control, IDOR, mass assignment,
                      session fixation.
       Container      Base-image EOL, exposed ports, runtime mode.
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
     /security-scan-all --firehose      see every finding
     /security-fix --finding <id>       fix exactly one
```

The scanner asks which tier you want to fix; reply with the number and `/fix-all` runs the matching `--severity` automatically.

---

#### `/show-findings` — interactive HTML report

Writes a self-contained HTML report to `.agentic-security/findings.html` and opens it in your default browser. The report has severity charts, a filterable findings list, per-finding evidence with the offending code snippet, and the proposed fix template. No external assets, no network required — works offline.

**To view the report:** it usually opens automatically when the command finishes. If it doesn't, open it manually:

```bash
# macOS
open .agentic-security/findings.html

# Linux
xdg-open .agentic-security/findings.html

# Windows
start .agentic-security/findings.html
```

---

#### `/fix-all` — patch findings in batch

Pick a severity tier; `/fix-all` dispatches the security-fixer agent on every finding at or above it. Tiers are **cumulative** — `/fix-all --high` patches critical **+** high. Sequential, test-aware, does not auto-revert on failure.

| Flag | Fixes |
|---|---|
| `/fix-all --critical` (default) | Critical only |
| `/fix-all --high` | Critical + High |
| `/fix-all --medium` | Critical + High + Medium |
| `/fix-all --low` | Everything |

Example — fixing all critical and high-severity findings:

```
> /fix-all --high

Checking git state…   clean ✓
Fixing 104 findings (31 critical + 73 high)…

  ✓  routes/login.ts:34       SQL Injection                → parameterized query
  ✓  lib/insecurity.ts:43     MD5 Password Hashing         → bcrypt (cost 12)
  ✓  routes/b2bOrder.ts:17    RCE via vm.runInContext      → JSON.parse
  ✓  routes/order.ts:35       IDOR                         → ownership check
  …  +100 more

Applied 104 fixes, 0 skipped (tests failed), 0 regressions introduced.
```

That's the entire product. You don't need anything else to ship safer code.

---

### ⚙️ Developer Mode

For the senior engineer, the platform team, the person who actually reads SARIF. Switch on with:

```bash
agentic-security profile set pro
```

Developer Mode unlocks **35+ commands** and adds: the full finding taxonomy (CWE / CVSS / OWASP / MITRE ATT&CK / CAPEC), machine-readable outputs (SARIF, JSON, JUnit, CSV) on every scan, CI gates, curated rule packs, audit-grade suppressions with reviewer + expiry, a triage workflow with MTTR trends, org-wide fleet scans, custom YAML rules, integrations with Slack / Jira / GitHub Security / SIEM, four compliance attestations (NIST AI 600-1, OWASP ASVS, PCI-DSS 4.0, SOC 2), and posture artifacts (SBOM, AI-BOM, PBOM, API inventory, attack-chain synthesis, PoC generation).

Every command, flag, and output format is documented in the **[Developer Guide →](docs/for-appsec-pros.md)**.

---

## License

Full legal terms in [LICENSE](./LICENSE). The short version: don't resell, don't reverse-engineer, otherwise enjoy.

*Stop shipping the bugs your AI didn't catch.*
