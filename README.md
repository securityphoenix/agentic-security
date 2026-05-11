# agentic-security

### The Claude Code Plugin that Catches what your AI Assistant Misses.

> Built by **[ClearCapabilities.Com](https://clearcapabilities.com)** · Runs inside Claude Code

[![License](https://img.shields.io/badge/license-PolyForm--Internal--Use-blue)](./LICENSE)
[![Tests](https://img.shields.io/badge/tests-75%2F75-brightgreen)]()
[![Bundle](https://img.shields.io/badge/bundle-2.16MB-orange)]()
[![Version](https://img.shields.io/badge/version-0.18.0-blue)]()

---

## Your AI is fast.

It's also writing security bugs.

This morning Claude wrote your login route in 9 seconds. Beautiful code. Tests pass.

It also lets anyone in the world log in as admin with a single line of curl.

You don't know this yet. Neither does Claude.

**One command finds it.**

---

## Two modes. One tool.

Both modes run the same engine. They differ in how much you see.

### 🎨 Easy Mode

Three commands. The whole product. The default for everyone.

**`/scan-all`** — daily, before deploy. One-screen verdict.

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

  1. routes/login.ts:34
     - db.query(`SELECT * FROM users WHERE email = '${req.body.email}'`)
     + db.query('SELECT * FROM users WHERE email = $1', [req.body.email])

     Why: An attacker can dump your entire users table.

  Type /show-findings to see the rest, or /fix-all to apply them.
```

**`/show-findings`** — print every finding from the last scan, grouped by severity. No re-scan.

```
Findings from last scan

CRITICAL — 2
  🛑 [a3f4b2c1] SQL Injection         routes/login.ts:34
      User input concatenated directly into SQL query string.
  🛑 [b9d8e7a2] Hardcoded Secret      config/db.ts:8
      Database password committed to source.

HIGH — 1
  ⚠️  [c2f1a0b3] Path Traversal       api/files.ts:67
      User-controlled path passed to fs.readFile without sanitization.

Total: 3
Next: /fix-all --severity critical  to remediate.
```

**`/fix-all`** — batch-fix every finding at or above a severity. Sequential, test-aware, doesn't auto-revert.

```
Fixing 3 findings…
  ✓ routes/login.ts:34   SQL Injection      → parameterized query
  ✓ config/db.ts:8       Hardcoded Secret   → moved to env var
  ✓ api/files.ts:67      Path Traversal     → path.join + allowlist

Applied 3 fixes, 0 skipped, 0 regressions introduced.
```

That's the entire product.

### ⚙️ Developer Mode

For the senior engineer. The platform team. The person who actually reads SARIF.

```bash
agentic-security profile set pro
```

Unlocks the full surface — 35+ commands and every output format. What you get on top of Easy Mode:

- **Full taxonomy in every finding** — CWE, CVSS, OWASP, MITRE ATT&CK, CAPEC.
- **Machine-readable output** — SARIF 2.1.0, JSON, JUnit, CSV written on every scan.
- **CI gating** — `agentic-security ci . --fail-on critical` with PR-base detection; pre-commit hook included.
- **Curated rule packs** — `owasp-top-10`, `cwe-top-25`, `llm-security`, `supply-chain`.
- **Audit-grade suppressions** — `.agentic-security/suppressions.yml` with signer ≠ reviewer, rule_version pinning, mandatory expiry.
- **Triage workflow** — per-finding state machine (`open` → `in-progress` → `fixed`/`wont-fix`/`false-positive`) with MTTR trend reports.
- **Org-wide fleet scans** — parallel worker pool across many repos with rolled-up output.
- **Custom rules in YAML** — project-local regex/AST rules, severity overrides, version pins.
- **Integrations** — Slack, Discord, Jira, GitHub Security tab, SIEM (Splunk / Datadog / Elastic).
- **Compliance attestations** — NIST AI 600-1, OWASP ASVS, PCI-DSS 4.0, SOC 2 — audit-ready CSV + JSON + Markdown.
- **Posture artifacts** — SBOM (CycloneDX 1.6, SPDX 2.3), PBOM, AI-BOM (CycloneDX 1.7 ML-BOM), API inventory, attack-chain synthesis, PoC generation.

Every command, flag, and output format is documented in the [Developer Guide →](docs/for-appsec-pros.md).

---

## What scans does `/scan-all` run?

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

---

## Install

In Claude Code:

```
/plugin install agentic-security
```

That's it. Now type `/scan-all`.

For CI, command line, or any project anywhere:

```bash
npx @clearcapabilities/agentic-security-scanner scan .
```

---

## License

Full legal terms in [LICENSE](./LICENSE). The short version: don't resell, don't reverse-engineer, otherwise enjoy.

For licensing inquiries, email **[ross@clearcapabilities.com](mailto:ross@clearcapabilities.com)**.

---

## One more thing.

Every generation of software gets a new superpower.

Cloud made infrastructure instant.  
Git made collaboration instant.  
AI made coding instant.

Now security has to become instant too.

Agentic Security is what happens when security tooling starts —

Running locally.  
Explaining issues in plain English.  
Coding the patch for you.  
And disappearing into your workflow until you need it.

Remember, the best security tools don't slow developers down anymore.

They make shipping safer feel effortless.

---

**🛡 agentic-security** · built with care by **[ClearCapabilities.Com](https://clearcapabilities.com)**

*Stop shipping the bugs your AI didn't catch.*
