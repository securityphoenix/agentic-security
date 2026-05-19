# PRD — Next-Generation SAST

**Status:** Draft  
**Author:** Ross Young <ross@clearcapabilities.com>  
**Date:** 2026-05-18  
**Scope:** What we'd build if we wanted to make every commercial SAST tool look like a `grep` wrapper.

---

## 0. Provocation

Today's SAST market is stuck. The leading commercial tools ship false-positive rates between 20% and 60% on real codebases, miss most cross-language flows entirely, can't reason about business logic, can't prove a single finding is exploitable, and offer no mechanism by which their accuracy improves with use. Customers cope by suppressing 70-90% of findings unread, which means the tool is providing about 10-30% of its claimed value. This PRD describes the tool that finally delivers on the original SAST promise: **find real exploitable bugs, prove they are real, and prove they are not noise.**

Three commitments differentiate the next-gen tool:

1. **Every emitted finding is accompanied by either (a) a verified executable PoC, (b) a verified absence-of-sanitizer proof, or (c) an honest "I cannot prove this from static evidence alone" label.** No more "probably an issue."
2. **Confidence scores are calibrated probabilities backed by a Brier score on a held-out labeled corpus, not ordinal priority numbers in disguise.** A "0.8 confidence" finding is wrong 20% of the time, measured.
3. **The tool gets more accurate the longer it runs on a codebase, without retraining a model.** Per-project FP rates trend down with use through a measured active-learning loop.

If we can hit all three, we change what SAST means.

---

## 1. North Star

> **Ship a SAST that a senior security engineer would deploy on her own startup without grumbling.**

That sentence is doing real work. It rules out:

- High-FP tools (she would turn them off within a week)
- Tools that miss obvious business-logic flaws (she'd find them in code review and lose trust)
- Tools that can't compose with her dev workflow (she'd uninstall the IDE plugin)
- Tools that overclaim (she's read enough vendor slides to recognize the smell)
- Tools that don't compose with the rest of the SDLC (she'd build her own glue script)

What it rules in:

- Findings are real, prioritized, and ranked by exploitability
- The tool understands her stack (React + FastAPI + Postgres + Stripe + Auth0 + Vercel)
- It traces the request from edge to database
- It explains why each finding matters in plain language with cost framing
- It writes the fix when the fix is mechanical
- It writes a regression test when the fix is non-mechanical
- It tells her when it isn't sure, and how to look more carefully

---

## 2. Goals & Non-Goals

### 2.1 Goals (in priority order)

| #   | Goal                                                                                                                                | Measure                                                                                       |
| --- | ----------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| G1  | **Calibrated confidence**: every finding's `confidence` is a probability with Brier ≤ 0.10 on a labeled corpus                       | Brier score on 1000-finding held-out set; visible in CI report                                |
| G2  | **Verified exploits**: ≥ 80% of `severity ≥ high` findings ship with a runnable PoC                                                  | Fraction of high+/critical findings with a `poc.ts`, `poc.py`, or framework-idiomatic harness |
| G3  | **Cross-language**: trace request-borne taint from HTTP edge → service → DB across language boundaries                              | F1 ≥ 0.85 on a polyglot benchmark (Node→Python→Java→Postgres)                                  |
| G4  | **Business-logic detection**: surface IDOR, broken authz, race-condition, and state-machine flaws beyond pattern matching            | F1 ≥ 0.75 on a curated business-logic corpus (real CVEs with logic flaws)                     |
| G5  | **Compositional fix**: ≥ 60% of mechanical findings get an apply-able patch that passes the project's linter and re-scan            | Pass-rate of generated patches in `fix-verify` loop                                            |
| G6  | **Per-project learning loop**: project FP rate trends down by ≥ 30% over 30 days of feedback                                        | Tracked per project via `validator-metrics.json`; visible in `/security-trend`                |
| G7  | **Honesty**: refuse to emit a finding without either evidence or explicit unverified label                                          | Zero findings with `confidence ≥ 0.7` that lack `poc`, `sanitizer-absence-proof`, or `unverified:true` |
| G8  | **Sub-minute incremental scan** on PRs of ≤ 500 LoC change                                                                          | p95 PR-incremental scan time                                                                  |
| G9  | **Determinism**: byte-identical SARIF for identical inputs across runs                                                              | CI gate; SARIF hash matched against expected                                                  |
| G10 | **Compositional with SDLC**: editor (LSP), CI (SARIF + policy), agent CLI (MCP), security tab (SARIF upload)                         | Coverage matrix in onboarding docs                                                            |

### 2.2 Non-Goals (for v1)

- **Replace dynamic application testing (DAST).** We ingest DAST signals but don't crawl the running app ourselves. DAST is a force multiplier; SAST is the foundation.
- **Replace fuzzing.** We ingest fuzz corpus findings; we don't run libFuzzer or AFL.
- **Replace formal verification.** A handful of high-stakes properties (memory safety, no-data-race) deserve their own tools. We surface where formal methods would help.
- **Compete with software composition analysis (SCA) as a standalone product.** SCA is bundled here because no-one wants to install two tools, but the SCA bar is lower than the SAST bar and we explicitly do not try to out-OSV the OSV team.
- **Run customer code in our cloud.** Privacy-preserving local execution is non-negotiable for the customer segment we want.

---

## 3. Target users

### 3.1 Primary persona — **Maya, senior security engineer, Series B startup**

- Owns AppSec for a 50-engineer org with 3 codebases in 4 languages
- Reports to the CTO; expected to ship in addition to gate
- Tolerates 1-2 false positives per week before turning the tool off
- Writes her own scripts when no commercial tool fits
- Reads SARIF directly when the UI lies

### 3.2 Secondary persona — **Vibecoder, founder/CTO at pre-product startup**

- Ships solo, leverages Claude Code, ships to prod multiple times a day
- Wants "is this safe to ship?" not "here are 47 findings to triage"
- Will pay if the tool prevents one incident
- Trusts the tool only if it shows its work

### 3.3 Tertiary persona — **Helena, head of security at regulated mid-market**

- Compliance lift (SOC2, ISO 27001, NIST AI 600-1) is half the job
- Needs attestation artifacts auto-generated
- Buys the tool because it produces the report the auditor wants

---

## 4. Pillars

The product has seven pillars. Each pillar is independent enough to invest in separately and load-bearing enough that without it the tool is not next-gen.

### Pillar 1 — Semantic Foundation

Today's SAST is mostly pattern-matching with optional shallow taint. The next-gen tool requires actual program understanding.

| Req         | Description                                                                                                                                                | Why                                                                                                                  |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| FR-SEM-1    | **Polyglot IR.** One canonical representation across JS/TS, Python, Java, Kotlin, Go, Ruby, C#, PHP, C/C++, Rust, Solidity, Swift, Kotlin (Android).        | Same finding shape across languages; one taint engine                                                                |
| FR-SEM-2    | **Full call graph + control flow graph** per function, with k=2 calling-context sensitivity.                                                              | k=1 (current state) misses interprocedural flows that depend on which caller routes data                              |
| FR-SEM-3    | **Field-sensitive taint** with object/struct field tracking (`user.profile.email` vs `user.profile.password`).                                            | Coarse object-level taint produces FPs on every audit-log-write                                                       |
| FR-SEM-4    | **Path-sensitive constant folding** with branch feasibility (don't report findings in provably-dead branches).                                            | The single biggest FP source on Java benchmarks                                                                       |
| FR-SEM-5    | **Symbolic execution for narrow paths** (≤ 4 branches deep, ≤ 200 LoC) when the taint engine reports `feasibility=unknown`.                                | The "I think but can't prove" gap closer                                                                              |
| FR-SEM-6    | **Hybrid static + dynamic.** When a test suite exists, instrument it and observe sink invocations under test inputs. Treat observed taint as ground truth. | The single biggest precision lift available without changing the user experience                                      |
| FR-SEM-7    | **Type-aware refinement.** When TypeScript types narrow a union (`string | undefined` → `string` after a guard), drop findings that depend on the wider type. | Eliminates ~15% of TS-codebase FPs                                                                                    |

### Pillar 2 — Cross-Asset Boundary Crossing

Today's SAST treats a microservice in isolation. Real attack chains cross service, language, network protocol, and infrastructure boundaries.

| Req         | Description                                                                                                                                            |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| FR-XSAT-1   | **HTTP/REST via OpenAPI.** Parse `openapi.{json,yaml}`. Match client `fetch`/`axios`/`requests` to server-side handlers. Propagate taint across.        |
| FR-XSAT-2   | **gRPC via .proto.** Match client stubs to server impls (Go/Java/Python/Node/Rust). Propagate taint across.                                            |
| FR-XSAT-3   | **GraphQL via SDL.** Match `gql` client queries to resolver impls (Apollo/NestJS/Strawberry/Graphene).                                                 |
| FR-XSAT-4   | **Message queues.** Schema-aware tracing across Kafka topics, RabbitMQ exchanges, AWS SQS queues, Google Pub/Sub topics, Redis streams.                |
| FR-XSAT-5   | **SQL/ORM round-trip.** ORM write at one site, ORM read of the same model at another — propagate taint through the database row.                       |
| FR-XSAT-6   | **IaC → application code.** Terraform / CloudFormation resources that the app references (env vars, ARNs, names). Flag publicly-exposed resources.    |
| FR-XSAT-7   | **Cloud secrets and IAM.** Parse IAM role policies attached to ECS/Lambda/EKS workloads; correlate with app behavior to detect over-permissioned roles. |
| FR-XSAT-8   | **Container runtime config.** Dockerfile, k8s manifest, ECS task def — flag dangerous combinations (privileged + bind-mounting docker.sock, etc.).      |
| FR-XSAT-9   | **Multi-repo composition.** Given a list of related repos, do all of the above across repositories.                                                    |

### Pillar 3 — Verification

A finding without verification is a hypothesis. We turn hypotheses into either confirmed bugs or labeled uncertainty.

| Req         | Description                                                                                                                                                       |
| ----------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-VER-1    | **LLM-validated triage** (already shipped at Layer 3). Layer-2 candidate → LLM accept/reject/escalate with file:line echo and challenge-token defenses.            |
| FR-VER-2    | **PoC generator** that executes against the target. Each finding gets an executable `poc.{ts,py,js,java,...}` that demonstrates the vuln when run on a test fixture. |
| FR-VER-3    | **Regression test generator.** Same finding gets a framework-idiomatic regression test that fails on the vulnerable code and passes after the fix.                |
| FR-VER-4    | **Property-based vulnerability hypothesis testing.** Use a property-based testing framework (Hypothesis / fast-check) to fuzz around the suspected sink.            |
| FR-VER-5    | **Live binary instrumentation** (eBPF on Linux, dtrace on macOS) — optional opt-in mode where the scanner hooks the running process to confirm taint paths.        |
| FR-VER-6    | **Per-finding verification verdict** in {`verified-exploit`, `verified-sanitizer-absence`, `verified-by-llm`, `unverified-by-design`, `cannot-verify`} with reason. |
| FR-VER-7    | **Refusal to silently drop.** Findings that fail verification become `escalate`, never `reject`, so an attacker who poisons the LLM can never make findings vanish.  |

### Pillar 4 — Business-Logic Reasoning

The class of bug that consumes the most security-engineer time is the one that pattern matching cannot find: missing authorization, broken state machines, race conditions, intent/implementation mismatch.

| Req         | Description                                                                                                                                                         |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-LOGIC-1  | **AuthZ matrix construction.** For each route, infer (auth-required, ownership-checked, role-required, tenant-isolated). Emit findings for the cells that disagree. |
| FR-LOGIC-2  | **State machine extraction.** Identify "status" fields with literal-string-set values; emit findings for transitions that bypass the documented set.                |
| FR-LOGIC-3  | **TOCTOU detection.** Pair `check(x)` with `act(x)` at the function-pair level; flag interleaved awaits that can let `x` change.                                    |
| FR-LOGIC-4  | **Attack chain synthesis.** Multi-finding composition: `Open Redirect + Broken Session Logout + Reflected XSS → Account Takeover`. Cite each link.                  |
| FR-LOGIC-5  | **Intent inference.** Use variable names, comments, and route shapes as evidence of the developer's intent; flag implementation that diverges (e.g. function named `validateOwnership` that doesn't). |
| FR-LOGIC-6  | **LLM-driven flow narration.** For each high-severity finding, a one-paragraph narrative of "how an attacker reaches this, what they get, what it costs you."        |
| FR-LOGIC-7  | **Negative-case test gap.** If the route has happy-path tests but no test for unauthorized access, surface as a "missing-test" finding.                              |

### Pillar 5 — Per-Codebase Adaptation

The tool that learns the codebase is the tool that customers keep. The tool that doesn't learn is the tool that ends up in the suppress-everything bucket.

| Req         | Description                                                                                                                                                          |
| ----------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-LEARN-1  | **Active-learning loop.** Triage verdicts (TP / FP / WAI) stored under `.agentic-security/triage-feedback.json`; consumed on next scan to suppress repeat-FPs by `stableId` or rule shape. |
| FR-LEARN-2  | **Customer-tuned rule packs.** Auto-synthesize a YAML rule from a "this should always fire" example; auto-suppress from a "this should never fire" example.           |
| FR-LEARN-3  | **Per-CWE precision/recall scorecard.** `validator-metrics.json` tracks per-family precision, recall, F1 over time. Visible in `/security-trend`.                     |
| FR-LEARN-4  | **Privacy-preserving federated learning.** Optional opt-in where each customer's de-identified TP/FP labels improve the global LLM-validator's accept/reject thresholds. No code or paths leave the customer environment. |
| FR-LEARN-5  | **Per-codebase confidence calibration.** Each customer's empirical TP-rate per family adjusts the global confidence prior so a customer's `0.8` matches their reality. |
| FR-LEARN-6  | **Auto-rule synthesis from repeated FPs.** If 5+ findings with similar shape get marked FP, propose a suppression rule with a generated explanation.                 |
| FR-LEARN-7  | **Compliance with the right to delete.** All learned state is local; a `--reset` flag wipes it for compliance.                                                       |

### Pillar 6 — Honest UX

The tool that gets used is the tool that doesn't lie to its user. Every signal must be honest about what it measures.

| Req         | Description                                                                                                                                                                                                                                                   |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-UX-1     | **Calibrated confidence** rendered as either an explicit probability ("83% likely TP, based on Brier-calibrated model with N=2400 historical labels") or as a tier label ("high confidence" / "medium" / "investigate"). No raw 0.7531 numbers in user-facing output unless explicitly toggled on. |
| FR-UX-2     | **Confidence intervals.** Where a probability is rendered, surface the 95% CI ("80–88%") rather than a point estimate, because the underlying labeled corpus has finite size.                                                                                  |
| FR-UX-3     | **"I don't know" labels.** When the verifier cannot rule a finding in or out, surface "cannot verify" with reason ("insufficient context", "deferred branch", "external service") rather than picking a confidence number out of a hat.                          |
| FR-UX-4     | **Cost framing.** Each finding has a plain-English blast-radius description ("if this fires on prod, you lose Stripe API key + Auth0 tenant + Postgres password — typical incident cost $80–250k").                                                            |
| FR-UX-5     | **One screen per finding.** The default rendering is one paragraph: what, where, why, how to fix. Taxonomy is opt-in.                                                                                                                                          |
| FR-UX-6     | **No marketing-speak in scanner output.** No emoji. No "industry-leading." No "next-gen." No "deep AI." The output reads like an engineer wrote it.                                                                                                            |
| FR-UX-7     | **Refusal to silently drop findings.** Every dropped finding is recorded in a suppression log with reason. `--firehose` shows everything.                                                                                                                       |
| FR-UX-8     | **Diff-aware presentation.** On PRs, only NEW findings since the base branch are shown. Pre-existing findings stay in the "tech debt" view.                                                                                                                     |

### Pillar 7 — SDLC Composition

The tool that gets adopted is the tool that fits the developer's existing workflow without forcing a new one.

| Req       | Description                                                                                                                                                                                  |
| --------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| FR-SDLC-1 | **LSP integration** (already shipped). Editor diagnostics on save in VS Code, JetBrains (LSP4IJ), Neovim, Emacs.                                                                              |
| FR-SDLC-2 | **MCP server** (already shipped). Agent-callable tools for `scan_diff`, `query_taint`, `explain_finding`, `apply_fix`, `verify_fix`, `synthesize_fix`. Works with Claude Code, Cursor, Aider, Cline. |
| FR-SDLC-3 | **CI templates** for GitHub Actions, GitLab CI, CircleCI, Buildkite, Jenkins.                                                                                                                |
| FR-SDLC-4 | **SARIF 2.1.0 emit** with full property bag (confidence, exploitability, signatureStatus, rulesetVersion).                                                                                   |
| FR-SDLC-5 | **STIX 2.1 emit** for the threat-intel side of the org that consumes IOCs.                                                                                                                   |
| FR-SDLC-6 | **PR-comment bot** with reasonable defaults (top 10 critical/high, link to full report, never spam).                                                                                         |
| FR-SDLC-7 | **Ticket sync.** Two-way sync against GitHub Issues / Linear / Jira / ServiceNow. Idempotent. State stored locally.                                                                          |
| FR-SDLC-8 | **Slack/Discord/Teams digest.** Daily / weekly summary configurable.                                                                                                                         |
| FR-SDLC-9 | **Policy-as-code gate.** `fail-on critical`, `fail-on high`, custom OPA policy for nuanced gating.                                                                                           |

---

## 5. Technical Architecture

```
                          ┌───────────────────────────┐
                          │  Frontends                │
                          │  • LSP (editor)            │
                          │  • CLI                     │
                          │  • MCP (agent tools)       │
                          │  • CI workflow             │
                          └─────────────┬─────────────┘
                                        │
                          ┌─────────────▼─────────────┐
                          │  Orchestrator             │
                          │  (engine.js)               │
                          └─────────────┬─────────────┘
                                        │
        ┌───────────────┬───────────────┼───────────────┬────────────────┐
        │               │               │               │                │
   ┌────▼─────┐   ┌─────▼─────┐   ┌─────▼─────┐   ┌─────▼─────┐    ┌─────▼─────┐
   │ Layer 1  │   │ Layer 2   │   │ Layer 3   │   │ Layer 4   │    │ Layer 5   │
   │ Polyglot │   │ Inter-    │   │ LLM       │   │ Verifier  │    │ Active    │
   │ IR + CFG │   │ procedural│   │ validator │   │ (PoC +    │    │ learning  │
   │ + CG     │   │ taint +   │   │ (challenge│   │ test gen) │    │ (per-     │
   │          │   │ symbolic  │   │ token +   │   │           │    │ project    │
   │          │   │ branches  │   │ fail-     │   │           │    │ FP/TP     │
   │          │   │           │   │ closed)   │   │           │    │ tracking) │
   └──────────┘   └───────────┘   └───────────┘   └───────────┘    └───────────┘
        │               │               │               │                │
        └───────────────┴───────────┬───┴───────────────┴────────────────┘
                                    │
                          ┌─────────▼─────────┐
                          │ Cross-asset       │
                          │ bridges           │
                          │ (OpenAPI / gRPC / │
                          │  GraphQL / queue /│
                          │  ORM / IaC / IAM) │
                          └───────────────────┘
                                    │
                          ┌─────────▼─────────┐
                          │ Findings pipeline │
                          │ stable-id → cluster→ │
                          │ confidence → exploit→ │
                          │ suppress → emit   │
                          └───────────────────┘
```

### 5.1 Layer breakdown

- **L1 (IR/CFG/CG):** Babel-based JS/TS frontend exists; tree-sitter for the rest. Per-function CFG, cross-file call graph keyed by stable function qid. K=2 calling-context.
- **L2 (interprocedural taint):** Walks the IR with field-sensitive forward taint. Sources/sinks/sanitizers from a structured catalog spanning every major framework. Path feasibility via constant folding. Per-function summary cache.
- **L3 (LLM validator):** Per-candidate LLM judgment with prompt-injection defenses (challenge token + file:line echo + fail-closed verdicts). Already shipped.
- **L4 (verifier):** Generates a PoC + regression test. Runs them in a sandboxed container. Records the verdict. New in next-gen.
- **L5 (active learning):** Per-project triage feedback consumed by L3 and the confidence calibrator.

### 5.2 What's shipped (in current `agentic-security` codebase, v0.48.0)

Pillar 1: ✅ partial (IR + L2 taint exist; needs k=2, full symbolic, dynamic instrumentation)  
Pillar 2: ✅ partial (HTTP via OpenAPI, gRPC, GraphQL, ORM, IaC — done; queues, IAM, multi-repo — missing)  
Pillar 3: ✅ partial (L3 LLM-validated triage done; PoC gen exists at agent level; full verifier loop not yet)  
Pillar 4: ✅ partial (attack chains, authz, missing-tests detection — done; AuthZ matrix + state-machine extraction not yet)  
Pillar 5: ✅ partial (active-learning loop scaffolded; calibration not yet shipped)  
Pillar 6: ✅ most of it (calibrated confidence is the gap)  
Pillar 7: ✅ most of it (Slack/Discord/Teams + ticket sync + LSP + MCP + SARIF + CI templates — done)

### 5.3 What's hard (open technical questions)

- **Calibration corpus.** Brier-calibrated confidence requires a labeled corpus of ≥ 1000 findings with TP/FP labels. We need to either curate one ourselves (expensive) or federate it.
- **PoC generation correctness.** A generated PoC that "exploits" a non-vuln is worse than no PoC. The verifier must distinguish "runs and demonstrates" from "runs without crashing." This is a research problem.
- **Multi-repo composition.** OpenAPI / gRPC bridges presume both repos are scanned in the same run. Cross-org / cross-tenancy is non-trivial.
- **Federated learning privacy.** Aggregating accept/reject signals across customers without leaking customer code requires a careful protocol design (differential privacy + secure aggregation).
- **Symbolic execution scaling.** Symbolic execution beyond ~200 LoC explodes. The "narrow paths only" gate must be principled.
- **Dynamic instrumentation portability.** eBPF is Linux. dtrace is macOS. Windows is a hole. JVM has its own story. We accept hybrid coverage in v1.

---

## 6. Engineering Culture & Process

What's not in the spec but determines whether v1 ships well:

### 6.1 Adversarial premortems

Every release ends with a documented adversarial premortem against the release artifact. The current process (rounds 1-4 logged in CHANGELOG.md) catches dead code, over-claims, and quiet regressions. We commit to running them indefinitely.

### 6.2 Bench-driven development

Every new detector lands with a fixture pair and an entry in the synthetic bench. F1 regressions block merge. Real-world benchmarks (Juliet, OWASP Benchmark, NodeGoat, DVWA, etc.) tracked separately with per-app F1 floors.

### 6.3 Honesty in claims

The CHANGELOG distinguishes "shipped" from "wired and tested" from "scaffolded." No commit message ever overstates closure; if a closure is overclaimed, the next CHANGELOG entry corrects it explicitly.

### 6.4 No dead code

Every exported symbol has a tested call site, enforced by `test/no-dead-modules.test.js`. Allowlist decay is enforced; stale exceptions fail the test.

### 6.5 Determinism

Concurrency=1 default for any cache-affecting workload. Sorted iteration everywhere we touch findings. Deterministic IDs (stableId) refactor-stable.

### 6.6 Premortem outputs are public

Each release ships its premortem findings in CHANGELOG with severity tags so customers can see exactly what we considered shipping vs what we actually shipped.

---

## 7. Success Metrics

### 7.1 Product-fit (lagging)

| Metric                                       | v1 target | Notes                                                                |
| -------------------------------------------- | --------- | -------------------------------------------------------------------- |
| 30-day active install retention              | ≥ 70%     | If they keep it installed, the FP rate is acceptable                  |
| `/fix --apply` rate per finding              | ≥ 25%     | Fixes that look useful enough to apply                                |
| Suppression rate (findings marked FP / WAI)  | ≤ 15%     | Lower is better; today's commercial SAST runs ~70-90%                |
| Time-to-first-finding-on-fresh-install       | ≤ 60s     | Cold-start barrier                                                   |
| PR-comment open rate (clicked link)          | ≥ 40%     | If they don't click, they don't trust                                |
| Net Promoter Score                           | ≥ 50      | Lagging signal; collect via in-tool prompt + email                    |

### 7.2 Technical (leading)

| Metric                                                       | v1 target |
| ------------------------------------------------------------ | --------- |
| Synthetic-bench F1                                            | ≥ 0.95    |
| OWASP Benchmark v1.2 F1                                       | ≥ 0.90    |
| NodeGoat F1                                                   | 1.00      |
| Juliet C/C++ F1 (curated CWEs)                                | ≥ 0.85    |
| Juliet Java F1 (curated CWEs)                                 | ≥ 0.95    |
| Cross-language polyglot bench F1                              | ≥ 0.85    |
| Business-logic curated bench F1                               | ≥ 0.75    |
| Brier score on confidence calibration                         | ≤ 0.10    |
| p95 PR-incremental scan time                                  | ≤ 60s     |
| p95 full-scan time on 100k LoC repo                           | ≤ 5min    |
| Determinism (byte-identical SARIF over identical input)       | 100%      |

---

## 8. Phasing

### Phase 1 (M0-M3) — Foundation

Deliver: calibrated confidence (G1), verified-exploit PoC generator for top 10 CWEs (G2 partial), cross-language polyglot benchmark + scaffolding for Pillar 2 missing pieces. Ship as v0.50.0.

Includes the Sentinel-parity work that's already in flight: IR (FR-SEM-1, FR-SEM-2 at k=1), L2 taint (FR-SEM-3 partial), L3 validator (FR-VER-1, FR-VER-7).

### Phase 2 (M3-M6) — Cross-asset

Deliver: queue-bridge (Kafka/RabbitMQ/SQS), IAM-policy reachability, container-runtime config detector, multi-repo composition (Pillar 2 complete). Ship as v0.60.0.

### Phase 3 (M6-M9) — Verifier loop

Deliver: full PoC + regression-test generator with sandbox execution (G2 ≥ 80%), property-based fuzz harness for top-20 sinks. Ship as v0.70.0.

### Phase 4 (M9-M12) — Business logic + active learning

Deliver: AuthZ matrix, state-machine extraction, TOCTOU detection (Pillar 4 complete), per-customer learning + federated calibration (Pillar 5 complete). Ship as v0.80.0.

### Phase 5 (M12-M15) — Polish + GA

Deliver: dynamic-instrumentation hybrid mode (FR-SEM-6, FR-VER-5), symbolic-execution narrow-path closer (FR-SEM-5), final calibration corpus + Brier score on labeled data. Ship as v1.0.0.

---

## 9. Risks

| Risk                                                                                                                          | Mitigation                                                                                                                                              |
| ----------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **R1: Calibration corpus is too expensive to curate.**                                                                        | Start by federating with 5 customer-design-partners; pay for explicit labeling on a held-out 500-finding sample. Budget $50-100k for the seed corpus.   |
| **R2: PoC generation produces convincing-but-wrong PoCs that customers ship.**                                                | Every generated PoC ships with a CI gate that runs it on a known-clean fixture too. The PoC must fail on clean code; otherwise we refuse to claim "exploit verified." |
| **R3: LLM-validator's failure mode is silent reject.**                                                                        | Already mitigated: fail-closed semantics + challenge-token + file:line cross-check. Continued investment in adversarial premortems each release.        |
| **R4: Symbolic execution doesn't scale to real codebases.**                                                                   | Narrow it explicitly: ≤ 4 branches, ≤ 200 LoC, only when the taint engine reports `feasibility=unknown`. Fall back to "cannot-verify" rather than time-out. |
| **R5: Per-customer federation leaks customer code.**                                                                          | Privacy review with an external security firm before turning on federation. Default OFF. Differential privacy + secure aggregation; no plain accept/reject signals leave the customer environment. |
| **R6: Commercial competitors copy our open ideas fast.**                                                                      | Open the engine; close the calibration corpus + the customer feedback loop + the verifier sandbox. The moat is the data, not the patterns.              |
| **R7: Customer adoption is gated by "must run in our VPC."**                                                                  | Already an architectural commitment: no runtime cloud calls, local LLM endpoints supported.                                                              |
| **R8: We over-claim coverage and a security incident blows back.**                                                            | Every claim is bench-backed. CHANGELOG documents honest caveats. We never claim "finds everything."                                                      |
| **R9: Dynamic-instrumentation hybrid mode triggers customer compliance review (root agent in prod).**                          | Hybrid mode is opt-in, off-by-default, and recommended for staging not prod. We document the exact hooks installed.                                       |
| **R10: We build a great tool and nobody finds out about it.**                                                                 | Out of scope for this PRD but real. The community-facing strategy goes elsewhere.                                                                       |

---

## 10. Open Questions

1. **Confidence calibration:** Is a single global Brier-calibrated model sufficient, or do we need per-language / per-framework sub-models? Recommend per-language for v1; merge if Brier scores converge.
2. **Verifier sandbox:** Run PoCs in Docker, Firecracker, or WASM? Docker is lowest friction; Firecracker is the long-term answer. Start with Docker and a strict resource cap.
3. **Federated learning protocol:** Roll our own DP + secure aggregation, or ride on an existing framework? Recommend ride on an existing protocol; the work to build privacy-preserving primitives from scratch is multi-quarter.
4. **Symbolic execution backend:** Build, ride, or fork? Probably ride on KLEE-style for C/C++ and write our own narrow JS executor.
5. **Pricing model:** Per-developer seat, per-codebase, per-finding, or open-core? Recommend open-core with the calibration corpus + verifier sandbox as the paid tier.
6. **Compliance posture:** SOC 2 Type II at v1 or v2? Customer-design-partners want it at v1; that's $80-200k of audit cost. Defer to v2 unless a design partner blocks adoption on it.
7. **Multi-language fix generation:** Do we ship machine-generated fixes in C/C++ and Rust where the cost of a wrong fix is highest, or limit to managed-runtime languages (JS, Python, Java, Go, Ruby, C#) in v1? Recommend limit to managed-runtime; surface "fix recommended manually" for native code.
8. **PoC vs Sanitizer-absence-proof:** Some classes (timing oracles, side channels, race conditions) cannot reasonably ship a PoC. Define a verified-sanitizer-absence proof shape per CWE family.

---

## 11. What this PRD intentionally does NOT specify

- Pricing, licensing, GTM, partners, customer-success ops, hiring plan — all outside engineering scope
- UI specifics for the cloud product (this PRD is for the engine + agent-facing tools)
- Compliance attestation specifics for non-NIST/non-OWASP frameworks (HIPAA, PCI, FedRAMP) — separate workstream
- Specific competitive matrix — see internal comparison doc; we do not name competitors in this PRD or in any shipped artifact

---

## 12. Appendix: Where today's `agentic-security` already exceeds the median commercial tool

Useful for orienting on what we're competing with.

| Capability                                          | Median commercial SAST | `agentic-security` today                                                                  |
| --------------------------------------------------- | ---------------------- | ----------------------------------------------------------------------------------------- |
| Calibrated confidence on findings                   | ❌                     | ✅ (ordinal today; calibrated probability is the Pillar-6 gap)                            |
| LLM-validated triage                                | ❌ or shallow          | ✅ Layer 3 with prompt-injection defenses                                                  |
| Cross-language taint (HTTP, gRPC, GraphQL, ORM)     | ❌ mostly              | ✅ (queue + IAM are the gaps)                                                              |
| IaC → application reachability                      | ❌                     | ✅                                                                                        |
| PoC generation                                      | ❌                     | 🟡 (agent-level; Layer-4 verifier loop is the Phase-3 gap)                                |
| Attack-chain synthesis across findings              | ❌                     | ✅                                                                                        |
| AI-BOM / OWASP-LLM-Top-10 / prompt-injection rules  | ❌                     | ✅                                                                                        |
| MCP / agent-callable tools                          | ❌                     | ✅ six hardened tools                                                                     |
| Per-customer learning loop                          | ❌                     | ✅ scaffolded; calibration is the Pillar-5 gap                                            |
| Honest CHANGELOG with adversarial premortems         | ❌                     | ✅ rounds 1-4 documented                                                                  |
| Determinism (byte-identical SARIF)                  | ❌                     | ✅                                                                                        |
| Refactor-stable finding IDs                         | ❌                     | ✅ stableId                                                                                |
| Open-source engine                                  | depends                | ✅ PolyForm Internal Use; relicense path open                                              |

The gap from "good open engine" to "next-gen product" is calibration, verifier loop, federation, and queue/IAM cross-asset coverage. Phase 1-5 above closes that gap.

---

**End of PRD.**
