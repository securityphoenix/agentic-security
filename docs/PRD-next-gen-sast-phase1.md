# Phase 1 Implementation Plan — Next-Gen SAST (M0–M3)

**Parent PRD:** `docs/PRD-next-gen-sast.md`  
**Status:** In progress  
**Owner:** Ross Young  
**Target release:** v0.50.0

This document breaks Phase 1 of the parent PRD into five shippable units. Each unit is sized so it can land in 1–3 sessions without forcing dead code into the repo. Dependencies between units are explicit.

## Phase 1 goals (from parent PRD)

- **G1.** Calibrated confidence (Brier ≤ 0.10 on a labeled corpus)
- **G2 (partial).** Verified-exploit PoC generator for top-10 CWEs
- **G3 (scaffold).** Cross-language polyglot benchmark
- **Pillar 2 (gap-fill).** Queues + IAM cross-asset bridges

## Shippable units

```
              P1.1 (PoC framework)
               │
               ▼
    ┌──────────────────┐
    │ P1.2 (Verifier   │
    │  sandbox loop)   │
    └──────┬───────────┘
           │
           ▼
    ┌──────────────────┐         ┌──────────────────┐
    │ P1.3 (Brier-     │         │ P1.5 (Queue      │
    │  calibrated      │         │  cross-lang)     │
    │  confidence)     │         └────┬─────────────┘
    └──────┬───────────┘              │
           │                          │
           └──────────┬───────────────┘
                      ▼
              P1.4 (Polyglot bench)
              (consumes signals from
               all the above)
```

P1.1 → P1.2 is the critical path. P1.5 is independent. P1.3 can start once P1.1 is producing data. P1.4 must come last because it measures all the others.

---

## P1.1 — PoC generator framework (FR-VER-2)

**Goal:** every high+/critical finding ships with an executable proof-of-concept file when the CWE family supports it.

**Scope:**

- New module `scanner/src/posture/poc-generator.js`.
- Template library covering the top-10 CWEs from the parent PRD's curated bench:
  - CWE-89 (SQL injection)
  - CWE-78 (Command injection)
  - CWE-79 (XSS — reflected, stored, DOM)
  - CWE-22 (Path traversal)
  - CWE-918 (SSRF)
  - CWE-94 (Code injection / eval)
  - CWE-352 (CSRF)
  - CWE-601 (Open redirect)
  - CWE-611 (XXE)
  - CWE-502 (Unsafe deserialization)
- Each template:
  - Renders to a runnable file (`.ts`, `.py`, `.java`, etc. — match the finding's source language).
  - Includes a one-paragraph "what this proves" comment header.
  - Calls the discovered endpoint (taint sink) with an attacker-controlled payload.
  - Returns 0 on demonstrated exploit, non-zero otherwise.
- Findings get a new field `f.poc = { lang, code, runHint }` when a template fires.
- Findings without a viable template get `f.poc = null` (explicit "no PoC available for this CWE family in v1").

**Out of scope for P1.1 (defer to P1.2):**

- Sandbox execution of the generated PoC.
- Marking findings as `verified-exploit` based on the PoC's exit code.
- Container / WASM isolation.
- Network egress controls.

**Acceptance criteria:**

- For every existing high+/critical synthetic-bench fixture in {`vulnerable-js`, `host-header`, `orm-raw-sql`}, the corresponding finding has `f.poc.code` populated.
- Template library covers the 10 listed CWEs at least one language each.
- Unit test asserts the generator produces non-empty `code` for known input.
- No dead exports (passes `test/no-dead-modules.test.js`).
- No regression on bench (`npm run bench` stays at 100%).
- CHANGELOG entry honest about what ships vs what's queued.

**Tests:**

- `test/poc-generator.test.js` — one assertion per CWE family.
- Smoke: `node bin/agentic-security.js scan test/fixtures/vulnerable-js --format json | jq '.findings[].poc'` shows poc objects for the SQL injection / command injection / XSS findings.

---

## P1.2 — Verifier sandbox loop (FR-VER-3, FR-VER-6, FR-VER-7)

**Depends on:** P1.1

**Goal:** the PoC framework produces files; this step runs them in isolation and assigns a verification verdict to each finding.

**Scope:**

- New module `scanner/src/posture/verifier.js`.
- Sandbox runner: Docker by default, with `--no-network --cap-drop=ALL --memory=256m --cpu-quota=20000 --pids-limit=64 --user nobody`. Fallback to subprocess with `ulimit` when Docker isn't available (with explicit caveat in stderr).
- Per-finding verdict set on `f.verifier_verdict`:
  - `verified-exploit` — PoC ran, exited 0, demonstrated the vuln on a known-vulnerable fixture.
  - `verified-by-llm` — Layer-3 LLM accepted; no PoC was generated.
  - `verified-sanitizer-absence` — pattern-based proof that no sanitizer is in the flow path.
  - `cannot-verify` — PoC failed to run or LLM returned `escalate`.
  - `unverified-by-design` — CWE family for which we explicitly don't ship a PoC (e.g., timing oracle).
- Regression-test generator emits a framework-idiomatic test (Jest for Node, pytest for Python, JUnit for Java) that fails before the fix and passes after.
- Fail-closed: any sandbox error promotes the finding to `cannot-verify`, never silently drops.
- New CLI subcommand `agentic-security verify [--finding <id>]` that runs the verifier loop on demand.

**Acceptance criteria:**

- For each PoC-supported family, the sandbox runs the generated PoC and assigns a verdict.
- 80%+ of high+/critical PoC-supported findings on the synthetic bench return `verified-exploit`.
- Docker absence is detected gracefully with a friendly stderr message and falls back to subprocess mode.
- Sandbox cannot escape (verified by integration test that attempts to write outside its working dir).
- New SARIF property `verifierVerdict` on each finding.
- CHANGELOG entry includes a "we cannot prove" caveat for unverified-by-design families.

---

## P1.3 — Brier-calibrated confidence (FR-UX-1, FR-UX-2)

**Depends on:** none (can start whenever)

**Goal:** the `confidence` field becomes a calibrated probability with a measurable Brier score, not an ordinal priority number.

**Scope:**

- New module `scanner/src/posture/calibration.js`.
- Per-family calibration table: maps the raw heuristic score → empirical TP rate, computed from `validator-metrics.json` history + the v0.47.0 active-learning loop.
- 95% confidence interval from the Wilson-score formula (small-sample-safe).
- Render in CLI as `"83% (CI 78–88, N=420)"` when `--show-calibration` is set; ordinal tier label otherwise.
- New `--brier` flag prints the running Brier score for the active calibration model.
- Seed calibration table shipped with the repo, computed from the OWASP Benchmark + Juliet labeled data.
- `f.calibrated_confidence`, `f.calibrated_confidence_ci`, `f.calibrated_n` on each finding.

**Acceptance criteria:**

- For families with N ≥ 30 labeled samples in the seed table: Brier ≤ 0.10.
- For families with N < 30: emit `f.calibrated_confidence: null` with reason `insufficient-samples`.
- SARIF property bag carries the three calibration fields.
- Tests verify Brier computation on a tiny corpus.
- `validator-metrics.json` history surfaces calibration via `agentic-security validator-cache stats`.

---

## P1.4 — Cross-language polyglot benchmark (G3)

**Depends on:** P1.1, P1.2, P1.3, P1.5 (it measures all of them)

**Goal:** a curated polyglot benchmark covering Node → Python → Java → Postgres flows. Lets us prove cross-asset claims.

**Scope:**

- New directory `bench/polyglot/cases/<case-id>/` per case. Each case has:
  - `manifest.yaml` — describes services, the request that triggers the flow, the expected sink, the expected verdict.
  - `services/node/`, `services/python/`, `services/java/` — the actual code.
  - `expected.json` — ground-truth findings (file:line:family triples).
- New runner `bench/polyglot/runner.mjs` — scans every case, computes F1 vs `expected.json`, writes `bench/polyglot/results/`.
- New `npm run bench:polyglot`.
- ≥ 10 cases at v1:
  - 3× HTTP→HTTP (via OpenAPI)
  - 2× HTTP→gRPC (via .proto)
  - 2× HTTP→GraphQL
  - 2× HTTP→Queue→DB
  - 1× HTTP→ORM-write→ORM-read

**Acceptance criteria:**

- Polyglot bench F1 ≥ 0.85 across the cases (per PRD G3).
- Runner deterministic.
- CI integration optional in Phase 1 (full integration in Phase 2 once F1 stable).

---

## P1.5 — Cross-language queues (FR-XSAT-4)

**Depends on:** none

**Goal:** trace taint across asynchronous message-queue boundaries when both producer and consumer are scanned.

**Scope:**

- New module `scanner/src/posture/cross-lang-queues.js`.
- Detectors for:
  - **Kafka** — `kafkajs`, `confluent-kafka` (Python), `kafka-clients` (Java), `sarama` (Go).
  - **AWS SQS** — `aws-sdk` (Node), `boto3` (Python), `aws-sdk-java`.
  - **RabbitMQ** — `amqplib` (Node), `pika` (Python), `RabbitTemplate` (Spring).
  - **Redis Streams** — `redis` clients with `xadd` / `xread`.
  - **Google Pub/Sub** — `@google-cloud/pubsub` (Node), `google-cloud-pubsub` (Python).
- Match producer site (topic name, message schema) to consumer site (same topic, schema-compatible).
- Emit `cross_language: true` with `boundary: 'queue'` and `topic` field on the chain finding.

**Acceptance criteria:**

- Fixtures: 1 vulnerable + 1 clean per queue tech.
- Bench: 5 new fixtures in `scanner/test/fixtures/cross-lang-queues/`.
- Bench F1 = 1.00 on the fixtures.
- No regression on existing cross-lang detectors (HTTP / gRPC / GraphQL / ORM / IaC).

---

## Session breakdown

Suggested cadence assuming ~3 hours of focused work per session:

| Session | Units                              | Notes                                                                                      |
| ------- | ---------------------------------- | ------------------------------------------------------------------------------------------ |
| S1      | P1.1 (PoC framework, top-5 CWEs)   | Land scaffold, template library for SQL injection / cmd injection / XSS / path / SSRF      |
| S2      | P1.1 (remaining CWEs) + P1.5 start | Finish PoC templates, start queues module with Kafka + SQS                                 |
| S3      | P1.5 finish + P1.3 start           | Queue fixtures and bench; start calibration module                                         |
| S4      | P1.2 (verifier sandbox)            | Docker runner + subprocess fallback + integration test                                     |
| S5      | P1.3 finish + P1.4 start           | Calibration CI + first polyglot benchmark cases                                            |
| S6      | P1.4 finish + Phase-5 premortem    | Polyglot bench complete; round-5 adversarial premortem against everything Phase 1 shipped  |
| S7      | Remediation + v0.50.0 release      | Close premortem findings; CHANGELOG; build dist; commit; push.                              |

This is honest scheduling: 7 sessions ≈ 21 hours of work. Real-world it's probably more like 10 sessions once we factor in test debt, rebench, and the inevitable "ship dead code" round we'll need to clean up.

## Out-of-Phase-1 (defer to Phase 2+)

- **FR-XSAT-7 IAM-policy reachability.** Phase 2.
- **FR-LOGIC-1 AuthZ matrix construction.** Phase 4.
- **FR-LOGIC-2 State-machine extraction.** Phase 4.
- **FR-LOGIC-3 TOCTOU at function-pair.** Phase 4.
- **FR-SEM-6 hybrid static+dynamic.** Phase 5.
- **FR-VER-5 eBPF/dtrace live instrumentation.** Phase 5.
- **Federated learning.** Phase 4 (and requires its own design doc + privacy review).

## Bench safety

Every commit on this branch must:

- Pass `npm test` (165 + 26 unit tests).
- Pass `node --test test/no-dead-modules.test.js` (both tests).
- Pass `node test/benchmark/bench.js --strict-no-unknown` (synthetic bench F1 ≥ baseline).
- For any new SAST detector: add a fixture pair + a `_familyMap` entry + an `expected.json` block.

## Honesty discipline

Every CHANGELOG entry in Phase 1 distinguishes:

- **Shipped & wired** — production path includes the new symbol; covered by tests.
- **Shipped & scaffolded** — exported, allowlisted in `no-dead-modules`, with a `_doc` explaining why.
- **Documented only** — design doc landed but no code yet.

If the round-5 adversarial premortem finds dead code, the next release ships with a CHANGELOG correction.

---

**End of Phase 1 plan.**
