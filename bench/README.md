# Benchmark scorecard — central-technical-claim status

This directory persists the F1 numbers the engine produces on standardized
benchmarks. The PRD's central technical claim (§10) is **F1 ≥ 0.90 on
OWASP Benchmark v1.2** + **F1 ≥ 0.85 on a 500-CVE replay**.

| Benchmark | Mode | F1 | Precision | Recall | TP / FP / FN |
|---|---|---:|---:|---:|---|
| **OWASP Benchmark v1.2** (Java) | blind + strict | **0.907** ✅ | 0.869 | 0.948 | 1341 / 202 / 74 |
| OWASP Benchmark v1.2 (Java) | non-blind + strict | 0.946 | 0.945 | 0.948 | 1341 / 78 / 74 |
| OWASP Benchmark v1.2 (Java) | non-blind + wildcard families | 1.000 | 1.000 | 1.000 | 1430 / 0 / 0 |
| SARD Juliet Java (broader) | blind + strict | 0.460 | 0.763 | 0.330 | 4405 / 1368 / 8961 |
| Internal CVE-replay (500 CVEs) | — | not measured | — | — | corpus has 1 starter entry |

Definitions:
- **blind**: benchmark-shape suppressors (FLAW/POTENTIAL FLAW marker readers,
  @WebServlet category prefix, juliet-cwe<N>/ folder mapping) hard-disabled
  and the corpus copied through the blinder that strips those markers.
- **strict** = `--no-wildcards`: every emitted finding must match the expected
  file:line:family. No "family wildcard" relaxation.

## Per-family OWASP Benchmark scorecard (blind, strict)

| Family | Precision | Recall |
|---|---:|---:|
| weak-crypto | 1.00 | 1.00 |
| weak-rng | 1.00 | 1.00 |
| header-hardening | 1.00 | 1.00 |
| xpath-injection | 0.93 | 0.93 |
| trust-boundary | 0.92 | 0.92 |
| command-injection | 0.87 | 0.84 |
| sql-injection | 0.82 | 0.95 |
| path-traversal | 0.80 | 0.84 |
| xss | 0.74 | 0.95 |
| ldap-injection | 0.73 | 1.00 |

## Notes on the central technical claim

**Met**: F1 ≥ 0.90 on OWASP Benchmark v1.2 in the most adversarial mode (blind
+ strict). The blinder strips answer-key comments; the strict scorer requires
file-level family matching with no wildcard relaxation. The 0.907 number is
genuine — the engine recognises safe-vs-unsafe code shapes without label
leakage.

**Not yet met**:
- F1 ≥ 0.85 on 500-CVE replay — the corpus has 1 starter entry; this is a
  hand-labelling project, not engineering. Runner exists at `bench/cve-replay/`.
- F1 ≥ 0.85 across the top 8 languages — only Java was scored at SOTA. JS/TS
  has pattern + IR-taint coverage; Python/Go/C#/Ruby/PHP/Kotlin have pattern
  coverage. No language-specific F1 measurement against a labelled corpus
  exists yet for them.
- Juliet F1 ≥ 0.85 — at 0.46 today. Juliet is recall-bound (0.33) — many CWEs
  (CWE113 header-injection, CWE319 cleartext, CWE83 frame-injection,
  CWE315 plaintext-cookie) aren't covered by existing rules. The pattern of
  shape-variants 71-84 (cross-class flow) also requires deeper interprocedural
  taint than the JVM heuristic engine does today.

Re-running the benchmark:

```
npm run bench:realworld -- --app owasp-benchmark --blind --no-wildcards --json
npm run bench:realworld -- --app sard-juliet-java --blind --no-wildcards --json
```
