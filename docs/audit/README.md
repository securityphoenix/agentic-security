# External audit sign-off

This directory is the home for **external auditor sign-off files** on the
benchmark corpora the project uses. It is currently **empty**. No corpus has
an external sign-off on file.

## What changed

The benchmark manifest previously carried `auditorVerified: true` flags on
six corpora (OWASP Benchmark, SARD Juliet Java / C# / C/C++, BigVul,
CVEfixes). That flag was a self-attestation — it meant *"the ground truth
of this corpus derives 1:1 from an upstream artifact we trust"* (e.g.
upstream's `expectedresults-1.2.csv`). It did NOT mean an external party
had reviewed and confirmed our use of that artifact.

To avoid confusion in published numbers, the flag has been renamed to
`auditorVerifiedSource: "<provenance>"`:

| Old | New | Meaning |
|---|---|---|
| `auditorVerified: true` (OWASP Benchmark) | `auditorVerifiedSource: "upstream-csv"` | GT derives from upstream's per-test CSV |
| `auditorVerified: true` (Juliet Java/C#/C-C++) | `auditorVerifiedSource: "upstream-juliet-folders"` | GT derives from upstream's `CWE<N>_*` folder convention |
| `auditorVerified: true` (BigVul) | `auditorVerifiedSource: "upstream-csv-claimed"` | GT derives from upstream's CSV (CSV-claimed, not externally re-checked) |
| `auditorVerified: true` (CVEfixes) | `auditorVerifiedSource: "upstream-sqlite-claimed"` | GT derives from upstream's SQLite (DB-claimed) |
| `auditorVerified: false` | (field absent) | Self-bootstrapped or curated; no upstream artifact |

The new label is provenance-only. The path to a real external sign-off is
below.

## How to add an external sign-off

1. The external reviewer walks the manifest entry for the corpus and
   confirms that the ground truth derivation in `bench-realworld.js` is
   faithful to the upstream artifact.
2. They (and the project) commit a file in this directory:

   ```
   docs/audit/<corpus-name>-<YYYY-MM-DD>.md
   ```

   With this structure:

   ```markdown
   # External audit — <corpus-name>

   - **Corpus:** <name>
   - **Upstream artifact:** <e.g. https://github.com/OWASP-Benchmark/BenchmarkJava/blob/<sha>/expectedresults-1.2.csv>
   - **Manifest entry:** scanner/test/benchmark/realworld/manifest.json#apps.<name>
   - **Auditor:** <Name, Affiliation, contact>
   - **Date:** YYYY-MM-DD
   - **Scope:** <what the auditor checked>
   - **Findings:** <what they confirmed / what they did not confirm>
   - **Signature / attestation:** <PGP signature, or signed-off-by line>
   ```

3. The auditor remains responsible for what they confirmed. The project
   is responsible for not silently changing ground-truth derivation
   without re-engaging them.

## Why no scores live in this directory

Numbers go stale. Audits attest to **methodology** — that the corpus is
what we say it is, and that the harness derives expected entries
correctly from upstream. Scores from a particular release are recorded
in the per-CWE history file under `.agentic-security/validator-metrics.json`
(local, gitignored) and in any release notes.

## Until a sign-off exists

The project's policy is:

- Do not publish single-corpus F1 numbers in any user-facing document.
- Do not publish aggregate scores without naming every corpus in the
  aggregate.
- Report Youden Index (TPR − FPR) alongside any F1 for corpora that
  declare a negative class.
