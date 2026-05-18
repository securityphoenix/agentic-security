# Changelog

## 0.47.0 — third-round premortem remediation

Third adversarial premortem identified 17 findings against the v0.46.0
remediation. All 17 are now closed. Highlights:

- **3R-1: integration test for dead exports** — new `test/no-dead-modules.test.js`
  walks `scanner/src/{posture,llm-validator,dataflow,lsp,ir,mcp}` and asserts
  every exported symbol has at least one external call site (`.js` files and
  `commands/*.md`). Allowlist for legitimate library-style exports. Closes the
  recurring "wired in code review, dead in code" failure mode.

- **3R-2 / 3R-3: single-sourced version** — `scanner/src/posture/version.js`
  reads `scanner/package.json#version` at module load; SARIF `tool.driver.version`
  and `CURRENT_RULESET_VERSION` now derive from it instead of independently
  hardcoded constants that diverged on every release.

- **3R-4: signing graceful degradation** — `rule-pack-signing.js` operates in a
  pass-through mode when both bundled and project keys are absent. One audit
  warning per session; findings carry `_passThroughSigning:true`. Set
  `AGENTIC_SECURITY_STRICT_SIGNING=1` to disable pass-through.

- **3R-5: CLI keygen safety rails** — `agentic-security-rule keygen` refuses
  `--out` paths under `.agentic-security/`; warns on non-TTY stdout without
  `--out`; writes private-key files mode 0600. `--i-understand-private-keys`
  to override.

- **3R-6: provenance surfaced in reports** — `normalizeFindings` carries
  `_unsigned` and `_passThroughSigning` through; SARIF `result.properties`
  emits `unsigned:true` / `passThroughSigning:true`; SARIF
  `invocations[].properties` now includes `rulesetVersion`, `rulesetVersionSource`,
  and `rulesetVersionMismatch` for trend attribution.

- **3R-7: requiresReAudit is now load-bearing** — `bench-realworld.js` reads
  curated expected JSONs' `requiresReAudit:true`, emits a stderr warning per
  affected corpus, and tags the corpus result with
  `requiresReAudit:true` so consumers know its F1 is informational.

- **3R-8: global deadline for custom rules** — `applyCustomRules()` now caps
  the total scan time across all files and all rules at 30s (overridable via
  `AGENTIC_SECURITY_CUSTOM_RULES_BUDGET_MS`), guarding against ReDoS sprees
  across many files even when each individual regex respects its 200ms budget.

- **3R-9: LSP dep-cache invalidation on manifest save** — saving any
  `package.json`/`pyproject.toml`/`Cargo.toml`/etc. now invalidates the cached
  dep snapshot before re-scanning, so freshly added vulnerable packages and
  removed ones reflect immediately in editor diagnostics.

- **3R-10: catalog OFFICIAL_ONLY is per-match** — `AGENTIC_SECURITY_CATALOG_OFFICIAL_ONLY=1`
  is now read per source/sink match instead of once at module load, so CI lanes
  that toggle strict mode just before invocation are actually honored.

- **3R-11: validator preflight handles SCA locators** — findings with
  `parser:'SCA'` or `pkg`/`component`/`purl` set are tagged
  `validator_verdict:'not-applicable'` rather than `'unvalidated'`, which
  was misleading for findings that an LLM cannot meaningfully judge.

- **3R-12: applyFix recover() cross-checks against last-scan.json** — the
  fix-history log entry records the matching finding's stableId at apply
  time; `recover()` after a crash now tags promoted entries as
  `applied-stale` when the finding has vanished from last-scan.json.

- **3R-13: file lock around log writes** — concurrent `applyFix`, `recover`,
  and `undo` invocations no longer race the `log.json` write; serialization
  via `log.lock` with 30s stale-lock reaping and 5s contention timeout.

- **3R-14: validator-cache GC subcommand** — `agentic-security validator-cache
  stats|gc [--older-than N] [--dry-run]` prunes `.agentic-security/llm-cache/`
  by age and prompt-version mismatch.

- **3R-15: tier cutoffs stable under 2-decimal rounding** — confidence tier
  (`high|medium|low|very-low`) is now derived from the 2-decimal display value,
  so a finding reported as "0.75" never lands in two tiers depending on the
  viewer's rounding.

- **3R-16: CHANGELOG ships with npm package** — `prepublishOnly` copies
  CHANGELOG.md into `scanner/`; added to `package.json#files`. The repo-root
  copy remains canonical; the in-package copy is gitignored.

- **3R-17: fix-history log compaction** — `agentic-security undo --compact
  [--retain-days N] [--prune-backups]` archives terminal entries (reverted,
  failed, applied-stale) older than the retention window into
  `log-archive-YYYY-MM.json`, optionally pruning their `.bak` files.

### Honesty correction

No claims in this release exceeded what shipped. v0.47.0 closes the 17
third-round premortem findings against v0.46.0 cleanly; the round-4 premortem
will surely find more, and that is fine.

## 0.46.0 — second-round premortem remediation + honesty correction

### Honesty correction for v0.45.0

The v0.45.0 commit message (`3acca6b fix(security): premortem remediation —
all 15 findings`) claimed all 15 first-round premortem findings were
remediated. A second-round adversarial premortem identified five of those
"closures" as dead code or wire-up regressions:

- `posture/fix-history.js::recover()` was exported but never called from
  any startup path → pending entries from a crashed `applyFix` accumulated
  forever. **Now fixed**: wired into `runScan.js` at top of every scan.

- `posture/ruleset-version.js::stampScan()` / `effectiveVersion()` were
  exported but never imported → ruleset-pinning was documentation only.
  **Now fixed**: wired into `runScan.js` to stamp every scan result.

- `posture/validator-metrics.js::recordTriage()` was exported but the
  `/triage` slash command did not invoke it → per-CWE production metrics
  never accumulated. **Now fixed**: `/triage` now calls `recordTriage` on
  every verdict (subject to the new symmetric learn gate).

- The custom-rules pipeline tagged unsigned RULES with `_unsigned: true`
  but the per-finding emitter (`toFinding`) did not copy the marker →
  the audit chain promised by the warning log did not exist in the data.
  **Now fixed**: findings now carry `_unsigned: true` when their rule does.

- `engine.js:6941` called the LLM validator with `concurrency: 4`,
  overriding the validator's `concurrency: 1` determinism default →
  cache-cold runs produced non-deterministic SARIF in the same commit
  that promised determinism. **Now fixed**: respects `AGENTIC_SECURITY_LLM_CONCURRENCY` env (default 1).

### Other second-round fixes

- **String-aware JSON parser** in the LLM validator. Previous
  `parseLastJsonObject` ignored string-state and could be fooled by braces
  inside JSON string literals. Rewritten to walk forward with full string-
  and escape-state tracking, then return the LAST valid candidate.

- **Empty file/line pre-flight** in `validateOne`. A validator response of
  `{"file":"","line":0,...}` trivially satisfied the cross-check on findings
  without precise location. Now refused with `unvalidated`.

- **Protected signing trust root**: trusted keys come from a built-in
  constant (`BUNDLED_OFFICIAL_KEYS`); project-local `.agentic-security/trusted-keys.json`
  is refused unless `AGENTIC_SECURITY_ALLOW_PROJECT_KEYS=1` is set
  (audit-logged). A PR contributor can no longer bootstrap a key into trust.

- **Key revocation**: trusted-keys.json `crl[]` honored (signature-hash
  blacklist); `revokedAt` field on each key honored (signatures dated after
  revocation refused).

- **`agentic-security-rule` CLI** for `keygen` / `sign` / `verify` with a
  first-time setup walkthrough and explicit private-key-handling warnings.

- **Symmetric AGENTIC_SECURITY_LEARN gate**: `/triage` no longer writes
  verdicts to `triage-feedback.json` without explicit opt-in. Prevents an
  attacker from poisoning the file in advance of someone flipping the
  read-side flag.

- **Worklist deadline check**: deep-mode taint engine honors `deadlineMs`
  inside `analyzeFunction`'s worklist (every 128 iterations). Pathological
  CFGs can no longer hold past the global timeout.

- **LSP loads dep-manifest files**: per-save scan in `lsp/server.js` now
  pre-walks the project tree once for `package.json` / `pom.xml` / `.proto`
  / `.graphql` / `.tf` so SCA + cross-language passes have their inputs.

- **SARIF notifications for caveats**: `tool.driver.notifications` and
  `invocations.toolExecutionNotifications` now carry the load-bearing
  warnings (priority scores are ordinal, OWASP Benchmark numbers are
  benchmark-tuned). Customer CI ingesters see them without reading docs.

- **Re-sanitization on cache read**: validator reasoning passes through
  `sanitizeReasoning` again on cache hit (defense in depth against any
  future write-path regression).

- **Provenance + requiresReAudit fields** added to all 25 bootstrapped GT
  files under `bench/.../expected/`. Machine-readable signal that the
  bootstrap origin is self-referential.

### What this commit honestly does NOT close

- BUNDLED_OFFICIAL_KEYS is empty — a production deployment needs the
  maintainers to generate a real keypair, distribute the private key
  offline, and ship the public key. Today's effective behavior is "no
  official keys, project keys via opt-in."
- The CVE-replay corpus is still 1 starter entry (G1 second half remains
  not delivered).
- Real-world Java F1 generalization is still unmeasured.

## 0.45.0 — first-round premortem remediation

(See commit 3acca6b. Some closures were dead-code; see honesty correction
above.)

## 0.44.0 — multi-session items: gRPC/GraphQL/ORM cross-lang, IDE plugins

## 0.43.0 — small engineering items: MCP verify_fix/synthesize_fix,
SentQL path predicates, conversation-context hook, fix-plan,
per-CWE metrics

## 0.42.0 — Layer 1 IR + Layer 2 interprocedural taint, F1=0.907 on
OWASP Bench v1.2 (blind, strict)
