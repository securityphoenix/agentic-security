---
description: Remediate every finding at or above a severity threshold. Silent batch — no interactive prompts.
argument-hint: "[--critical|--high|--medium|--low]  (or: --severity <tier>)"
---

Read `.agentic-security/last-scan.json` and apply remediation fixes in batch.

## Flag syntax

Both forms are accepted and equivalent:

- **Shorthand**: `/fix-all --critical`, `/fix-all --high`, `/fix-all --medium`, `/fix-all --low`
- **Long form**: `/fix-all --severity critical`, `/fix-all --severity high`, etc.

The tier is **cumulative** — `/fix-all --high` fixes both critical and high findings. `--critical` (default) fixes critical only.

## Behavior

This command runs **non-interactively**. No `[y/s/d/q]` prompts. For every finding at or above the chosen tier (default `critical`):

1. Dispatch the `security-fixer` subagent for that finding. It reads the affected file, applies the fix template adapted to the surrounding code, and runs the project test command (if one is configured).
2. After the fix applies, re-scan the affected file (`scanner --format json --since HEAD~0`) to verify the finding no longer reproduces and to detect any new findings the patch may have introduced.
3. If tests fail or the patch introduces a new finding, **do not auto-revert**. Stop the loop, report which fix broke which test (or which regression was introduced), and let the user decide whether to keep the partial progress or revert manually (`git checkout <file>`).

Fixes are applied in sequence (not parallel — each may invalidate later findings). Order: critical first, then high (if requested), then medium (if requested). Within a severity tier, order by `toxicityScore` descending so the highest-impact patches land first.

After the run, print a one-line summary:
```
Applied N fixes, M skipped (tests failed), K regressions introduced.
```

## Severity tiers

| Flag | Fixes |
|---|---|
| `--critical` (default) | Critical only |
| `--high` | Critical + High |
| `--medium` | Critical + High + Medium |
| `--low` | Everything (critical + high + medium + low) |

## Agent notes

- Use the `security-fixer` subagent for every file edit.
- Warn the user **before starting** if the git tree is dirty — the batch can't be safely rolled back if there are uncommitted changes mixed in. Suggest committing or stashing first.
- After the loop completes (or stops), the user can run `/security-scan-all` to confirm the final state.

🛡  agentic-security · created by ClearCapabilities.Com
