---
description: Deprecated alias — use /supply-chain-check --show alternatives. Kept one release for muscle-memory.
argument-hint: "[path] [--json]"
---

# /dep-alternatives (deprecated alias)

This command has been folded into `/supply-chain-check --show alternatives`.
The full supply-chain verdict (default `/supply-chain-check`) already
includes alternative-package suggestions; the `--show alternatives` flag
returns the alternatives-only view.

**Use `/supply-chain-check` going forward.** Examples:

```
/supply-chain-check                          # full rollup
/supply-chain-check --show alternatives      # alternatives-only (== old /dep-alternatives)
```

This alias is kept for one release so muscle-memory invocations don't break.
It will be removed in a future minor version.
