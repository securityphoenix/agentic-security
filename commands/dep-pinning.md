---
description: Deprecated alias — use /supply-chain-check --show pinning. Kept one release for muscle-memory.
argument-hint: "[path] [--fix] [--json]"
---

# /dep-pinning (deprecated alias)

This command has been folded into `/supply-chain-check --show pinning`. The
full supply-chain verdict (default `/supply-chain-check`) already includes
pinning; the `--show pinning` flag returns the pinning-only view.

**Use `/supply-chain-check` going forward.** Examples:

```
/supply-chain-check                          # full rollup
/supply-chain-check --show pinning           # pinning-only (== old /dep-pinning)
```

This alias is kept for one release so muscle-memory invocations don't break.
It will be removed in a future minor version.
