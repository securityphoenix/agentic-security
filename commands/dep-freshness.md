---
description: Deprecated alias — use /supply-chain-check --show freshness. Kept one release for muscle-memory.
argument-hint: "[path] [--json] [--ecosystem npm|pip|cargo|gem|pub|packagist]"
---

# /dep-freshness (deprecated alias)

This command has been folded into `/supply-chain-check --show freshness`. The
full supply-chain verdict (default `/supply-chain-check`) already includes
freshness; the `--show freshness` flag returns the freshness-only view.

**Use `/supply-chain-check` going forward.** Examples:

```
/supply-chain-check                          # full rollup
/supply-chain-check --show freshness         # freshness-only (== old /dep-freshness)
```

This alias is kept for one release so muscle-memory invocations don't break.
It will be removed in a future minor version.
