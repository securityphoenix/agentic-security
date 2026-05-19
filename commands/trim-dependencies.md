---
description: Deprecated alias — use /trim --what deps (or /trim for both). Kept one release for muscle-memory.
argument-hint: "[--include-dead-code] [--apply]"
---

# /trim-dependencies (deprecated alias)

This command has been folded into `/trim`. Default `/trim` runs both passes
(deps + dead code); `/trim --what deps` is the dep-only path.

**Use `/trim` or `/trim --what deps` going forward.** Examples:

```
/trim                            # both: deps + dead code (== old --include-dead-code)
/trim --what deps                # deps only (== old /trim-dependencies)
/trim --what deps --apply        # remove unused deps now
```

This alias is kept for one release so muscle-memory invocations don't break.
It will be removed in a future minor version.
