---
description: Deprecated alias — use /explain --narrative. Kept one release for muscle-memory.
argument-hint: "<finding-id> | --random | --worst | --post-mortem"
---

# /story-explain (deprecated alias)

This command has been folded into `/explain --narrative`. Same persona table,
same template, same `--post-mortem` variant.

**Use `/explain --narrative` going forward.** Examples:

```
/explain --narrative CWE-89
/explain --narrative --random
/explain --narrative --worst
/explain --narrative --post-mortem CWE-639
```

This alias is kept for one release so muscle-memory invocations don't break.
It will be removed in a future minor version.
