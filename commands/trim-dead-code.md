---
description: Deprecated alias — use /trim --what code. Kept one release for muscle-memory.
argument-hint: "[path] [--language js|ts|py|go|rust] [--include-wrappers] [--skip-dynamic-check] [--apply]"
---

# /trim-dead-code (deprecated alias)

This command has been folded into `/trim --what code`. Same backing
behavior, same flags, same multi-tier SAFE/CAUTION/DANGER output.

**Use `/trim --what code` going forward.** Examples:

```
/trim --what code                           # report only, all languages
/trim --what code --apply                   # batch-remove SAFE-tier
/trim --what code --language js --apply     # JS/TS only
```

This alias is kept for one release so muscle-memory invocations don't break.
It will be removed in a future minor version.
