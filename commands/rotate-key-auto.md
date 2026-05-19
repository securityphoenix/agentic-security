---
description: Deprecated alias — use /rotate-secret --auto. Kept one release for muscle-memory.
argument-hint: "<leaked-value> | --scan | --provider <name> --new-value <new> | [--scrub-history]"
---

# /rotate-key-auto (deprecated alias)

This command has been folded into `/rotate-secret --auto`. Same backing script
(`scripts/rotate-key-auto.py`), same provider matrix, same safety properties.

**Use `/rotate-secret --auto` going forward.** Examples:

```
/rotate-secret --auto                                    # interactive end-to-end rotation
/rotate-secret --auto --scan                             # rescan for the leaked value
/rotate-secret --auto --provider stripe --new-value <v>  # non-interactive
/rotate-secret --auto --scrub-history                    # also purge from git history
```

This alias is kept for one release so muscle-memory invocations don't break.
It will be removed in a future minor version.
