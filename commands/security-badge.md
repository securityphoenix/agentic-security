---
description: Deprecated alias — use /security-attestation --format badge. Kept one release for muscle-memory.
argument-hint: "[--apply]"
---

# /security-badge (deprecated alias)

This command has been folded into `/security-attestation --format badge`.
Same shield, same investor-ready summary, same source-of-truth.

**Use `/security-attestation` going forward.** Examples:

```
/security-attestation                            # badge (default)
/security-attestation --format badge --apply     # write README badge inline
```

This alias is kept for one release so muscle-memory invocations don't break.
It will be removed in a future minor version.
