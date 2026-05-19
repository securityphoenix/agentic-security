---
description: Deprecated alias — use /security-attestation --format onepager. Kept one release for muscle-memory.
argument-hint: "[--output PATH] [--company NAME] [--contact EMAIL]"
---

# /security-onepager (deprecated alias)

This command has been folded into `/security-attestation --format onepager`.
Same `SECURITY.md` template, same scan-posture inputs, same enterprise
questionnaire shape.

**Use `/security-attestation` going forward.** Examples:

```
/security-attestation --format onepager
/security-attestation --format onepager --output SECURITY.md --company "Acme"
```

This alias is kept for one release so muscle-memory invocations don't break.
It will be removed in a future minor version.
