---
description: Deprecated alias — use /security-attestation --format page. Kept one release for muscle-memory.
argument-hint: "--contact <email> [--pgp <url>] [--canonical-url https://yourapp.com]"
---

# /trust-page (deprecated alias)

This command has been folded into `/security-attestation --format page`.
Same `/.well-known/security.txt`, same live `/security` HTML page, same
posture inputs.

**Use `/security-attestation` going forward.** Examples:

```
/security-attestation --format page --contact security@acme.com
/security-attestation --format page --canonical-url https://acme.com
```

This alias is kept for one release so muscle-memory invocations don't break.
It will be removed in a future minor version.
