---
description: Stack-specific security audits (db/auth/rate-limit/etc). Aliased to /compliance --audit.
---

# /audit (alias)

This command is an **alias** for `/compliance --audit`. The capability is preserved exactly; this file is kept for back-compat with users who have muscle memory.

When invoked, execute `/compliance --audit` with any additional arguments passed through.

For the full command surface, see `/secure --help` (or the legacy `/help`).

Forwards to: `/compliance --audit $@`
