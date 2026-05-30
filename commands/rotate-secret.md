---
description: Guided revoke + scrub of a leaked secret. Aliased to /fix --rotate-secret.
---

# /rotate-secret (alias)

This command is an **alias** for `/fix --rotate-secret`. The capability is preserved exactly; this file is kept for back-compat with users who have muscle memory.

When invoked, execute `/fix --rotate-secret` with any additional arguments passed through.

For the full command surface, see `/secure --help` (or the legacy `/help`).

Forwards to: `/fix --rotate-secret $@`
