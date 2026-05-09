---
description: Enforce a license policy across your dependency tree (allow / deny / review-required). Emits findings for components whose license violates the policy.
argument-hint: "[--init]"
---

Run the license-policy check against the current scan.

1. **First-time setup**: if `.agentic-security/license-policy.yml` does not exist, offer to create one with sensible defaults:

```yaml
# .agentic-security/license-policy.yml
allow:
  - MIT
  - Apache-2.0
  - BSD-2-Clause
  - BSD-3-Clause
  - ISC
  - 0BSD
  - Unlicense
deny:
  - GPL-3.0
  - GPL-2.0
  - AGPL-3.0
  - AGPL-1.0
  - SSPL-1.0
review:
  - LGPL-2.1
  - LGPL-3.0
  - MPL-2.0
  - EPL-2.0
unknown: review   # what to do with components missing a license: allow | deny | review
```

2. Run the scan:

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan . --format cli
```

3. License-policy violations appear as `kind: 'license'` findings. Severities:
   - **high** — denied license (e.g., GPL-3.0 in a closed-source product)
   - **low** — license requires manual review (LGPL/MPL) or no declared license

## Why this exists

License compliance is a board-level concern in any commercial product (especially closed-source). The policy file is the single source of truth — your legal team owns it; the scanner just enforces it on every commit.
