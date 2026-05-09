---
description: Export the project's API surface as Markdown / JSON / OpenAPI 3.1. Each endpoint is annotated with auth status (🔒 / ⚠️) and data classifications (PII / PHI / PCI / Confidential). Required deliverable for customer security questionnaires.
argument-hint: "[--format md|json|openapi] [--output api-inventory.md]"
---

Generate an API inventory from the last scan.

```bash
node -e "
const { runScan } = await import('${CLAUDE_PLUGIN_ROOT}/scanner/src/runScan.js');
const { toAPIInventoryMarkdown, toAPIInventoryJSON, toOpenAPI } = await import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/api-inventory.js');
const { scan, meta } = await runScan('.');
const fmt = '${FORMAT:-md}';
let body;
if (fmt === 'json') body = JSON.stringify(toAPIInventoryJSON(scan), null, 2);
else if (fmt === 'openapi') body = JSON.stringify(toOpenAPI(scan, meta), null, 2);
else body = toAPIInventoryMarkdown(scan);
process.stdout.write(body);
"
```

Output formats:

- **md** (default) — Markdown table with `Method | Path | Auth | Data classes | File:Line`. Sorted by risk: unauthenticated + sensitive-data first.
- **json** — Machine-readable inventory with summary + per-route fields.
- **openapi** — OpenAPI 3.1 stub including `bearerAuth` security scheme and `x-agentic-security-data-classes` extensions per operation.

Recommended next step: pair with `/security-drift` so you can see which API endpoints were added or lost auth between two scans.

## Why this exists

API inventory is a top-tier ASPM deliverable — it answers the auditor's first question ("show me your API surface") without manual cataloguing. The inventory is built from the route inventory the engine already produces during every scan, so the cost is zero per scan.
