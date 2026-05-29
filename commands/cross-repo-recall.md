---
description: Look up sibling-repo fixes + triage decisions for the same family from this developer's cross-repo history.
argument-hint: "<finding-id-or-family>"
---

# /cross-repo-recall

Query the local cross-repo memory (`~/.claude/agentic-security/cross-repo/`) for past fixes and triage decisions on the same family. Surfaces "you already handled this in repo X — same fix?"

## What you'll see

```
Cross-repo signal for finding F-abc123 (family: sqli):

Past fixes for sqli in other repos:
  - repo-fp-94a2c7b1   3d ago — switched to db.prepare() with positional bindings
  - repo-fp-d6f5108e   2w ago — Knex schemaBuilder.raw replaced with chain

Past triage for sqli in other repos:
  - repo-fp-94a2c7b1   1mo ago — wont-fix (internal admin tool, not externally reachable)
```

## How the store is built

- Every `apply_fix` invocation records `{ family, fixPattern, repo-fingerprint, commitSha }` into `~/.claude/agentic-security/cross-repo/patterns.jsonl`
- Every triage transition to `wont-fix` / `false-positive` records `{ family, decision, reason, repo-fingerprint }` into `triage.jsonl`
- Repo identifiers are SHA-256 fingerprints of the git remote URL (or scan-root path), so the local file does not reveal bare repo names

## Privacy

- All data stored under the developer's `~/.claude/` — never transmitted
- Opt-out: `AGENTIC_SECURITY_NO_CROSS_REPO=1`
- File rotation at 5000 lines per log

## Implementation

```js
import { findSiblingSignals, renderSiblingNote } from '@clear-capabilities/agentic-security-scanner/posture/cross-repo-memory.js';

const signals = findSiblingSignals(scanRoot, finding);
console.log(renderSiblingNote(signals));
```

When you scan, every finding gets a `crossRepoSignal` field automatically (via the engine annotator) — this command is for explicit recall without re-scanning.
