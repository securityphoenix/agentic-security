---
description: Diff two scans (or two refs) for posture changes — new/removed endpoints, new/removed deps, lost auth boundaries, newly exposed data classes, severity deltas. Pairs with /security-baseline and /security-material-change.
argument-hint: "[--from <baseline.json|ref>] [--to <baseline.json|ref|HEAD>]"
---

Compute posture drift between two scans.

1. Resolve `--from` and `--to`:
   - If both are JSON paths, load them directly.
   - If `--from` is a git ref, run `git checkout <ref> -- .` in a temp worktree, scan, capture; then restore. (Or simpler: ask the user to save a baseline first via `/security-baseline save`.)
   - Default `--from = .agentic-security/baseline.json`, `--to = current scan`.

2. Run the diff:

```bash
node -e "
const { driftBetween, driftToMarkdown } = await import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/drift.js');
const fs = await import('node:fs/promises');
const a = JSON.parse(await fs.readFile('${FROM:-.agentic-security/baseline.json}', 'utf8'));
const b = JSON.parse(await fs.readFile('${TO:-.agentic-security/last-scan.json}', 'utf8'));
process.stdout.write(driftToMarkdown(driftBetween(a, b)));
"
```

3. Print the Markdown output verbatim. The report contains:
   - **Headline tier** (info / low / medium / high / critical)
   - **Auth boundaries lost** — every previously-authenticated route now exposed
   - **New endpoints** — flagged with 🔒 (auth) or ⚠️ (unauth)
   - **New dependencies** and **new CVEs introduced**
   - **New findings** + severity delta
   - **Newly exposed data classes** (PII / PHI / PCI / Confidential)

4. Suggest follow-ups based on the headline tier:
   - `critical` (auth boundary lost or new critical finding) → recommend `/security-poc <id>` for the new finding and `/security-fix` to restore the boundary.
   - `high` (new unauth endpoints, new high-tier CVE) → recommend `/security-chain` to check whether the new surface combines with existing findings into an attack chain.
   - `medium`/`low`/`info` → no follow-up needed; safe to merge.

## Why this exists

With baseline + drift you ratchet your security posture forward — new bugs can't sneak in unnoticed, and lost auth boundaries are flagged before merge.
