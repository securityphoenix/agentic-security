---
description: Estimate engineering hours per finding — quantify the security debt this PR / branch / repo carries.
argument-hint: "[--top <n>] [--by family|file] [--summary]"
---

# /time-to-fix

For each open finding, estimate engineering hours to remediate. Total + per-family rollup answers PM/CFO questions like "how much of next sprint will fixing this take?"

## Example

```bash
/time-to-fix --summary
```

Output:
```
138 finding(s) — ~84.5 engineering hours of security debt.

Top families:
  authz     22.0h  (11 findings)
  sqli      11.5h  (23 findings)
  hardcoded-secret  8.0h  (8 findings)

Source mix:
  68 findings estimated from project's own fix history
  70 findings estimated from family-base defaults
```

## How estimates work

For each finding:
1. **Base hours** come from either:
   - Project's `.agentic-security/fix-history/log.json` for the same family (preferred — learned from your repo)
   - Family-base defaults from `posture/time-to-fix.js#FAMILY_BASE_HOURS`
2. **Patch-shape adjustment** — if `fix.code` is present in the finding, multiply by 1.0 (≤3 lines) / 1.4 (≤10) / 2.0 (≤30) / 3.0 (>30)
3. **Reachability adjustment** — public-reachable findings need more testing (×1.3); unreachable findings need less (×0.7)

## Source transparency

Each finding gets a `estimatedFixHoursSource` field:
- `history` — learned from the project's own past fixes (most accurate)
- `family-base` — fell back to the curated default

When your repo accumulates fix history, the estimates improve automatically.

## Implementation

The annotator runs at scan time. This command just formats `last-scan.json`:

```js
import { annotateTimeToFix, renderTimeSummary } from '@clear-capabilities/agentic-security-scanner/posture/time-to-fix.js';

const scan = readLastScan(scanRoot);
const roll = annotateTimeToFix(scanRoot, scan.findings);
console.log(renderTimeSummary(roll));
```

## Use cases

- **PR commenting** — pair with `/pr-augment` to surface "this PR ships +6h of security debt" inline
- **Sprint planning** — `/time-to-fix --summary` answers "can we close all criticals in next sprint?"
- **Budget conversations** — combine with `/risk-dollars` to compute ROI: "$420k of expected loss for 84h of work"
