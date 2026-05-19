---
description: Finding-level diff between two scan JSON outputs. Independent of scanner version. "What did this PR break?"
argument-hint: "[--previous <a.json>] [--current <b.json>] [--format cli|json]"
---

Compare two scan results — typically yesterday's `last-scan.json` vs today's. Surfaces added / removed / changed findings keyed on stableId (refactor-stable) or `(file, line, family)` when no stableId is present.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true

PREV=""
CURR=""
FORMAT="cli"
NEXT=""
for arg in "$@"; do
  case "$NEXT" in
    previous) PREV="$arg"; NEXT=""; continue ;;
    current) CURR="$arg"; NEXT=""; continue ;;
    format) FORMAT="$arg"; NEXT=""; continue ;;
  esac
  case "$arg" in
    --previous) NEXT="previous" ;;
    --current) NEXT="current" ;;
    --format) NEXT="format" ;;
  esac
done

# Default convenience: --previous defaults to .agentic-security/last-scan.prev.json,
# --current defaults to .agentic-security/last-scan.json. If --previous isn't given
# but a prev snapshot exists, use it.
[ -z "$PREV" ] && [ -f .agentic-security/last-scan.prev.json ] && PREV=".agentic-security/last-scan.prev.json"
[ -z "$CURR" ] && [ -f .agentic-security/last-scan.json ] && CURR=".agentic-security/last-scan.json"

if [ -z "$PREV" ] || [ -z "$CURR" ]; then
  echo "Usage: /scan-baseline --previous <a.json> --current <b.json> [--format cli|json]"
  echo ""
  echo "Default looks for .agentic-security/last-scan.prev.json + .agentic-security/last-scan.json."
  echo "To snapshot the current scan before re-scanning:"
  echo "  cp .agentic-security/last-scan.json .agentic-security/last-scan.prev.json"
  echo "  /scan --all"
  echo "  /scan-baseline"
  exit 1
fi

node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan-baseline \
  --previous "$PREV" --current "$CURR" --format "$FORMAT"
ec=$?
# Exit 1 means "delta detected" — not an error.
[ $ec -le 1 ] && exit 0 || exit $ec
```

## What's compared

| Field | When it changes |
|---|---|
| **Added** | Present in current scan, absent in previous. Likely introduced by recent commits. |
| **Removed** | Present in previous scan, absent in current. Likely fixed (or moved). |
| **Changed** | Same finding key, different `severity` / `mitigationVerdict` / `validator_verdict`. Severity drift, mitigation flip, validator promotion. |
| **Unchanged** | Same key, same fields. Reported as count only. |

## Use cases

- **PR review**: `cp .agentic-security/last-scan.json .agentic-security/last-scan.prev.json` before checkout, `/scan --all` after, `/scan-baseline` to see exactly what the branch introduced.
- **Fix verification**: snapshot before `/fix`, re-scan, `/scan-baseline` to confirm only the targeted finding moved.
- **Daily delta**: cron a daily `/scan-baseline` against yesterday's snapshot to track regressions over time.

## Distinct from `/diff-scan`

`/diff-scan` compares two SCANNER VERSIONS against the same codebase (catches scanner regressions). `/scan-baseline` compares two SCAN RESULTS against the same scanner (catches codebase regressions / fixes). Both are useful; use the right one.

🛡  agentic-security · created by ClearCapabilities.Com
