---
description: Three-agent review of ONE finding — red (attack) / blue (hardening) / auditor. Hash-chained transcript trio.
argument-hint: "--finding <id> [--target <url>] [--max-calls 30] [--max-wall-ms 480000]"
---

Run the full red-team → blue-team → auditor cascade on a single finding from the last scan. Each phase emits a hash-chained transcript; the auditor's verdict is the canonical output (`exploit-confirmed` / `exploit-mitigable` / `exploit-uncertain` / `exploit-rejected`).

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true

FINDING=""
TARGET=""
MAX_CALLS="30"
MAX_WALL_MS="480000"
NEXT=""
for arg in "$@"; do
  case "$NEXT" in
    finding) FINDING="$arg"; NEXT=""; continue ;;
    target) TARGET="$arg"; NEXT=""; continue ;;
    max-calls) MAX_CALLS="$arg"; NEXT=""; continue ;;
    max-wall-ms) MAX_WALL_MS="$arg"; NEXT=""; continue ;;
  esac
  case "$arg" in
    --finding) NEXT="finding" ;;
    --target) NEXT="target" ;;
    --max-calls) NEXT="max-calls" ;;
    --max-wall-ms) NEXT="max-wall-ms" ;;
  esac
done

if [ -z "$FINDING" ]; then
  echo "Usage: /three-agent-review --finding <id> [--target <url>] [--max-calls 30] [--max-wall-ms 480000]"
  echo ""
  echo "Without --target the red team operates in dry-run mode (static reasoning only)."
  echo "Without AGENTIC_SECURITY_LLM_ENDPOINT, every phase short-circuits to its static-analysis equivalent — still produces a useful verdict."
  exit 1
fi

mkdir -p .agentic-security/three-agent-transcripts

node -e "
const fs = require('fs');
const path = require('path');
const { runThreeAgentReview } = require('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/three-agent-pipeline.js');
let scan;
try { scan = JSON.parse(fs.readFileSync('.agentic-security/last-scan.json','utf8')); }
catch { console.log('No scan yet. Run /scan first.'); process.exit(0); }
const id = process.env.FINDING;
const target = process.env.TARGET;
const maxCalls = parseInt(process.env.MAX_CALLS || '30', 10);
const maxWallMs = parseInt(process.env.MAX_WALL_MS || '480000', 10);
const f = (scan.findings || []).find(x => x.id === id || x.stableId === id);
if (!f) { console.log('No finding matches ' + id); process.exit(0); }

const W = (s,c) => process.stdout.isTTY ? '\x1b['+c+'m'+s+'\x1b[0m' : s;
const BOLD='1', DIM='2', RED='31', YELLOW='33', GREEN='32', CYAN='36';

(async () => {
  console.log('');
  console.log(W('Three-agent review', BOLD));
  console.log(W('  Finding: ' + (f.vuln || '') + '  ' + f.file + ':' + f.line, DIM));
  console.log(W('  Target:  ' + (target || '(none — dry-run)'), DIM));
  console.log(W('  Budget:  ' + maxCalls + ' calls / ' + (maxWallMs/1000) + 's wall', DIM));
  console.log('');

  const result = await runThreeAgentReview(f, { target, maxCalls, maxWallMs });

  console.log(W('▼ Phase 1 — Red Team', RED));
  console.log('  outcome:        ' + result.red.outcome);
  console.log('  tool-calls:     ' + result.red.toolCallCount);
  console.log('  transcript:     ' + result.red.transcriptHead);
  console.log('');

  console.log(W('▼ Phase 2 — Blue Team (defender)', CYAN));
  console.log('  mode:           ' + result.blue.mode);
  console.log('  recommendations:');
  for (const r of result.blue.recommendations) console.log('    • ' + r);
  console.log('  transcript:     ' + result.blue.transcriptHead);
  console.log('');

  const VC = result.auditor.verdict === 'exploit-confirmed' ? RED
           : result.auditor.verdict === 'exploit-mitigable' ? YELLOW
           : result.auditor.verdict === 'exploit-rejected' ? GREEN
           : DIM;
  console.log(W('▼ Phase 3 — Auditor', BOLD));
  console.log('  ' + W('VERDICT: ' + result.auditor.verdict, VC + ';' + BOLD));
  console.log('  rationale: ' + result.auditor.rationale);
  console.log('  mode:       ' + result.auditor.mode);
  console.log('  transcript: ' + result.auditor.transcriptHead);
  console.log('');

  const out = path.join('.agentic-security', 'three-agent-transcripts', (f.stableId || f.id || 'transcript') + '.json');
  fs.writeFileSync(out, JSON.stringify(result, null, 2));
  console.log(W('Full envelope: ' + out, DIM));
})();
" FINDING=\"$FINDING\" TARGET=\"$TARGET\" MAX_CALLS=\"$MAX_CALLS\" MAX_WALL_MS=\"$MAX_WALL_MS\"
```

## Outcomes

| Auditor verdict | Meaning |
|---|---|
| **`exploit-confirmed`** | Red team produced data-exfil / priv-esc / account-takeover AND no static hardening template exists. Manual remediation required. |
| **`exploit-mitigable`** | Red team confirmed but blue team's recommendations would close it. Apply the patches and re-run. |
| **`exploit-uncertain`** | Red team did not reach a business-impact outcome (aborted-budget / timeout / no LLM endpoint). Re-run with a longer budget or live target. |
| **`exploit-rejected`** | Red team failed. Defense appears adequate against the modeled attacker. |

## When to use

- **Promotion review** — before promoting a finding from "high" to "blocker," run the full cascade to confirm a real attacker would reach business impact.
- **Critique a fix** — after applying a /fix patch, re-run to confirm the auditor flips from `exploit-confirmed` / `exploit-mitigable` to `exploit-rejected`.
- **Pre-incident drill** — pre-prod review with the staging URL as `--target`.

## Cost

Every phase honors the budget. Without `AGENTIC_SECURITY_LLM_ENDPOINT`, all three phases short-circuit to static analysis — useful even offline. With an LLM endpoint, expect ~3× single-finding adversary-agent cost (red + blue + auditor each invoke the model).

🛡  agentic-security · created by ClearCapabilities.Com
