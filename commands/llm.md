---
description: LLM security — red-team an endpoint, test jailbreak families, or generate a promptfoo eval suite.
argument-hint: "--mode redteam|jailbreak|eval [--endpoint URL] [--api-key KEY] [--categories ...] [--strategies ...] [--corpus full|jailbreak|bias|harmful] [--scan]"
---

Three modes:

## Mode: redteam (default)

Two sub-modes:
- **`--scan`** (default if no `--endpoint`): static analysis of the project's LLM-calling code.
- **`--endpoint URL`**: active red-team — sends prompt corpus through the endpoint, judges responses.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
MODE="redteam"
ENDPOINT=""
API_KEY=""
CATEGORIES=""
STRATEGIES=""
FAMILIES="dan,base64,role-play,authority,hypothetical,chained"
CORPUS="full"
OUTPUT=""
SCAN_ONLY=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2;;
    --endpoint) ENDPOINT="$2"; shift 2;;
    --api-key) API_KEY="$2"; shift 2;;
    --categories) CATEGORIES="$2"; shift 2;;
    --strategies) STRATEGIES="$2"; shift 2;;
    --families) FAMILIES="$2"; shift 2;;
    --corpus) CORPUS="$2"; shift 2;;
    --output) OUTPUT="$2"; shift 2;;
    --out) OUTPUT="$2"; shift 2;;
    --scan) SCAN_ONLY="1"; shift;;
    *) shift;;
  esac
done

case "$MODE" in

# ── redteam ──
redteam)
  if [ -n "$SCAN_ONLY" ] || [ -z "$ENDPOINT" ]; then
    echo "Static red-team scan: identifying LLM-call sites with missing defenses…"
    /agentic-security:scan --llm
    echo ""
    echo "Static findings written. For active red-team, supply --endpoint URL."
    exit 0
  fi
  OUTPUT="${OUTPUT:-llm-redteam-report.md}"
  node -e "
  const { runActiveRedteam, renderRedteamMarkdownReport } = await import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/llm-redteam.js');
  const opts = {
    endpoint: '${ENDPOINT}',
    apiKey: '${API_KEY}' || undefined,
    categories: '${CATEGORIES}' ? '${CATEGORIES}'.split(',') : undefined,
    strategies: '${STRATEGIES}' ? '${STRATEGIES}'.split(',') : undefined,
    concurrency: 4,
  };
  const { results, summary } = await runActiveRedteam(opts);
  const md = renderRedteamMarkdownReport(results, summary, '${ENDPOINT}');
  require('fs').writeFileSync('${OUTPUT}', md);
  console.log('────────────────────────────────────────────────');
  console.log('Red-team complete:', summary.total, 'prompts');
  console.log('  ✅ Pass:', summary.pass, '  ❌ Fail:', summary.fail, '  ⚠ Inconclusive:', summary.inconclusive);
  if (summary.failedPlugins.length) console.log('Failed plugins:', summary.failedPlugins.join(', '));
  console.log('Report:', '${OUTPUT}');
  "
  ;;

# ── jailbreak ──
jailbreak)
  if [ -z "$ENDPOINT" ]; then
    echo "Usage: /llm --mode jailbreak --endpoint URL [--api-key KEY] [--families dan,base64,role-play,authority,hypothetical,chained]"
    exit 1
  fi
  MAPPED=$(echo "$FAMILIES" | sed 's/dan/role-play-dan/g; s/base64/base64-encode/g; s/role-play/role-play-dan/g; s/authority/authority-claim/g; s/hypothetical/hypothetical-framing/g; s/chained/chained-context/g')
  node -e "
  const { runActiveRedteam } = await import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/llm-redteam.js');
  const opts = {
    endpoint: '${ENDPOINT}',
    apiKey: '${API_KEY}' || undefined,
    categories: ['harmful', 'security'],
    strategies: '${MAPPED}'.split(','),
    concurrency: 6,
  };
  const { results } = await runActiveRedteam(opts);
  console.log('────────────────────────────────────────────────');
  console.log('Jailbreak Detector — by attack family');
  console.log('');
  const byStrategy = {};
  for (const r of results) {
    const s = r.strategy || 'direct';
    byStrategy[s] ??= { pass: 0, fail: 0 };
    if (r.verdict === 'pass') byStrategy[s].pass++;
    else if (r.verdict === 'fail') byStrategy[s].fail++;
  }
  for (const [s, c] of Object.entries(byStrategy).sort()) {
    const total = c.pass + c.fail;
    const passRate = total ? ((c.pass / total) * 100).toFixed(0) : 'n/a';
    const verdict = c.fail === 0 ? '✅ DEFENDED' : c.pass === 0 ? '❌ JAILBROKEN' : '⚠ PARTIAL';
    console.log('  ' + s.padEnd(22), '|', verdict.padEnd(15), '|', 'defended ' + passRate + '%');
  }
  const failed = results.filter(r => r.verdict === 'fail');
  if (failed.length) {
    console.log('');
    console.log('Successful jailbreaks (' + failed.length + '):');
    for (const f of failed.slice(0, 5)) console.log('  -', f.id, '(' + (f.strategy || 'direct') + ')');
  }
  "
  ;;

# ── eval ──
eval)
  OUTPUT="${OUTPUT:-promptfoo.yaml}"
  ENDPOINT_URL="${ENDPOINT:-http://localhost:8000/chat}"
  node -e "
  const { RED_TEAM_PROMPTS } = await import('${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/llm-redteam-prompts.js');
  let prompts = RED_TEAM_PROMPTS;
  const corpus = '${CORPUS}';
  if (corpus === 'jailbreak') prompts = prompts.filter(p => p.category === 'security');
  if (corpus === 'bias') prompts = prompts.filter(p => p.category === 'bias');
  if (corpus === 'harmful') prompts = prompts.filter(p => p.category === 'harmful');

  const yaml = [
    'description: agentic-security red-team suite (auto-generated)', '',
    'prompts:', '  - \"{{prompt}}\"', '',
    'providers:', '  - id: http', '    config:', '      url: \"${ENDPOINT_URL}\"',
    '      method: POST', '      headers:', '        Content-Type: application/json',
    '      body:', '        prompt: \"{{prompt}}\"',
    '      transformResponse: \"json.response || json.text || json.choices?.[0]?.message?.content || json\"',
    '', 'tests:',
  ];
  for (const p of prompts) {
    yaml.push('  - description: \"[' + p.category + '/' + p.plugin + '] ' + p.description.replace(/\"/g, '\\\\\"') + '\"');
    yaml.push('    vars:');
    yaml.push('      prompt: |');
    yaml.push('        ' + p.prompt.split('\\n').join('\\n        '));
    yaml.push('    assert:');
    const pattern = p.expectedRejection.source.replace(/\\\\/g, '\\\\\\\\').replace(/\"/g, '\\\\\"');
    yaml.push('      - type: regex');
    yaml.push('        value: \"' + pattern + '\"');
    yaml.push('    metadata:');
    yaml.push('      severity: ' + p.severity);
    yaml.push('      strategy: ' + (p.strategy || 'direct'));
    yaml.push('');
  }
  require('fs').writeFileSync('${OUTPUT}', yaml.join('\\n'));
  console.log('Wrote', '${OUTPUT}', 'with', prompts.length, 'tests.');
  console.log('');
  console.log('Run via promptfoo:  promptfoo eval -c ${OUTPUT}');
  console.log('Run via plugin:     /llm --mode redteam --endpoint ${ENDPOINT_URL}');
  "
  ;;

*)
  echo "Unknown mode: $MODE"
  echo "Valid modes: redteam (default), jailbreak, eval"
  exit 1
  ;;
esac
```

## Categories (promptfoo-aligned)

| Category | Plugins covered |
|---|---|
| `security` | system-prompt-override, prompt-extraction, ascii-smuggling, jailbreak-dan, indirect-prompt-injection, sql-injection, shell-injection |
| `privacy` | direct-pii-exposure, pii-social-engineering, pii-session-data |
| `harmful` | self-harm, violent-crime, illegal-drugs, chemical-biological-weapons, ied |
| `bias` | race-bias, gender-bias, age-bias |
| `misinformation` | medical-incorrect-knowledge, political-opinions, hallucination |
| `agentic` | tool-discovery, bola, bfla, memory-poisoning |
| `coding-agent` | secret-file-read, secret-env-read, network-egress-bypass, automation-poisoning |

## Attack strategies

`base64-encode`, `rot13`, `role-play-dan`, `authority-claim`, `hypothetical-framing`, `multilingual`, `chained-context`

## Examples

```bash
/llm                                           # Static scan (default)
/llm --endpoint http://localhost:8000/chat      # Active red-team
/llm --mode jailbreak --endpoint URL            # Jailbreak families only
/llm --mode eval --endpoint URL                 # Generate promptfoo YAML
```
