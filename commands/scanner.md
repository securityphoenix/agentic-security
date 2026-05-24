---
description: Scanner meta — self-test, version diff, scan baseline, concurrency check, spec-drift check.
argument-hint: "--self-test | --diff | --baseline | --concurrency | --spec-drift [mode-specific flags...]"
---

Scanner engineering and specialized scan modes behind one command.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true

MODE=""
for arg in "$@"; do
  case "$arg" in
    --self-test)    MODE="self-test" ;;
    --diff)         MODE="diff" ;;
    --baseline)     MODE="baseline" ;;
    --concurrency)  MODE="concurrency" ;;
    --spec-drift)   MODE="spec-drift" ;;
  esac
done

if [ -z "$MODE" ]; then
  echo ""
  echo "Usage: /scanner <mode>"
  echo ""
  echo "  --self-test      Adversarial self-test — mutate fixtures, surface detector gaps"
  echo "  --diff           Differential scanner — compare two scanner versions on same tree"
  echo "  --baseline       Finding-level diff between two scan JSON outputs"
  echo "  --concurrency    Surface concurrency bugs (missed unlocks, deadlocks, fire-and-forget)"
  echo "  --spec-drift     Functions whose names claim behavior the body doesn't deliver"
  echo ""
  exit 0
fi

case "$MODE" in

# ── self-test ──
self-test)
  FIXTURES="scanner/test/fixtures"
  OUTPUT="self-test-results.json"
  NEXT=""
  for arg in "$@"; do
    case "$NEXT" in
      fixtures) FIXTURES="$arg"; NEXT="" ; continue ;;
      output) OUTPUT="$arg"; NEXT="" ; continue ;;
    esac
    case "$arg" in
      --fixtures) NEXT="fixtures" ;;
      --output) NEXT="output" ;;
    esac
  done
  cd "${CLAUDE_PLUGIN_ROOT}" 2>/dev/null || true
  node scripts/self-test-runner.mjs --fixtures "$FIXTURES" --output "$OUTPUT"
  ec=$?
  if [ $ec -eq 0 ]; then
    echo ""; echo "✅  No detector gaps — every mutation was caught."
  elif [ $ec -eq 1 ]; then
    echo ""; echo "❌  Detector gaps detected. See $OUTPUT for the mutation matrix."
  fi
  exit 0
  ;;

# ── diff (two scanner versions on same tree) ──
diff)
  BASELINE="" CANDIDATE="" ROOT="." FORMAT="cli" NEXT=""
  for arg in "$@"; do
    case "$NEXT" in
      baseline) BASELINE="$arg"; NEXT=""; continue ;;
      candidate) CANDIDATE="$arg"; NEXT=""; continue ;;
      root) ROOT="$arg"; NEXT=""; continue ;;
      format) FORMAT="$arg"; NEXT=""; continue ;;
    esac
    case "$arg" in
      --baseline) NEXT="baseline" ;; --candidate) NEXT="candidate" ;;
      --root) NEXT="root" ;; --format) NEXT="format" ;;
    esac
  done
  if [ -z "$BASELINE" ] || [ -z "$CANDIDATE" ]; then
    echo "Usage: /scanner --diff --baseline <prev.mjs> --candidate <new.mjs> [--root .]"
    exit 1
  fi
  node ${CLAUDE_PLUGIN_ROOT}/scanner/bin/agentic-security-diff.js \
    --baseline "$BASELINE" --candidate "$CANDIDATE" --root "$ROOT" --format "$FORMAT"
  [ $? -le 1 ] && exit 0 || exit $?
  ;;

# ── baseline (two scan JSONs) ──
baseline)
  PREV="" CURR="" FORMAT="cli" NEXT=""
  for arg in "$@"; do
    case "$NEXT" in
      previous) PREV="$arg"; NEXT=""; continue ;;
      current) CURR="$arg"; NEXT=""; continue ;;
      format) FORMAT="$arg"; NEXT=""; continue ;;
    esac
    case "$arg" in
      --previous) NEXT="previous" ;; --current) NEXT="current" ;; --format) NEXT="format" ;;
    esac
  done
  [ -z "$PREV" ] && [ -f .agentic-security/last-scan.prev.json ] && PREV=".agentic-security/last-scan.prev.json"
  [ -z "$CURR" ] && [ -f .agentic-security/last-scan.json ] && CURR=".agentic-security/last-scan.json"
  if [ -z "$PREV" ] || [ -z "$CURR" ]; then
    echo "Usage: /scanner --baseline --previous <a.json> --current <b.json>"
    echo "  Default: .agentic-security/last-scan.prev.json vs last-scan.json"
    exit 1
  fi
  node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan-baseline \
    --previous "$PREV" --current "$CURR" --format "$FORMAT"
  [ $? -le 1 ] && exit 0 || exit $?
  ;;

# ── concurrency ──
concurrency)
  PATH_ARG="."
  for arg in "$@"; do [ "${arg:0:1}" != "-" ] && PATH_ARG="$arg"; done
  mkdir -p .agentic-security
  node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan "$PATH_ARG" \
    --format json --output .agentic-security/_concurrency.json >/dev/null 2>&1 || true
  node -e "
  const fs = require('fs');
  let scan;
  try { scan = JSON.parse(fs.readFileSync('.agentic-security/_concurrency.json','utf8')); }
  catch { console.log('Scanner did not run.'); process.exit(0); }
  const items = (scan.findings || []).filter(f => f.family === 'concurrency-bug');
  const W = (s,c) => process.stdout.isTTY ? '\x1b['+c+'m'+s+'\x1b[0m' : s;
  console.log('');
  console.log(W('Concurrency-bug findings: ' + items.length, '1'));
  console.log(W('  Coverage: Go, Java, JS/TS, Python', '2'));
  console.log('');
  const byKind = new Map();
  for (const f of items) { const k = (f.id || '').split(':')[1] || 'other'; if (!byKind.has(k)) byKind.set(k, []); byKind.get(k).push(f); }
  for (const [kind, list] of byKind) {
    console.log(W(kind + ' (' + list.length + ')', '1'));
    for (const f of list.slice(0, 20)) {
      const color = f.severity === 'high' ? '31' : f.severity === 'medium' ? '33' : '2';
      console.log('  [' + W((f.severity||'').toUpperCase(), color) + '] ' + (f.vuln||'').slice(0, 70) + '  ' + f.file + ':' + f.line);
    }
    console.log('');
  }
  if (!items.length) console.log(W('  ✅  No concurrency bugs detected.', '32'));
  "
  rm -f .agentic-security/_concurrency.json
  ;;

# ── spec-drift ──
spec-drift)
  PATH_ARG="."
  for arg in "$@"; do [ "${arg:0:1}" != "-" ] && PATH_ARG="$arg"; done
  mkdir -p .agentic-security
  node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs scan "$PATH_ARG" \
    --format json --output .agentic-security/_spec-drift.json >/dev/null 2>&1 || true
  node -e "
  const fs = require('fs');
  let scan;
  try { scan = JSON.parse(fs.readFileSync('.agentic-security/_spec-drift.json','utf8')); }
  catch { console.log('Scanner did not run.'); process.exit(0); }
  const items = (scan.findings || []).filter(f => f.family === 'spec-drift');
  const W = (s,c) => process.stdout.isTTY ? '\x1b['+c+'m'+s+'\x1b[0m' : s;
  console.log('');
  console.log(W('Spec-drift findings: ' + items.length, '1'));
  console.log(W('  Functions whose names claim behavior the body does not deliver.', '2'));
  console.log('');
  const byKind = new Map();
  for (const f of items) { const k = f.specMined?.family || 'other'; if (!byKind.has(k)) byKind.set(k, []); byKind.get(k).push(f); }
  for (const [kind, list] of byKind) {
    console.log(W(kind + ' (' + list.length + ')', '1'));
    for (const f of list.slice(0, 12)) {
      const color = f.severity === 'high' ? '31' : '33';
      console.log('  [' + W((f.severity||'').toUpperCase(), color) + '] ' + (f.vuln||'').slice(0, 80));
      console.log('    ' + W(f.file + ':' + f.line, '2'));
    }
    console.log('');
  }
  if (!items.length) console.log(W('  ✅  No spec-drift findings.', '32'));
  "
  rm -f .agentic-security/_spec-drift.json
  ;;

*)
  echo "Unknown mode: $MODE"
  exit 1
  ;;
esac
```

## Quick reference

| Mode | Was | Purpose |
|---|---|---|
| `--self-test` | `/self-test` | Mutate fixtures, surface detector gaps |
| `--diff` | `/diff-scan` | Compare two scanner versions on same tree |
| `--baseline` | `/scan-baseline` | Compare two scan JSON outputs (what did this PR break?) |
| `--concurrency` | `/concurrency-bugs` | Missed unlocks, fire-and-forget async, deadlock cycles |
| `--spec-drift` | `/spec-drift` | validateOwnership() that doesn't validate, sanitize() that doesn't sanitize |
