---
description: Find unused code — exports with zero callers, files with zero inbound imports, wrapper functions that add no value. Multi-language (JS/TS via IR call graph; Python/Go/Rust via native tools). Reports SAFE / CAUTION / DANGER tiers; never deletes without --apply.
argument-hint: "[path] [--language js|ts|py|go|rust] [--include-wrappers] [--skip-dynamic-check] [--apply]"
---

Identify dead code across every supported language for the project. Multi-tier output (SAFE / CAUTION / DANGER) lets you batch-remove the safe items in one shot while flagging the risky ones for review.

```bash
node ${CLAUDE_PLUGIN_ROOT}/scanner/dist/agentic-security.mjs banner 2>/dev/null || true
PATH_ARG="."
LANGS=""
INCLUDE_WRAPPERS=false
SKIP_DYNAMIC=false
APPLY=false

for arg in "$@"; do
  case "$arg" in
    --language)             NEXT_IS_LANGS=1 ;;
    --include-wrappers)     INCLUDE_WRAPPERS=true ;;
    --skip-dynamic-check)   SKIP_DYNAMIC=true ;;
    --apply)                APPLY=true ;;
    -*) ;;
    *)
      if [ -n "$NEXT_IS_LANGS" ]; then LANGS="$arg"; unset NEXT_IS_LANGS
      else PATH_ARG="$arg"
      fi
      ;;
  esac
done

node --input-type=module -e "
import { scanDeadCode, groupByTier } from '${CLAUDE_PLUGIN_ROOT}/scanner/src/posture/dead-code.js';
import { buildProjectIR } from '${CLAUDE_PLUGIN_ROOT}/scanner/src/ir/index.js';
import * as fs from 'node:fs';
import * as path from 'node:path';

const root = path.resolve('${PATH_ARG}');
const langs = '${LANGS}' ? '${LANGS}'.split(',').map(s => s.trim()) : ['js','ts','py','go','rust'];

// Build file map for IR + dynamic-ref filter.
function walk(dir, out = new Map()) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      // Skip hidden directories (.cache, .next, .bench-cache, .git, .venv, ...)
      if (e.name.startsWith('.')) continue;
      // Skip fixture / benchmark trees — they are loaded by path, not import,
      // and would over-fire the unused-file detector.
      if (/^(node_modules|dist|build|coverage|__pycache__|target|vendor|fixtures|benchmarks|samples|examples|__fixtures__|__snapshots__)$/.test(e.name)) continue;
      walk(p, out);
    } else if (e.isFile() && /\\.(js|ts|jsx|tsx|mjs|cjs)$/.test(e.name)) {
      try { out.set(path.relative(root, p), fs.readFileSync(p, 'utf8')); } catch {}
    }
  }
  return out;
}
const fileContents = walk(root);
// buildProjectIR expects a plain object — convert from Map.
const ircontents = Object.fromEntries(fileContents);
const { callGraph } = buildProjectIR(ircontents);

const findings = scanDeadCode(root, {
  languages: langs,
  skipDynamicCheck: ${SKIP_DYNAMIC},
  callgraph: callGraph,
  fileContents,
});

const grouped = groupByTier(findings);
const total = findings.length;

console.log('');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('  agentic-security: trim-dead-code');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('');
console.log('  Scanned ' + fileContents.size + ' source files.');
console.log('  Total dead-code candidates: ' + total);
console.log('    SAFE    (clear to delete): ' + grouped.safe.length);
console.log('    CAUTION (needs review):    ' + grouped.caution.length);
console.log('    DANGER  (do not delete):   ' + grouped.danger.length);
console.log('');

function printTier(name, list) {
  if (!list.length) return;
  console.log('  ── ' + name + ' (' + list.length + ') ──');
  for (const f of list.slice(0, 30)) {
    console.log('    ' + f.kind + '  ' + (f.name || '') + '  →  ' + f.file + ':' + f.line);
    if (f.description) console.log('      ' + f.description);
  }
  if (list.length > 30) console.log('    ... and ' + (list.length - 30) + ' more');
  console.log('');
}
printTier('SAFE',    grouped.safe);
printTier('CAUTION', grouped.caution);
printTier('DANGER',  grouped.danger);

if (${APPLY}) {
  console.log('  --apply requested. Delegating to refactor-cleaner agent for batched removal.');
  console.log('  The agent will:');
  console.log('    1. Create a checkpoint branch');
  console.log('    2. Remove SAFE-tier items one at a time');
  console.log('    3. Run the project test command between batches');
  console.log('    4. Auto-revert on test failure');
  console.log('    5. Commit each successful batch separately');
  process.exit(0);
}

console.log('  Re-run with --apply to delete the SAFE-tier items via the');
console.log('  refactor-cleaner agent (test-gated + git checkpoint per batch).');
" 2>&1
```

## What it detects

| Kind | Detector | Tier defaults |
|---|---|---|
| `unused-export` | JS/TS IR call graph — `export` with zero callers across project | SAFE if not in entry-point file |
| `unused-file` | JS/TS — file with zero inbound function references | CAUTION (might be loaded dynamically) |
| `wrapper-fn` | JS/TS — single-expression function that forwards args unchanged to another fn | CAUTION (callers may rely on the indirection) |
| `unused-function`/`variable`/`class`/`method` (Python) | `vulture --min-confidence 60` | SAFE ≥ 80% confidence; CAUTION otherwise |
| `unused-function` (Go) | `deadcode ./...` | SAFE |
| `unused-dependency` (Rust) | `cargo +nightly udeps --output json` | SAFE |

## How tiers are assigned

- **SAFE** — internal/module-private symbol with zero callers AND no dynamic-reference signal (no string-literal match, no framework decorator above the declaration, no Reflect/getattr usage anywhere in the codebase).
- **CAUTION** — the symbol matches at least one dynamic-reference signal (the name appears as a string literal somewhere, or the symbol is a public export that other repos might consume). Needs human review.
- **DANGER** — the file is an entry point (`bin/`, `cli.ts`, `manage.py`, `main.go`), or the declaration is decorated with a framework decorator (`@app.get`, `@Component`, `@Bean`). Not surfaced for removal.

## Safety rails for `--apply`

Delegates to the **refactor-cleaner** agent, which follows this protocol:
1. **Test baseline** — runs `npm test` / `pytest` / `go test` / `cargo test` first; aborts if the baseline is red.
2. **Create checkpoint branch** — `dead-code-cleanup-<timestamp>`.
3. **Batch by tier** — only SAFE tier is touched by `--apply`. CAUTION + DANGER are listed for the user.
4. **One symbol at a time within each file** — remove, save, run tests.
5. **Auto-revert on test failure** — `git checkout -- <file>` if the test gate goes red.
6. **One commit per successful batch** — easy to revert any single removal.

## False-positive controls

The dynamic-reference filter (enabled by default; disable with `--skip-dynamic-check`) checks every file for:
- The symbol name as a JS/Python string literal
- Reflection-style access (`Reflect.get`, `getattr`, `obj[name]`)
- Framework decorators on the declaration line

When any of these match, the finding is demoted to CAUTION (or dropped entirely if a framework decorator is present).

## Persist annotations to keep symbols

Add a comment anywhere in the project to allowlist a symbol from the scan:

```
// dead-code-keep: setupGracefulShutdown
# dead-code-keep: register_signal_handlers
```

🛡  agentic-security · created by ClearCapabilities.Com
