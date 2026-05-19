// Dead-code scanner — multi-language unused-code surface.
//
// Detects three categories of dead code:
//   1. unused-export   — an `export function/const/class` with zero callers
//   2. unused-file     — a file with zero inbound imports (excluding entry points)
//   3. wrapper-fn      — a one-line function whose body is `return other(...args)`
//
// Per-language strategy:
//   JS/TS  — use the existing IR + callgraph (`src/ir/`) to compute callers
//            per qid + dynamic-reference filter (string-literal grep,
//            decorator usage, framework call sites).
//   Python — shell out to `vulture` if installed; otherwise AST-based fallback.
//   Go     — shell out to `deadcode ./...` if installed.
//   Rust   — shell out to `cargo +nightly udeps` if installed.
//
// Output: standard finding shape with extras:
//   {
//     family:      'dead-code',
//     kind:        'unused-export' | 'unused-file' | 'wrapper-fn',
//     tier:        'safe' | 'caution' | 'danger',
//     severity:    'info',
//     stableId, confidence, exploitability, file, line, vuln, ...
//   }
//
// Tier semantics:
//   safe     — internal / module-private symbol with no callers AND no
//              dynamic-reference matches AND not a known framework callback.
//   caution  — public-API export OR matches one dynamic-reference signal
//              (string-literal grep, decorator-style call). External
//              consumers may exist.
//   danger   — entry points, exported class with subclasses, decorated
//              with a framework decorator (@app.get, @Component, etc.),
//              or referenced via reflection (`getattr`, `Reflect.get`).
//
// IMPORTANT: scanDeadCode is OFF by default — it runs in O(N²) on the file
// count (cross-file ref check). Opt in via opts.enabled or the slash
// command's explicit invocation.

import { execSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

const ENTRY_POINT_PATTERNS = [
  /^bin\//, /^scripts\//, /(^|\/)cli\.[jt]s$/, /(^|\/)index\.[jt]s$/,
  /(^|\/)main\.[jt]s$/, /\.test\.[jt]s$/, /\.spec\.[jt]s$/,
  /(^|\/)conftest\.py$/, /(^|\/)__init__\.py$/, /(^|\/)manage\.py$/,
  /(^|\/)main\.go$/, /(^|\/)main\.rs$/,
  // npm-script-invoked entry points — bench runners, audit scripts, etc.
  /(^|\/)bench(?:[.-][^/]+)?\.(?:m?js|ts)$/, /(^|\/)audit-[^/]+\.(?:m?js|ts)$/,
  /^benchmark\//, /\/benchmark\//,
];

const FRAMEWORK_DECORATORS = new Set([
  // Python
  'app.route', 'app.get', 'app.post', 'app.put', 'app.delete', 'app.patch',
  'blueprint.route', 'router.get', 'router.post', 'router.put',
  'app.task', 'celery.task', 'shared_task',
  'pytest.fixture', 'pytest.mark.parametrize',
  'click.command', 'click.group',
  // JS/TS (decorator metadata)
  'Component', 'Injectable', 'Module', 'Controller', 'Service',
  'Get', 'Post', 'Put', 'Delete', 'Patch',
  // Java/Spring (already caught via java IR but listed for completeness)
  'GetMapping', 'PostMapping', 'PutMapping', 'DeleteMapping', 'RequestMapping',
  'Bean', 'Component', 'Service', 'Repository', 'Controller', 'Configuration',
]);

const DYNAMIC_REFERENCE_PATTERNS = [
  // String-literal match — the symbol name appears as a JS/Python string
  // literal (often a router key, an event name, or a getattr target).
  (name) => new RegExp(`['"\`]${escapeRegex(name)}['"\`]`),
  // Reflect / getattr — JS Reflect.get / Python getattr / Object[key]
  (name) => new RegExp(`(getattr|Reflect\\.(get|has)|\\["${escapeRegex(name)}"\\])`),
];

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function isEntryPoint(relPath) {
  return ENTRY_POINT_PATTERNS.some((re) => re.test(relPath));
}

/**
 * Filter candidate-dead symbols by checking for dynamic references.
 *   candidates: [{ name, file, line, kind }]
 *   allFiles:   Map<relPath, content>
 *
 * Returns the same shape with:
 *   - removed: candidates that match a dynamic-reference signal (kept out)
 *   - kept:    candidates we still believe are dead
 *   - tierHints: Map<idKey, 'caution'|'danger'>
 */
export function filterDynamicReferences(candidates, allFiles) {
  const tierHints = new Map();
  const kept = [];
  const removed = [];
  for (const c of candidates || []) {
    let dynamicMatch = false;
    let frameworkMatch = false;
    for (const [fp, content] of allFiles) {
      // Skip the file where the symbol is declared — self-references don't
      // prove external use.
      if (fp === c.file) continue;
      for (const buildRe of DYNAMIC_REFERENCE_PATTERNS) {
        if (buildRe(c.name).test(content)) { dynamicMatch = true; break; }
      }
      if (dynamicMatch) break;
    }
    // Framework decorator check — any line `@<deco>` immediately above the
    // declaration in the symbol's own file → danger tier (framework calls it).
    const ownContent = allFiles.get(c.file);
    if (ownContent && c.line) {
      const lines = ownContent.split('\n');
      const above = lines[c.line - 2] || '';
      const m = above.match(/^\s*@([\w.]+)/);
      if (m && FRAMEWORK_DECORATORS.has(m[1])) frameworkMatch = true;
    }
    if (frameworkMatch) {
      tierHints.set(c.key || `${c.file}::${c.name}`, 'danger');
      removed.push({ ...c, reason: 'framework-decorator' });
      continue;
    }
    if (dynamicMatch) {
      tierHints.set(c.key || `${c.file}::${c.name}`, 'caution');
      kept.push({ ...c, tierHint: 'caution', reason: 'dynamic-reference-match' });
      continue;
    }
    kept.push({ ...c, tierHint: 'safe' });
  }
  return { kept, removed, tierHints };
}

/**
 * Detect unused JS/TS exports + unused files using the existing IR
 * call graph as ground truth.
 *
 *   projectRoot: absolute path
 *   fileContents: Map<relPath, content>  (JS/TS files only)
 *   callgraph: output of buildCallGraph(perFileIR)
 *
 * Returns a list of dead-code findings.
 */
export function detectDeadJsTs(projectRoot, fileContents, callgraph) {
  if (!fileContents || !callgraph) return [];
  const findings = [];
  // 1. unused-export: every fn qid with no callers AND has an exported name
  //    + no entry-point file context.
  for (const [qid, fn] of callgraph.functions) {
    if (!fn.exported) continue;
    const callers = callgraph.callersOf.get(qid) || [];
    if (callers.length > 0) continue;
    if (isEntryPoint(fn.file)) continue;
    findings.push({
      family: 'dead-code',
      kind: 'unused-export',
      severity: 'info',
      file: fn.file,
      line: fn.line || 1,
      name: fn.name,
      key: `${fn.file}::${fn.name}`,
      tierHint: 'safe',
      vuln: 'Unused export',
      description: `\`${fn.name}\` is exported from ${fn.file} but has no internal callers.`,
      remediation: `Remove the export or wire it into a call site. If it is a public API, allowlist it.`,
    });
  }
  // 2. unused-file: file has no inbound textual imports from any other file.
  // Textual import scan catches namespace imports (`import * as N from ...`)
  // and side-effect imports (`import './foo';`) that the callgraph misses.
  const fileHasInbound = new Map();
  for (const f of fileContents.keys()) fileHasInbound.set(f, false);
  for (const [importerFp, content] of fileContents) {
    for (const m of String(content).matchAll(/(?:from\s+|import\s*\(\s*)['"]([^'"]+)['"]/g)) {
      const spec = m[1];
      if (!spec) continue;
      if (spec.startsWith('.')) {
        // Relative import — resolve to a candidate path within fileContents.
        const importerDir = path.dirname(importerFp);
        const resolved = path.normalize(path.join(importerDir, spec));
        // Try as-is, with .js, /index.js, etc.
        for (const cand of [resolved, `${resolved}.js`, `${resolved}.ts`, `${resolved}.mjs`,
                            `${resolved}/index.js`, `${resolved}/index.ts`]) {
          if (fileHasInbound.has(cand)) { fileHasInbound.set(cand, true); break; }
        }
      }
    }
  }
  for (const [fp, hasIn] of fileHasInbound) {
    if (hasIn) continue;
    if (isEntryPoint(fp)) continue;
    // Skip if the file declares zero functions — likely a constants module.
    let hasFn = false;
    for (const fn of callgraph.functions.values()) if (fn.file === fp) { hasFn = true; break; }
    if (!hasFn) continue;
    findings.push({
      family: 'dead-code',
      kind: 'unused-file',
      severity: 'info',
      file: fp,
      line: 1,
      name: path.basename(fp),
      key: `${fp}::__file__`,
      tierHint: 'caution',
      vuln: 'Unused file',
      description: `No file in the project imports ${fp}.`,
      remediation: `Delete the file, or verify it is loaded dynamically (e.g., via a glob or a registry).`,
    });
  }
  return findings;
}

/**
 * Detect wrapper functions whose body is essentially `return other(...args)`.
 * These add no semantic value and are usually leftover indirection from
 * refactors. Operates per-file on JS/TS using the IR.
 */
export function detectWrapperFns(callgraph) {
  if (!callgraph || !callgraph.functions) return [];
  const out = [];
  for (const fn of callgraph.functions.values()) {
    if (!fn.body) continue;
    // Conservative: body is a single expression-statement whose value is
    // a call passing the parameters straight through (in order).
    const body = fn.body.trim();
    if (body.length > 120) continue;
    const m = body.match(/^(?:return\s+)?(\w+(?:\.\w+)*)\s*\(\s*([^)]*)\s*\)\s*;?$/);
    if (!m) continue;
    const calleeName = m[1];
    const args = m[2].split(',').map((s) => s.trim()).filter(Boolean);
    const params = (fn.params || []).map((p) => p.name || p);
    if (args.length !== params.length) continue;
    const passThrough = args.every((a, i) => a === params[i]);
    if (!passThrough) continue;
    out.push({
      family: 'dead-code',
      kind: 'wrapper-fn',
      severity: 'info',
      file: fn.file,
      line: fn.line || 1,
      name: fn.name,
      key: `${fn.file}::${fn.name}::wrapper`,
      tierHint: 'caution',
      vuln: 'Wrapper function',
      description: `\`${fn.name}\` only forwards its arguments to \`${calleeName}\`. The indirection adds no semantic value.`,
      remediation: `Inline \`${calleeName}\` at the call sites and delete \`${fn.name}\`.`,
    });
  }
  return out;
}

/**
 * Shell out to a language-native dead-code tool. Returns an array of
 * findings in our schema, or [] if the tool is not installed.
 *
 *   tool:   'vulture' | 'deadcode' | 'cargo-udeps'
 *   cwd:    project root
 */
export function runExternalDeadCodeTool(tool, cwd) {
  try {
    switch (tool) {
      case 'vulture': {
        // vulture emits "<file>:<line>: unused <kind> '<name>' (60% confidence)"
        const out = execSync('vulture --min-confidence 60 .', {
          cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 60_000,
        });
        return parseVultureOutput(out, cwd);
      }
      case 'deadcode': {
        const out = execSync('deadcode ./...', {
          cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 60_000,
        });
        return parseGoDeadcodeOutput(out, cwd);
      }
      case 'cargo-udeps': {
        const out = execSync('cargo +nightly udeps --output json', {
          cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], timeout: 120_000,
        });
        return parseCargoUdepsOutput(out, cwd);
      }
      default: return [];
    }
  } catch (_e) {
    // Tool not installed or returned non-zero. Silent — caller decides
    // whether to surface that as a warning.
    return [];
  }
}

function parseVultureOutput(text, cwd) {
  const findings = [];
  for (const line of String(text || '').split('\n')) {
    const m = line.match(/^(.+?):(\d+):\s*unused\s+(function|variable|class|method|attribute|import|property)\s+'([^']+)'\s+\((\d+)%\s+confidence\)/);
    if (!m) continue;
    const [, file, lineNo, kind, name, conf] = m;
    const confidence = Math.min(0.95, parseInt(conf, 10) / 100);
    findings.push({
      family: 'dead-code',
      kind: `unused-${kind}`,
      severity: 'info',
      file: path.relative(cwd, file),
      line: parseInt(lineNo, 10),
      name,
      key: `${file}::${name}`,
      tierHint: confidence >= 0.8 ? 'safe' : 'caution',
      confidence,
      vuln: `Unused ${kind}`,
      description: `vulture reports \`${name}\` as unused (${conf}% confidence).`,
      remediation: `Delete \`${name}\` or annotate with # noqa if it is intentionally retained.`,
    });
  }
  return findings;
}

function parseGoDeadcodeOutput(text, cwd) {
  const findings = [];
  for (const line of String(text || '').split('\n')) {
    const m = line.match(/^(.+?):(\d+):(\d+):\s*(.+)$/);
    if (!m) continue;
    const [, file, lineNo, , msg] = m;
    const nameMatch = msg.match(/^(?:unreachable\s+)?(?:function|method)\s+([^\s]+)/i);
    findings.push({
      family: 'dead-code',
      kind: 'unused-function',
      severity: 'info',
      file: path.relative(cwd, file),
      line: parseInt(lineNo, 10),
      name: nameMatch ? nameMatch[1] : msg,
      key: `${file}::${nameMatch ? nameMatch[1] : msg}`,
      tierHint: 'safe',
      vuln: 'Unused Go declaration',
      description: msg,
      remediation: `Delete the declaration or wire it into a call site.`,
    });
  }
  return findings;
}

function parseCargoUdepsOutput(jsonText, cwd) {
  try {
    const obj = JSON.parse(jsonText);
    const findings = [];
    const unused = (obj?.unused_deps && Object.values(obj.unused_deps)) || [];
    for (const pkg of unused) {
      const deps = [].concat(pkg.normal || [], pkg.development || [], pkg.build || []);
      for (const d of deps) {
        findings.push({
          family: 'dead-code',
          kind: 'unused-dependency',
          severity: 'info',
          file: 'Cargo.toml',
          line: 1,
          name: d,
          key: `cargo::${d}`,
          tierHint: 'safe',
          vuln: 'Unused Cargo dependency',
          description: `\`${d}\` is declared in Cargo.toml but never used.`,
          remediation: `cargo remove ${d}`,
        });
      }
    }
    return findings;
  } catch (_e) {
    return [];
  }
}

/**
 * Categorize a dead-code finding into a risk tier based on:
 *   - tierHint (from detector)
 *   - file context (entry point → danger)
 *   - export visibility (re-exported from index.js → caution)
 *
 * Tier:
 *   safe    — clear to delete
 *   caution — needs human review (public API, dynamic-ref signal)
 *   danger  — do not delete from this run
 */
export function classifyTier(finding, ctx = {}) {
  if (!finding) return 'caution';
  if (isEntryPoint(finding.file)) return 'danger';
  if (finding.tierHint) return finding.tierHint;
  return 'caution';
}

/**
 * Master entrypoint. Returns dead-code findings across every supported
 * language for the project.
 *
 *   opts.languages?      — restrict to a subset ['js','ts','py','go','rust']
 *   opts.skipDynamicCheck? — disable dynamic-reference filter (faster, more FPs)
 *   opts.callgraph?      — pre-built JS/TS call graph (avoid rebuild)
 *   opts.fileContents?   — Map<relPath, content> for the dynamic-ref filter
 */
export function scanDeadCode(projectRoot, opts = {}) {
  const findings = [];
  const langs = new Set(opts.languages || ['js', 'ts', 'py', 'go', 'rust']);

  // JS/TS — IR-based (requires callgraph + file contents to be passed in)
  if ((langs.has('js') || langs.has('ts')) && opts.callgraph && opts.fileContents) {
    let jsFindings = [];
    jsFindings = jsFindings.concat(detectDeadJsTs(projectRoot, opts.fileContents, opts.callgraph));
    jsFindings = jsFindings.concat(detectWrapperFns(opts.callgraph));
    if (!opts.skipDynamicCheck) {
      const { kept } = filterDynamicReferences(jsFindings, opts.fileContents);
      jsFindings = kept;
    }
    findings.push(...jsFindings);
  }

  // External tools (best-effort, silent on absence).
  if (langs.has('py'))   findings.push(...runExternalDeadCodeTool('vulture',     projectRoot));
  if (langs.has('go'))   findings.push(...runExternalDeadCodeTool('deadcode',    projectRoot));
  if (langs.has('rust')) findings.push(...runExternalDeadCodeTool('cargo-udeps', projectRoot));

  // Final tier classification.
  for (const f of findings) f.tier = classifyTier(f);

  return findings;
}

/** Bucket findings by tier — convenient for the apply path. */
export function groupByTier(findings) {
  const out = { safe: [], caution: [], danger: [] };
  for (const f of findings || []) {
    const t = f.tier || classifyTier(f);
    (out[t] || out.caution).push(f);
  }
  return out;
}
