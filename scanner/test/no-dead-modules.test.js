// Dead-module guard test (premortem 3R5.2 / 3R-1).
//
// The recurring failure mode across three premortem rounds was: a remediation
// ships a new module, the commit message claims closure, but no production
// path imports/calls the module. This test fails the build when that
// pattern recurs.
//
// Mechanism: for every JS file under scanner/src/{posture,llm-validator,
// dataflow,lsp,ir,mcp}/, find each top-level `export function`/`export const`
// /`export class` and assert at least one OTHER source file imports or
// references that symbol. Self-references inside the same file don't count.
//
// What's intentionally NOT covered:
//   - Pure re-exports through an index.js: those count as call sites for the
//     symbol's home file (the home file's exports are used).
//   - `_internal`, `_private` exports prefixed with `_`: those are test-only
//     helpers, allowed to live without external callers (but counted if used).
//   - Standalone bin scripts (scanner/bin/*.js): they are the entry points.
//
// Allowlist (this list MUST be small and reviewed in PR): symbols that are
// shipped as future-public API but not yet called. Each entry justified.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SRC_ROOT = path.resolve(__dirname, '..', 'src');

const SCAN_DIRS = [
  'posture', 'llm-validator', 'dataflow', 'lsp', 'ir', 'mcp',
];

// Symbols allowed to be uncalled. Each MUST have a justification.
// This list is intentionally generous on existing modules; the test exists
// to PREVENT THE RECURRENCE of "ship dead code in a remediation commit," not
// to demand 100% call-site coverage for the existing public API. New modules
// added after v0.46.0 should be wired in (or explicitly allowlisted with a
// reason) before merge.
const ALLOWLIST = new Set([
  // ── Bin-only entry points ───────────────────────────────────────────────
  'rule-pack-signing.js::keygen',           // bin/agentic-security-rule.js
  'rule-pack-signing.js::signRulePack',     // bin/agentic-security-rule.js
  'lsp/server.js::startLspServer',           // bin/agentic-security-lsp.js
  // ── Validator internal helpers — used via _internal export for tests ─
  'llm-validator/index.js::sanitizeReasoning',
  'llm-validator/index.js::parseLastJsonObject',
  'llm-validator/index.js::validateResponse',
  'llm-validator/index.js::validateOne',
  // ── Module-internal lookups — re-exported through index.js facade ───
  'catalog.js::matchSource',
  'catalog.js::matchSinkOrSanitizer',
  'catalog.js::_catalogSize',
  'catalog.js::CATALOG',
  'catalog.js::applyPathFeasibility',
  'ir/parser-js.js::parseJsFile',
  'callgraph.js::buildCallGraph',
  // ── MCP tool registration — each tool registers via the ALL_TOOLS array ──
  'mcp/tools.js::scan_diff',
  'mcp/tools.js::query_taint',
  'mcp/tools.js::explain_finding',
  'mcp/tools.js::apply_fix',
  'mcp/tools.js::verify_fix',
  'mcp/tools.js::synthesize_fix',
  // ── Path-predicates internal name table — used by tests / debugging ──
  'path-predicates.js::_internalPredicateNames',
  // ── posture/* future-API surface (pre-v0.46.0, kept for API symmetry) ──
  'blast-radius.js::collectProjectSignals',
  'custom-rules.js::runRule',
  'deterministic.js::computeRulePackHash',
  'deterministic.js::buildLockfile',
  'deterministic.js::readLockfile',
  'deterministic.js::SCANNER_VERSION',
  'epss.js::fetchEPSS',
  'fix-history.js::readLog',
  'fix-plan.js::countPatchBounds',
  'fix-plan.js::renderFixPlan',
  'fix-plan.js::emitFixPlanFile',
  'fix-plan.js::shouldEmitFixPlan',
  'fix-verify.js::runProjectLinter',
  'learning.js::loadFeedback',
  'learning.js::recordVerdict',
  'learning.js::saveFeedback',
  'llm-redteam.js::runActiveRedteam',
  'llm-redteam.js::renderRedteamMarkdownReport',
  'material-change.js::parseDiff',
  'material-change.js::classifyHunk',
  'material-change.js::classifyGitDiff',
  'profile.js::PROFILES',
  'rule-overrides.js::loadOverrides',
  'rule-overrides.js::runCustomRules',
  'rule-pack-signing.js::BUNDLED_OFFICIAL_KEYS',
  'ruleset-version.js::readPinned',
  'ruleset-version.js::effectiveVersion',
  'ruleset-version.js::CURRENT_RULESET_VERSION',
  'security-trend.js::computeTrend',
  'stable-id.js::computeStableId',
  'streak.js::loadStreak',
  'streak.js::markLaunchCheckPassed',
  'streak.js::formatAchievements',
  'suppressions.js::loadSoftAccepted',
  'suppressions.js::saveSoftAccepted',
  'suppressions.js::loadProSuppressions',
  'suppressions.js::validateProSuppression',
  'triage.js::loadTriage',
  'triage.js::STATES',
  'validator-metrics.js::recordTriage',  // wired via commands/triage.md (not .js)
  'validator-metrics.js::getLatest',
  'validator-metrics.js::checkFloors',
  'validator-metrics.js::saveFeedback',
  // ── Summaries cache (k=1) — used internally; future-public surface ──
  'summaries.js::SummaryCache',
  'summaries.js::entryStateFromCall',
]);

function listJsFiles(dir) {
  const out = [];
  function walk(d) {
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) { walk(p); continue; }
      if (e.isFile() && /\.js$/.test(e.name)) out.push(p);
    }
  }
  walk(dir);
  return out;
}

function extractExports(content) {
  const exports = [];
  // export function NAME(
  for (const m of content.matchAll(/^\s*export\s+(?:async\s+)?function\s+(\w+)\s*\(/gm)) {
    exports.push({ name: m[1], kind: 'fn' });
  }
  // export const NAME =
  for (const m of content.matchAll(/^\s*export\s+const\s+(\w+)\s*=/gm)) {
    exports.push({ name: m[1], kind: 'const' });
  }
  // export class NAME
  for (const m of content.matchAll(/^\s*export\s+class\s+(\w+)/gm)) {
    exports.push({ name: m[1], kind: 'class' });
  }
  // export { a, b as c, ... } — list-style re-exports
  for (const m of content.matchAll(/^\s*export\s*\{\s*([^}]+)\s*\}/gm)) {
    for (const seg of m[1].split(',')) {
      const name = seg.trim().split(/\s+as\s+/).pop();
      if (name && /^\w+$/.test(name)) exports.push({ name, kind: 'reexport' });
    }
  }
  return exports;
}

function loadAllSources() {
  const files = [];
  for (const d of SCAN_DIRS) files.push(...listJsFiles(path.join(SRC_ROOT, d)));
  // Also walk top-level src/ files (engine.js, runScan.js, index.js, report/*).
  for (const e of fs.readdirSync(SRC_ROOT, { withFileTypes: true })) {
    if (e.isFile() && /\.js$/.test(e.name)) files.push(path.join(SRC_ROOT, e.name));
  }
  for (const d of ['report', 'sast', 'sca', 'secrets', 'integrations']) {
    files.push(...listJsFiles(path.join(SRC_ROOT, d)));
  }
  // Also include bin scripts (they're consumers).
  const binDir = path.resolve(SRC_ROOT, '..', 'bin');
  if (fs.existsSync(binDir)) files.push(...listJsFiles(binDir));
  // And test files — tests count as call sites too.
  const testDir = path.resolve(SRC_ROOT, '..', 'test');
  if (fs.existsSync(testDir)) files.push(...listJsFiles(testDir));
  // Slash-command markdown files contain `node -e` blocks that import
  // posture/validator-metrics, etc. — count those as call sites too.
  const cmdDir = path.resolve(SRC_ROOT, '..', '..', 'commands');
  if (fs.existsSync(cmdDir)) {
    for (const e of fs.readdirSync(cmdDir, { withFileTypes: true })) {
      if (e.isFile() && /\.md$/.test(e.name)) files.push(path.join(cmdDir, e.name));
    }
  }
  return files.map(f => ({ path: f, content: fs.readFileSync(f, 'utf8') }));
}

test('every export in posture/llm-validator/dataflow/lsp/ir/mcp has a call site', async () => {
  const all = loadAllSources();
  const violations = [];
  for (const d of SCAN_DIRS) {
    const dir = path.join(SRC_ROOT, d);
    for (const fp of listJsFiles(dir)) {
      const content = fs.readFileSync(fp, 'utf8');
      const exports = extractExports(content);
      const rel = path.basename(path.dirname(fp)) + '/' + path.basename(fp);
      const justFile = path.basename(fp);
      for (const { name } of exports) {
        if (name.startsWith('_') && name !== '_internal') continue;
        const allowKey = `${justFile}::${name}`;
        const allowKey2 = `${rel}::${name}`;
        if (ALLOWLIST.has(allowKey) || ALLOWLIST.has(allowKey2)) continue;
        // Look for at least one reference to `name` in a file other than itself.
        const ref = all.find(s => s.path !== fp && new RegExp(`\\b${name}\\b`).test(s.content));
        if (!ref) {
          violations.push(`${rel}::${name} is exported but has no external call site`);
        }
      }
    }
  }
  assert.equal(violations.length, 0,
    `Dead modules detected (premortem 3R5.2 — recurring "ship dead code" pattern):\n  ` +
    violations.join('\n  ') +
    `\n\nFix: either (a) wire the symbol into a production path, ` +
    `(b) add it to ALLOWLIST in test/no-dead-modules.test.js with justification, ` +
    `or (c) delete the export.`);
});
