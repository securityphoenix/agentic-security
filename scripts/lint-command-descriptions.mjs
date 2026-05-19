#!/usr/bin/env node
// Frontmatter lint for commands/ and skills/ (LangChain harness-anatomy #5 / Tier 1).
//
// Always-paid context cost = description + argument-hint per registered surface.
// 77 commands × 200-char avg description is ~15 KB always loaded into the
// model's command-routing reasoning. This script enforces caps so the surface
// can't drift back up.
//
// Caps:
//   - description:    ≤ 120 chars  (UI menu line + model routing)
//   - argument-hint:  ≤ 200 chars  (CLI usage signature)
//
// Per the post: "Skills address the issue of too many tools or MCP servers
// loaded into context on agent start which degrades performance before the
// agent can start working." This lint keeps the surface honest.
//
// Usage:
//   node scripts/lint-command-descriptions.mjs               # exit 0 = clean
//   node scripts/lint-command-descriptions.mjs --json
//   node scripts/lint-command-descriptions.mjs --fix-report  # show worst offenders, don't auto-fix
'use strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..');

const DESCRIPTION_CAP = 120;
const ARGUMENT_HINT_CAP = 200;
const TARGETS = [
  { dir: 'commands', glob: /\.md$/ },
  // Skills also occupy registered surface; same caps apply.
  // SKILL.md lives one level down in skills/<name>/SKILL.md.
  { dir: 'skills', glob: /\/SKILL\.md$/ },
];

function _walk(dir) {
  const out = [];
  const stack = [dir];
  while (stack.length) {
    const cur = stack.pop();
    let entries;
    try { entries = fs.readdirSync(cur, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const fp = path.join(cur, e.name);
      if (e.isDirectory()) stack.push(fp);
      else if (e.isFile()) out.push(fp);
    }
  }
  return out;
}

function _parseFrontmatter(body) {
  if (!body.startsWith('---\n')) return null;
  const close = body.indexOf('\n---', 4);
  if (close < 0) return null;
  const block = body.slice(4, close);
  const out = {};
  // Naive single-line key: value parser. Handles `key: "value"` and
  // `key: value`; doesn't try to handle multi-line YAML — frontmatter for
  // commands/skills is single-line scalars by convention here.
  for (const rawLine of block.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const m = /^([A-Za-z_][\w-]*)\s*:\s*(.*)$/.exec(line);
    if (!m) continue;
    let v = m[2].trim();
    // Strip surrounding quotes (single OR double).
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
      v = v.slice(1, -1);
    }
    out[m[1]] = v;
  }
  return out;
}

const issues = [];

function _scanFile(fp) {
  let body;
  try { body = fs.readFileSync(fp, 'utf8'); }
  catch (e) { issues.push({ file: fp, kind: 'unreadable', detail: e.message }); return; }
  const fm = _parseFrontmatter(body);
  if (!fm) {
    // Skip docs/utility files with no frontmatter (README, _CONFINEMENT.md, etc.).
    return;
  }
  if (!fm.description) {
    issues.push({ file: fp, kind: 'missing-description' });
    return;
  }
  const dlen = fm.description.length;
  if (dlen > DESCRIPTION_CAP) {
    issues.push({
      file: fp, kind: 'description-too-long',
      length: dlen, cap: DESCRIPTION_CAP, excess: dlen - DESCRIPTION_CAP,
      preview: fm.description.slice(0, 80) + '…',
    });
  }
  if (fm['argument-hint']) {
    const hlen = fm['argument-hint'].length;
    if (hlen > ARGUMENT_HINT_CAP) {
      issues.push({
        file: fp, kind: 'argument-hint-too-long',
        length: hlen, cap: ARGUMENT_HINT_CAP, excess: hlen - ARGUMENT_HINT_CAP,
        preview: fm['argument-hint'].slice(0, 80) + '…',
      });
    }
  }
}

const args = new Set(process.argv.slice(2));
const wantJson = args.has('--json');
const fixReport = args.has('--fix-report');

let total = 0;
for (const t of TARGETS) {
  const root = path.join(REPO, t.dir);
  if (!fs.existsSync(root)) continue;
  const files = _walk(root).filter(fp => t.glob.test(fp.replace(/\\/g, '/')));
  for (const fp of files) { _scanFile(fp); total++; }
}

if (wantJson) {
  console.log(JSON.stringify({ scanned: total, issues, caps: { description: DESCRIPTION_CAP, argumentHint: ARGUMENT_HINT_CAP } }, null, 2));
  process.exit(issues.length ? 1 : 0);
}

if (fixReport) {
  // Sort worst offenders first so the operator knows where to start trimming.
  const tooLong = issues.filter(i => i.kind === 'description-too-long' || i.kind === 'argument-hint-too-long')
    .sort((a, b) => b.excess - a.excess);
  console.log(`Scanned ${total} surfaces under commands/ and skills/`);
  console.log(`Description cap: ${DESCRIPTION_CAP} chars   argument-hint cap: ${ARGUMENT_HINT_CAP} chars`);
  console.log(`Found ${tooLong.length} overflows.\n`);
  for (const i of tooLong.slice(0, 30)) {
    const rel = path.relative(REPO, i.file);
    console.log(`  +${String(i.excess).padStart(4)}  ${rel.padEnd(40)}  ${i.kind}`);
  }
  if (tooLong.length > 30) console.log(`  …and ${tooLong.length - 30} more`);
  process.exit(issues.length ? 1 : 0);
}

if (issues.length) {
  console.error(`command-description-lint: ${issues.length} issue(s) across ${total} files:`);
  for (const i of issues.slice(0, 50)) {
    const rel = path.relative(REPO, i.file);
    if (i.kind === 'description-too-long') {
      console.error(`  ${rel}: description ${i.length} > ${i.cap} chars (excess ${i.excess})`);
    } else if (i.kind === 'argument-hint-too-long') {
      console.error(`  ${rel}: argument-hint ${i.length} > ${i.cap} chars (excess ${i.excess})`);
    } else {
      console.error(`  ${rel}: ${i.kind}`);
    }
  }
  if (issues.length > 50) console.error(`  …and ${issues.length - 50} more`);
  process.exit(1);
}
console.log(`command-description-lint: clean (${total} surfaces, all within caps)`);
process.exit(0);
