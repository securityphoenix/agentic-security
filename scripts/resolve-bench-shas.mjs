#!/usr/bin/env node
// Pin all unpinned bench corpora to specific commit shas.
// Requires network access and git. Run from repo root:
//
//   node scripts/resolve-bench-shas.mjs [--dry-run]
//
// Updates manifest.json in-place with resolved shas.
// Re-run check-bench-shas.mjs to verify.

import { readFileSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const DRY = process.argv.includes('--dry-run');
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const MANIFEST_PATH = join(ROOT, 'scanner', 'test', 'benchmark', 'realworld', 'manifest.json');

const BRANCH_PATTERN = /^(master|main|HEAD|develop|dev|trunk|latest|release|stable|next|nightly|canary|11\.x)$/i;
const SHA_PATTERN = /^[0-9a-f]{7,40}$/i;
const TAG_PATTERN = /^v\d+\.\d+/;

const manifest = JSON.parse(readFileSync(MANIFEST_PATH, 'utf8'));
const apps = manifest.apps;

function resolve(repo, ref) {
  const r = spawnSync('git', ['ls-remote', '--exit-code', repo, ref], {
    encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 20_000,
  });
  if (r.status !== 0) return null;
  const line = r.stdout.trim().split('\n')[0];
  return line ? line.split('\t')[0] : null;
}

let changed = 0;
for (const [name, app] of Object.entries(apps)) {
  const sha = app.sha || '';
  const isPin = SHA_PATTERN.test(sha) || TAG_PATTERN.test(sha);
  if (isPin) { process.stdout.write(`  skip  ${name} (already pinned to ${sha.slice(0,12)})\n`); continue; }

  const ref = BRANCH_PATTERN.test(sha) ? sha : 'HEAD';
  process.stdout.write(`  resolving ${name} @ ${ref} ...`);
  const resolved = resolve(app.repo, ref);
  if (!resolved) {
    process.stdout.write(` FAILED (check network / repo URL)\n`);
    continue;
  }
  process.stdout.write(` ${resolved.slice(0, 12)}\n`);
  if (!DRY) {
    app.sha = resolved;
    changed++;
  }
}

if (!DRY && changed > 0) {
  writeFileSync(MANIFEST_PATH, JSON.stringify(manifest, null, 2) + '\n');
  process.stdout.write(`\nWrote ${changed} updated sha(s) to ${MANIFEST_PATH}\n`);
  process.stdout.write(`Run: node scripts/check-bench-shas.mjs  to verify.\n`);
} else if (DRY) {
  process.stdout.write('\n(dry-run — manifest not modified)\n');
} else {
  process.stdout.write('\nNo changes needed.\n');
}
