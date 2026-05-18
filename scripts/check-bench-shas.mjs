#!/usr/bin/env node
// CI + pre-commit check: every bench corpus in manifest.json must be pinned
// to a specific commit sha — never a branch name like "master" / "main" / "HEAD".
// Unpinned references break reproducibility: the bench-cache key is (name)-(sha),
// so a branch ref produces a new cache miss on every pull while pretending the
// corpus didn't change.
//
// Usage (run from repo root):
//   node scripts/check-bench-shas.js           # exits 0 = all pinned
//   node scripts/check-bench-shas.js --report  # print table even if clean

import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPORT = process.argv.includes('--report');
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const MANIFEST = join(ROOT, 'scanner', 'test', 'benchmark', 'realworld', 'manifest.json');

const BRANCH_PATTERN = /^(master|main|HEAD|develop|dev|trunk|latest|release|stable|next|nightly|canary)$/i;
const SHA_PATTERN = /^[0-9a-f]{7,40}$/i;
const TAG_PATTERN = /^v\d+\.\d+/;  // semver tags like v5.1.0 are acceptable pins

let manifest;
try {
  manifest = JSON.parse(readFileSync(MANIFEST, 'utf8'));
} catch (e) {
  console.error(`check-bench-shas: cannot read manifest: ${e.message}`);
  process.exit(2);
}

const apps = manifest.apps || {};
const unpinned = [];
const pinned = [];

for (const [name, app] of Object.entries(apps)) {
  const sha = app.sha || '';
  const isPin = SHA_PATTERN.test(sha) || TAG_PATTERN.test(sha);
  const isBranch = BRANCH_PATTERN.test(sha) || (!sha);
  if (isBranch || (!isPin && !isBranch)) {
    unpinned.push({ name, sha: sha || '(empty)' });
  } else {
    pinned.push({ name, sha: sha.slice(0, 12) });
  }
}

if (REPORT || unpinned.length > 0) {
  if (pinned.length) {
    console.log(`Pinned (${pinned.length}):`);
    for (const { name, sha } of pinned) {
      console.log(`  ✓  ${name.padEnd(35)} ${sha}`);
    }
  }
  if (unpinned.length) {
    console.log(`\nUnpinned — FAIL (${unpinned.length}):`);
    for (const { name, sha } of unpinned) {
      console.log(`  ✗  ${name.padEnd(35)} "${sha}"`);
    }
  }
}

if (unpinned.length > 0) {
  if (!REPORT) {
    console.error(`\ncheck-bench-shas: ${unpinned.length} app(s) in manifest.json have unpinned sha.`);
    console.error(`Replace each branch name with a specific commit hash.`);
    console.error(`Run: node scripts/check-bench-shas.js --report  for full details.`);
  }
  process.exit(1);
}

console.log(`check-bench-shas: all ${pinned.length} app(s) are pinned. ✓`);
process.exit(0);
