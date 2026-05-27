#!/usr/bin/env node
// GHSA fix-commit analysis — generates vuln-function-hints from GitHub Advisory fix commits.
//
// For each GHSA advisory with a fix commit reference:
//   1. Fetches the commit diff via GitHub API
//   2. Extracts function/method names from changed lines in the diff
//   3. Maps advisory → package → vulnerable function names
//   4. Outputs vuln-function-hints-generated.json
//
// Usage:
//   node scripts/ghsa-to-hints.mjs [--ecosystem npm|pypi|go] [--limit 100] [--output path]
//
// Requires: `gh` CLI authenticated (uses `gh api`)
//
// This runs nightly in CI, NOT at scan time.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_OUTPUT = path.join(__dirname, '..', 'scanner', 'src', 'sca', 'vuln-function-hints-generated.json');

const JS_FUNC_RE = /^[+-]\s*(?:export\s+)?(?:async\s+)?(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(|(\w+)\s*\([^)]*\)\s*\{)/;
const PY_FUNC_RE = /^[+-]\s*(?:async\s+)?def\s+(\w+)\s*\(/;
const GO_FUNC_RE = /^[+-]\s*func\s+(?:\([^)]*\)\s+)?(\w+)\s*\(/;
const JAVA_METHOD_RE = /^[+-]\s*(?:public|private|protected|static|final|abstract|synchronized|native)\s+.*?\s+(\w+)\s*\(/;

function extractFunctionsFromDiff(diff) {
  const functions = new Set();
  for (const line of diff.split('\n')) {
    for (const re of [JS_FUNC_RE, PY_FUNC_RE, GO_FUNC_RE, JAVA_METHOD_RE]) {
      const m = line.match(re);
      if (m) {
        const name = m[1] || m[2] || m[3];
        if (name && name.length > 1 && !/^(if|else|for|while|switch|case|return|class|import|export|from|const|let|var|try|catch|finally|throw|new|delete|typeof|void|in|of)$/.test(name)) {
          functions.add(name);
        }
      }
    }
  }
  return [...functions];
}

function ghApi(endpoint) {
  try {
    const out = execFileSync('gh', ['api', endpoint, '--paginate'], {
      encoding: 'utf8',
      timeout: 30000,
      maxBuffer: 10 * 1024 * 1024,
    });
    return JSON.parse(out);
  } catch (e) {
    if (e.stdout) {
      try { return JSON.parse(e.stdout); } catch { /* ignore */ }
    }
    return null;
  }
}

function fetchCommitDiff(owner, repo, sha) {
  try {
    const out = execFileSync('gh', ['api', `repos/${owner}/${repo}/commits/${sha}`, '-H', 'Accept: application/vnd.github.diff'], {
      encoding: 'utf8',
      timeout: 15000,
      maxBuffer: 5 * 1024 * 1024,
    });
    return out;
  } catch {
    return null;
  }
}

function extractCommitFromUrl(url) {
  if (!url) return null;
  // https://github.com/owner/repo/commit/sha
  const m = url.match(/github\.com\/([^/]+)\/([^/]+)\/commit\/([a-f0-9]+)/);
  if (m) return { owner: m[1], repo: m[2], sha: m[3] };
  return null;
}

async function main() {
  const args = process.argv.slice(2);
  const ecosystem = args.includes('--ecosystem') ? args[args.indexOf('--ecosystem') + 1] : 'npm';
  const limit = args.includes('--limit') ? parseInt(args[args.indexOf('--limit') + 1]) : 100;
  const outputPath = args.includes('--output') ? args[args.indexOf('--output') + 1] : DEFAULT_OUTPUT;
  const dryRun = args.includes('--dry-run');

  console.log(`Fetching GHSA advisories for ${ecosystem} (limit: ${limit})...`);

  const advisories = ghApi(`/advisories?ecosystem=${ecosystem}&per_page=${Math.min(limit, 100)}&type=reviewed`);
  if (!advisories || !Array.isArray(advisories)) {
    console.error('Failed to fetch advisories. Is `gh` authenticated?');
    process.exit(1);
  }

  console.log(`Fetched ${advisories.length} advisories`);
  const hints = {};
  let processed = 0, withCommit = 0, withFunctions = 0;

  for (const adv of advisories.slice(0, limit)) {
    processed++;
    const pkgName = adv.vulnerabilities?.[0]?.package?.name;
    if (!pkgName) continue;

    const refs = adv.references || [];
    let commitInfo = null;
    for (const ref of refs) {
      commitInfo = extractCommitFromUrl(ref);
      if (commitInfo) break;
    }
    if (!commitInfo) continue;
    withCommit++;

    const diff = fetchCommitDiff(commitInfo.owner, commitInfo.repo, commitInfo.sha);
    if (!diff) continue;

    const functions = extractFunctionsFromDiff(diff);
    if (!functions.length) continue;
    withFunctions++;

    if (!hints[pkgName]) hints[pkgName] = [];
    for (const fn of functions) {
      if (!hints[pkgName].includes(fn)) hints[pkgName].push(fn);
    }

    if (processed % 10 === 0) console.log(`  ${processed}/${advisories.length} processed, ${withFunctions} with functions...`);
  }

  console.log(`\nResults: ${processed} advisories → ${withCommit} with fix commit → ${withFunctions} with extractable functions`);
  console.log(`Packages covered: ${Object.keys(hints).length}`);

  const output = {
    _generated: true,
    _generatedAt: new Date().toISOString(),
    _ecosystem: ecosystem,
    _advisoriesProcessed: processed,
    _packagesWithHints: Object.keys(hints).length,
    ...hints,
  };

  if (dryRun) {
    console.log('\n[DRY RUN] Would write:');
    for (const [pkg, fns] of Object.entries(hints).slice(0, 20)) {
      console.log(`  ${pkg}: [${fns.join(', ')}]`);
    }
    if (Object.keys(hints).length > 20) console.log(`  ... and ${Object.keys(hints).length - 20} more`);
  } else {
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, JSON.stringify(output, null, 2) + '\n');
    console.log(`Written to ${outputPath}`);
  }
}

main().catch(e => { console.error(e); process.exit(1); });
