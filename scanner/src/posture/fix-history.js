// Fix history — preview, apply, undo for auto-fixes.
//
// Every applied fix:
//   1. Saves the original file contents to .agentic-security/fix-history/<id>.bak
//   2. Records {findingId, file, originalSha256, appliedAt, ruleId} in
//      .agentic-security/fix-history/log.json
//
// `agentic-security undo` reverts the most recent applied fix (or `--all`
// to revert every fix in the log, in reverse order).

import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

function historyDir(scanRoot) {
  return path.join(scanRoot, '.agentic-security', 'fix-history');
}
function logPath(scanRoot) { return path.join(historyDir(scanRoot), 'log.json'); }

function ensure(scanRoot) { fs.mkdirSync(historyDir(scanRoot), { recursive: true }); }

export function readLog(scanRoot) {
  const fp = logPath(scanRoot);
  if (!fs.existsSync(fp)) return [];
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); } catch { return []; }
}
function writeLog(scanRoot, log) {
  ensure(scanRoot);
  fs.writeFileSync(logPath(scanRoot), JSON.stringify(log, null, 2));
}
function sha(s) { return crypto.createHash('sha256').update(s).digest('hex').slice(0, 16); }

// Build a unified-diff-ish preview between two strings, with line numbers.
// Not a real `diff -u`, but readable enough for the vibecoder use case.
export function preview(originalContent, newContent, file) {
  const a = originalContent.split('\n');
  const b = newContent.split('\n');
  const max = Math.max(a.length, b.length);
  const out = [`--- ${file} (before)`, `+++ ${file} (after)`];
  let firstDiff = -1, lastDiff = -1;
  for (let i = 0; i < max; i++) {
    if ((a[i] || '') !== (b[i] || '')) {
      if (firstDiff < 0) firstDiff = i;
      lastDiff = i;
    }
  }
  if (firstDiff < 0) { out.push('(no changes)'); return out.join('\n'); }
  const ctx = 3;
  const start = Math.max(0, firstDiff - ctx);
  const end = Math.min(max, lastDiff + ctx + 1);
  for (let i = start; i < end; i++) {
    const sa = a[i], sb = b[i];
    if (sa === sb) out.push(`  ${String(i + 1).padStart(4)}  ${sa ?? ''}`);
    else {
      if (sa !== undefined) out.push(`- ${String(i + 1).padStart(4)}  ${sa}`);
      if (sb !== undefined) out.push(`+ ${String(i + 1).padStart(4)}  ${sb}`);
    }
  }
  return out.join('\n');
}

// Apply a fix and record it in history. Returns the history entry.
export async function applyFix({ scanRoot, file, originalContent, newContent, findingId, ruleId, vuln }) {
  ensure(scanRoot);
  const absFile = path.resolve(scanRoot, file);
  const id = `fix-${Date.now().toString(36)}-${sha(file + findingId).slice(0, 6)}`;
  const bakPath = path.join(historyDir(scanRoot), `${id}.bak`);
  await fsp.writeFile(bakPath, originalContent);
  await fsp.writeFile(absFile, newContent);
  const entry = {
    id,
    findingId,
    ruleId: ruleId || null,
    vuln: vuln || null,
    file,
    backupPath: path.relative(scanRoot, bakPath),
    originalSha: sha(originalContent),
    newSha: sha(newContent),
    appliedAt: new Date().toISOString(),
    reverted: false,
  };
  const log = readLog(scanRoot);
  log.push(entry);
  writeLog(scanRoot, log);
  return entry;
}

// Revert the most recent un-reverted fix. Returns the entry or null.
export async function undoLast(scanRoot) {
  const log = readLog(scanRoot);
  for (let i = log.length - 1; i >= 0; i--) {
    if (!log[i].reverted) {
      const entry = log[i];
      const bak = path.resolve(scanRoot, entry.backupPath);
      const absFile = path.resolve(scanRoot, entry.file);
      if (!fs.existsSync(bak)) return { error: `backup missing: ${bak}` };
      const original = await fsp.readFile(bak, 'utf8');
      await fsp.writeFile(absFile, original);
      entry.reverted = true;
      entry.revertedAt = new Date().toISOString();
      writeLog(scanRoot, log);
      return entry;
    }
  }
  return null;
}

// Revert everything that hasn't been reverted, in reverse order.
export async function undoAll(scanRoot) {
  const reverted = [];
  let r;
  while ((r = await undoLast(scanRoot)) && !r.error) reverted.push(r);
  return reverted;
}

export function listHistory(scanRoot) { return readLog(scanRoot); }
