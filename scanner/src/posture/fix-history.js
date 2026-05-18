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

// Premortem 3R-12: cross-check helpers for last-scan.json. We look up
// findings by `id` (the finding's canonical key from the engine) so we can
// stash the corresponding stableId on the fix entry and verify in recover().
function _lastScanPath(scanRoot) {
  return path.join(scanRoot, '.agentic-security', 'last-scan.json');
}
function _readLastScan(scanRoot) {
  const fp = _lastScanPath(scanRoot);
  if (!fs.existsSync(fp)) return null;
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); } catch { return null; }
}
function _allFindings(scan) {
  if (!scan || typeof scan !== 'object') return [];
  return [
    ...(scan.findings || []),
    ...(scan.logicVulns || []),
    ...(scan.secrets || []),
    ...(scan.sca || []),
    ...(scan.iac || []),
  ];
}
function _lookupStableId(scanRoot, findingId) {
  const scan = _readLastScan(scanRoot);
  if (!scan) return null;
  for (const f of _allFindings(scan)) {
    if (f && f.id === findingId) return f.stableId || null;
  }
  return null;
}
function _findingStillPresent(scanRoot, entry) {
  const scan = _readLastScan(scanRoot);
  if (!scan) return null;  // unknown — caller treats as "skip cross-check"
  for (const f of _allFindings(scan)) {
    if (!f) continue;
    if (entry.stableId && f.stableId && f.stableId === entry.stableId) return true;
    if (entry.findingId && f.id === entry.findingId) return true;
  }
  return false;
}

// Premortem 3R-13: writing fix-history/log.json from concurrent
// applyFix / recover() invocations can interleave and corrupt the JSON. We
// use an exclusive (wx) lockfile under the history dir; whoever creates it
// wins, others spin briefly. The lock is released in finally{}. Stale
// locks > 30s are reaped on contention.
async function _withLogLock(scanRoot, fn) {
  ensure(scanRoot);
  const lockPath = path.join(historyDir(scanRoot), 'log.lock');
  const startedAt = Date.now();
  const TIMEOUT_MS = 5000;
  while (true) {
    try {
      const handle = await fsp.open(lockPath, 'wx');
      await handle.writeFile(String(process.pid));
      try { await handle.close(); } catch {}
      try {
        return await fn();
      } finally {
        try { await fsp.unlink(lockPath); } catch {}
      }
    } catch (e) {
      if (e && e.code === 'EEXIST') {
        try {
          const st = await fsp.stat(lockPath);
          if (Date.now() - st.mtimeMs > 30000) {
            try { await fsp.unlink(lockPath); } catch {}
            continue;
          }
        } catch {}
        if (Date.now() - startedAt > TIMEOUT_MS) {
          throw new Error('fix-history: log lock timed out');
        }
        await new Promise(r => setTimeout(r, 25));
        continue;
      }
      throw e;
    }
  }
}

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

// Apply a fix and record it in history. Two-phase commit (premortem P2-9):
//
//   1. Write the backup file + fsync.
//   2. Write the log with the entry marked status='pending' + fsync.
//   3. Write the new file content + fsync.
//   4. Update the log entry to status='applied' + fsync.
//
// If we crash between (1) and (3) — backup exists, log entry says 'pending',
// file is untouched. `recover()` rolls forward by deleting the pending entry.
// If we crash between (3) and (4) — backup exists, log entry says 'pending',
// file IS the new content. `recover()` checks file hash; if it matches newSha
// the entry is promoted to 'applied'; if it matches originalSha it's dropped.
//
// This guarantees the file is never modified without a corresponding
// recoverable log entry.
export async function applyFix({ scanRoot, file, originalContent, newContent, findingId, ruleId, vuln, stableId }) {
  return _withLogLock(scanRoot, async () => {
    ensure(scanRoot);
    const absFile = path.resolve(scanRoot, file);
    const id = `fix-${Date.now().toString(36)}-${sha(file + findingId).slice(0, 6)}`;
    const bakPath = path.join(historyDir(scanRoot), `${id}.bak`);
    // Phase 1: backup + fsync.
    await _writeAndSync(bakPath, originalContent);
    const resolvedStableId = stableId || _lookupStableId(scanRoot, findingId);
    const entry = {
      id,
      findingId,
      stableId: resolvedStableId || null,
      ruleId: ruleId || null,
      vuln: vuln || null,
      file,
      backupPath: path.relative(scanRoot, bakPath),
      originalSha: sha(originalContent),
      newSha: sha(newContent),
      appliedAt: new Date().toISOString(),
      status: 'pending',
      reverted: false,
    };
    // Phase 2: log entry marked pending + fsync.
    const log = readLog(scanRoot);
    log.push(entry);
    await _writeLogAndSync(scanRoot, log);
    // Phase 3: write the new content to the target file + fsync.
    try {
      await _writeAndSync(absFile, newContent);
    } catch (e) {
      entry.status = 'failed';
      entry.error = e.message;
      await _writeLogAndSync(scanRoot, log);
      throw e;
    }
    // Phase 4: promote to applied.
    entry.status = 'applied';
    await _writeLogAndSync(scanRoot, log);
    return entry;
  });
}

async function _writeAndSync(fp, content) {
  await fsp.mkdir(path.dirname(fp), { recursive: true });
  const handle = await fsp.open(fp, 'w');
  try {
    await handle.writeFile(content);
    if (typeof handle.sync === 'function') await handle.sync();
  } finally {
    await handle.close();
  }
}

async function _writeLogAndSync(scanRoot, log) {
  ensure(scanRoot);
  const fp = logPath(scanRoot);
  const handle = await fsp.open(fp, 'w');
  try {
    await handle.writeFile(JSON.stringify(log, null, 2));
    if (typeof handle.sync === 'function') await handle.sync();
  } finally {
    await handle.close();
  }
}

// Recover from a crash mid-applyFix. Reads the log, examines any 'pending'
// entries, compares the file's current sha against entry.newSha / .originalSha,
// and either promotes to 'applied' or drops the entry. Returns the recovered
// entries.
export async function recover(scanRoot) {
  return _withLogLock(scanRoot, () => _recoverInner(scanRoot));
}

async function _recoverInner(scanRoot) {
  const log = readLog(scanRoot);
  const recovered = [];
  for (const e of log) {
    if (e.status !== 'pending') continue;
    const absFile = path.resolve(scanRoot, e.file);
    let curr;
    try { curr = await fsp.readFile(absFile, 'utf8'); }
    catch { e.status = 'failed'; e.error = 'file-missing'; recovered.push(e); continue; }
    const currSha = sha(curr);
    if (currSha === e.newSha) {
      // Premortem 3R-12: before blindly promoting a pending fix to applied,
      // cross-check that the finding is still recognized by last-scan.json.
      // If last-scan was re-run during the crash and the issue has vanished
      // (fixed externally, file refactored away), we record that ambiguity
      // rather than tagging this as a successful auto-fix.
      const stillPresent = _findingStillPresent(scanRoot, e);
      if (stillPresent === false) {
        e.status = 'applied-stale';
        e.error = 'finding-not-in-last-scan';
      } else {
        e.status = 'applied';
      }
      e.recoveredAt = new Date().toISOString();
      recovered.push(e);
    } else if (currSha === e.originalSha) {
      e.status = 'failed';
      e.error = 'file-untouched-during-crash';
      e.recoveredAt = new Date().toISOString();
      recovered.push(e);
    } else {
      e.status = 'failed';
      e.error = `file-content-mismatch-curr-sha=${currSha}`;
      e.recoveredAt = new Date().toISOString();
      recovered.push(e);
    }
  }
  if (recovered.length) await _writeLogAndSync(scanRoot, log);
  return recovered;
}

// Revert the most recent un-reverted fix. Returns the entry or null.
export async function undoLast(scanRoot) {
  return _withLogLock(scanRoot, async () => {
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
  });
}

// Revert everything that hasn't been reverted, in reverse order.
export async function undoAll(scanRoot) {
  const reverted = [];
  let r;
  while ((r = await undoLast(scanRoot)) && !r.error) reverted.push(r);
  return reverted;
}

export function listHistory(scanRoot) { return readLog(scanRoot); }

// Premortem 3R-17: fix-history/log.json grows monotonically. A long-running
// project will accumulate thousands of entries over years. We compact by
// archiving entries older than the retention window and reverted entries
// to log-archive-<YYYY-MM>.json, leaving only "fresh" (active or recent)
// entries in the active log. .bak files referenced by archived entries
// can be optionally pruned (only when `--prune-backups` flag is set,
// since their absence would break undo).
export async function compactLog(scanRoot, opts = {}) {
  return _withLogLock(scanRoot, async () => {
    const retainDays = typeof opts.retainDays === 'number' ? opts.retainDays : 90;
    const pruneBackups = !!opts.pruneBackups;
    const cutoff = Date.now() - retainDays * 24 * 60 * 60 * 1000;
    const log = readLog(scanRoot);
    const keep = [];
    const archive = [];
    for (const e of log) {
      const tsStr = e.recoveredAt || e.revertedAt || e.appliedAt;
      const ts = tsStr ? Date.parse(tsStr) : Date.now();
      const old = isFinite(ts) && ts < cutoff;
      const terminal = e.reverted === true || e.status === 'failed' || e.status === 'applied-stale';
      if (old && terminal) archive.push(e);
      else keep.push(e);
    }
    if (archive.length) {
      const month = new Date().toISOString().slice(0, 7);
      const archivePath = path.join(historyDir(scanRoot), `log-archive-${month}.json`);
      let prior = [];
      try { prior = JSON.parse(await fsp.readFile(archivePath, 'utf8')); } catch { prior = []; }
      await _writeAndSync(archivePath, JSON.stringify(prior.concat(archive), null, 2));
      if (pruneBackups) {
        for (const e of archive) {
          if (!e.backupPath) continue;
          const bak = path.resolve(scanRoot, e.backupPath);
          try { await fsp.unlink(bak); } catch {}
        }
      }
      await _writeLogAndSync(scanRoot, keep);
    }
    return { archived: archive.length, kept: keep.length };
  });
}
