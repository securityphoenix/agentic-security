// Worker-thread parallelism infrastructure for per-file SAST analysis.
//
// Gated behind AGENTIC_SECURITY_PARALLEL=1 (default OFF).
// When enabled, distributes per-file detector execution across a bounded
// worker pool (default 2 workers, max 4).
//
// Architecture:
//   - Main thread: orchestrates file distribution, collects findings
//   - Workers: receive (filepath, content), run detectors, return findings[]
//   - Bounded queue prevents memory exhaustion on large monorepos
//
// v1: stub infrastructure. The actual worker dispatch is deferred until
// the per-file detectors are refactored into a single function that can
// be serialized to a worker. Today the detectors import 60+ modules with
// shared state (e.g., _GLOBAL_JAVA_TAINTED_METHODS), making them
// non-trivially parallelizable.

import { availableParallelism } from 'node:os';

export function isParallelEnabled() {
  return process.env.AGENTIC_SECURITY_PARALLEL === '1';
}

export function recommendedWorkerCount() {
  const cpus = availableParallelism();
  return Math.max(1, Math.min(4, Math.floor(cpus / 2)));
}

export function createParallelContext(opts = {}) {
  const workerCount = opts.workers || recommendedWorkerCount();
  return {
    enabled: isParallelEnabled(),
    workerCount,
    filesProcessed: 0,
    totalMs: 0,
    _stats: {
      dispatched: 0,
      completed: 0,
      errors: 0,
      avgMs: 0,
    },
  };
}

export async function runParallelFileScans(files, fileContents, detectorFn, opts = {}) {
  if (!isParallelEnabled()) return null;

  const ctx = createParallelContext(opts);
  const results = [];

  // v1 stub: run sequentially but through the parallel context for testing.
  // v2 will use worker_threads with a bounded queue.
  for (const fp of files) {
    const content = fileContents[fp];
    if (!content) continue;
    const t0 = Date.now();
    try {
      const findings = detectorFn(fp, content);
      results.push(...(findings || []));
      ctx._stats.completed++;
    } catch {
      ctx._stats.errors++;
    }
    ctx._stats.dispatched++;
    ctx.totalMs += Date.now() - t0;
    ctx.filesProcessed++;
  }
  ctx._stats.avgMs = ctx.filesProcessed ? Math.round(ctx.totalMs / ctx.filesProcessed) : 0;
  return { findings: results, stats: ctx._stats };
}
