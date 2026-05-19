// Three-agent adversarial review pipeline.
//
// Composes the existing single-step adversary-agent (red team) with the
// defender-agent and auditor-agent into a single bounded cascade per
// finding:
//
//     red.runAgent(finding, target)  →  attack transcript + outcome
//     blue.runDefender(finding, red) →  hardening recommendations
//     auditor.runAuditor(finding, red, blue) → final verdict
//
// Each phase is hash-chained; the final output is a structured envelope
// the slash command can render. Without a configured LLM endpoint, every
// phase short-circuits to its static-analysis equivalent — the cascade
// still produces a useful artifact (static hardening + static verdict).

import { runAgent as runRedTeam } from './adversary-agent.js';
import { runDefender } from './defender-agent.js';
import { runAuditor } from './auditor-agent.js';

const DEFAULT_RED_BUDGET = { maxCalls: 30, maxWallMs: 8 * 60 * 1000 };

export async function runThreeAgentReview(finding, opts = {}) {
  const target = opts.target || '';
  const startedAt = new Date().toISOString();

  // Phase 1 — red team.
  const red = await runRedTeam(finding, {
    target,
    maxCalls: opts.maxCalls ?? DEFAULT_RED_BUDGET.maxCalls,
    maxWallMs: opts.maxWallMs ?? DEFAULT_RED_BUDGET.maxWallMs,
    llmInvoke: opts.redLlmInvoke,
    executeTool: opts.redExecuteTool,
  });

  // Phase 2 — blue team. Reads the red transcript.
  const blue = await runDefender(finding, red.transcript, {
    llmInvoke: opts.blueLlmInvoke,
  });

  // Phase 3 — auditor. Reads both prior transcripts.
  const audit = await runAuditor(finding, red.transcript, blue, {
    llmInvoke: opts.auditorLlmInvoke,
  });

  return {
    startedAt,
    finishedAt: new Date().toISOString(),
    finding: {
      stableId: finding?.stableId || null,
      file: finding?.file || null,
      line: finding?.line || null,
      vuln: finding?.vuln || null,
      family: finding?.family || null,
      severity: finding?.severity || null,
    },
    red: {
      outcome: red.outcome,
      toolCallCount: (red.transcript?.entries || []).filter(e => e.tool).length,
      transcriptHead: red.transcript?.chainHead || null,
    },
    blue: {
      mode: blue.mode,
      recommendations: blue.recommendations || [],
      transcriptHead: blue.transcript?.chainHead || null,
    },
    auditor: {
      verdict: audit.verdict,
      rationale: audit.rationale,
      mode: audit.mode,
      transcriptHead: audit.transcript?.chainHead || null,
    },
    target,
  };
}
