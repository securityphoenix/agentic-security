// Auditor agent — Phase 3 of the three-agent review pipeline.
//
// Reads the red team's attack transcript AND the blue team's hardening
// recommendations, then issues a final verdict:
//
//   verdict:
//     exploit-confirmed   — red team produced data-exfil / priv-esc /
//                            account-takeover outcome AND blue team's
//                            recommendations don't already exist in the code.
//     exploit-mitigable   — red team confirmed but blue team's static
//                            hardening would close it (apply the patches).
//     exploit-uncertain   — red team partial / aborted; need deeper review.
//     exploit-rejected    — red team failed to reach any business-impact
//                            outcome; defense is adequate.
//
// Like defender-agent and adversary-agent: bounded LLM, hash-chained
// transcript, no-op fallback (static heuristic) without an LLM endpoint.

import * as crypto from 'node:crypto';

const TOOL_ACL = new Set([
  'compare_attack_to_defense',
  'check_patch_state',
  'record_verdict',
]);

const _RED_SUCCESS = new Set([
  'data-exfil', 'priv-esc', 'account-takeover', 'financial-loss', 'cleanup-traces',
]);

function chainHash(prev, entry) {
  const h = crypto.createHash('sha256');
  h.update(prev || '');
  h.update(JSON.stringify(entry));
  return h.digest('hex').slice(0, 16);
}

function _staticVerdict(redTeamTranscript, defenderResult) {
  const outcome = redTeamTranscript?.outcome || 'failed';
  const recCount = (defenderResult?.recommendations || []).length;
  if (_RED_SUCCESS.has(outcome)) {
    return recCount >= 1 ? 'exploit-mitigable' : 'exploit-confirmed';
  }
  if (outcome === 'failed' || outcome === 'unverified-no-llm-endpoint') {
    return 'exploit-uncertain';
  }
  if (outcome === 'aborted-budget' || outcome === 'aborted-timeout') {
    return 'exploit-uncertain';
  }
  return 'exploit-rejected';
}

function _rationale(verdict, redOutcome, recCount) {
  switch (verdict) {
    case 'exploit-confirmed':
      return `Red team produced "${redOutcome}" and no static hardening template exists for this family — manual remediation required.`;
    case 'exploit-mitigable':
      return `Red team produced "${redOutcome}" but ${recCount} concrete hardening step${recCount === 1 ? '' : 's'} would close the gap. Apply them and re-run.`;
    case 'exploit-uncertain':
      return `Red team did not reach a business-impact outcome (outcome="${redOutcome}"). Re-run with a longer budget or live target before treating as resolved.`;
    case 'exploit-rejected':
      return `Red team failed to produce a business-impact outcome. Existing defenses appear adequate against the modeled attacker.`;
    default:
      return 'No rationale available.';
  }
}

function startAuditorTranscript(finding, redTeamTranscript, defenderResult) {
  const seed = {
    seedFinding: {
      stableId: finding?.stableId || null,
      file: finding?.file || null,
      line: finding?.line || null,
      vuln: finding?.vuln || null,
    },
    redOutcome: redTeamTranscript?.outcome || null,
    defenderMode: defenderResult?.mode || null,
    defenderRecCount: (defenderResult?.recommendations || []).length,
    startedAt: new Date().toISOString(),
    entries: [],
    chainHead: '',
  };
  seed.chainHead = chainHash('', seed.seedFinding);
  return seed;
}

function appendAuditorEntry(transcript, entry) {
  if (!transcript || !entry) return;
  if (entry.tool && !TOOL_ACL.has(entry.tool)) {
    entry = { ...entry, refused: true, refusedReason: `tool '${entry.tool}' not in auditor ACL` };
  }
  transcript.chainHead = chainHash(transcript.chainHead, entry);
  transcript.entries.push({ ...entry, hash: transcript.chainHead });
}

export async function runAuditor(finding, redTeamTranscript, defenderResult, opts = {}) {
  const transcript = startAuditorTranscript(finding, redTeamTranscript, defenderResult);
  const verdict = _staticVerdict(redTeamTranscript, defenderResult);
  const redOutcome = redTeamTranscript?.outcome || 'unknown';
  const recCount = (defenderResult?.recommendations || []).length;
  const rationale = _rationale(verdict, redOutcome, recCount);
  appendAuditorEntry(transcript, { phase: 'static-verdict', verdict, rationale });
  if (typeof opts.llmInvoke === 'function' && process.env.AGENTIC_SECURITY_LLM_ENDPOINT) {
    try {
      const llmReview = await opts.llmInvoke(transcript);
      appendAuditorEntry(transcript, { phase: 'llm-review', review: llmReview });
      return { transcript, verdict, rationale, llmReview, mode: 'llm-augmented' };
    } catch (e) {
      appendAuditorEntry(transcript, { phase: 'llm-error', error: String(e?.message || e) });
    }
  }
  return { transcript, verdict, rationale, mode: 'static-only' };
}

export { TOOL_ACL };
