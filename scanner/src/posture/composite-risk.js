// Composite risk score — derived 0–100 ordinal for agent + UI ordering.
//
// Today three independent ordinals coexist on every finding:
//   1. f.exploitability ∈ [0,1]  (posture/exploitability.js)
//   2. f.toxicityScore: integer  (engine.js scoreToxicity — unbounded)
//   3. f.mitigationVerdict       (posture/mitigation-composite.js — 3-state enum)
//
// An agent sorting "which finding first" has no canonical key. This
// annotator composes the three into one normalized 0–100 ordinal:
//
//   compositeRisk           — 0..100 number, sortable
//   compositeRiskTier       — 'critical' | 'high' | 'medium' | 'low' | 'minimal'
//   compositeRiskFactors    — provenance strings; same pattern as
//                             f.exploitabilityFactors. The reader can audit
//                             how the score was assembled.
//
// IMPORTANT — this is NOT a probability.
//
// The plan calls it a derived field on purpose: the three upstream signals
// are themselves not calibrated probabilities. compositeRisk inherits that
// limitation. Treat it as a triage key for "show me top 10," not as a
// number to render as "65% likely to be exploited."
//
// The annotator NEVER modifies the inputs (exploitability, toxicityScore,
// mitigationVerdict). They retain their independent shapes for callers
// that depend on them.

// Tier thresholds. Calibrated against the SEVERITY_BASE constants from
// exploitability.js so that:
//   - a critical sev + reachable + KEV produces a 'critical' tier
//   - a medium sev with no extra signals produces 'low' or 'medium'
// These can move once we have a held-out labeled corpus; for now they are
// hand-picked.
const TIER_THRESHOLDS = [
  { min: 85, name: 'critical' },
  { min: 65, name: 'high'     },
  { min: 35, name: 'medium'   },
  { min: 15, name: 'low'      },
  { min:  0, name: 'minimal'  },
];

function tierFor(score) {
  for (const t of TIER_THRESHOLDS) if (score >= t.min) return t.name;
  return 'minimal';
}

function scoreOne(f) {
  const factors = [];
  // Base: exploitability is the most informative single signal. Scale 0–1
  // to 0–100. Findings with no exploitability fall back to severity-only
  // ordinals via toxicityScore below.
  let base = 0;
  if (typeof f.exploitability === 'number' && Number.isFinite(f.exploitability)) {
    base = f.exploitability * 100;
    factors.push(`exploit:${f.exploitability}`);
  } else if (f.severity) {
    // Conservative fallback: rough severity-only mapping. Stops the score
    // from being 0 on findings that bypassed annotateExploitability.
    const sevBase = { critical: 70, high: 55, medium: 35, low: 20, info: 10 }[f.severity];
    if (typeof sevBase === 'number') {
      base = sevBase;
      factors.push(`sev-only:${f.severity}`);
    }
  }

  // Mitigation verdict adjusts the base. 'mitigated-in-prod' and
  // 'unreachable-in-prod' are demoting; 'exposed-in-prod' is neutral.
  // The multipliers err conservative — even an unreachable critical KEV
  // keeps a floor (mitigations might be wrong; the finding still merits
  // a human glance).
  if (f.mitigationVerdict === 'mitigated-in-prod') {
    base *= 0.4;
    factors.push('mitigated-in-prod');
  } else if (f.mitigationVerdict === 'unreachable-in-prod') {
    base *= 0.2;
    factors.push('unreachable-in-prod');
  } else if (f.mitigationVerdict === 'exposed-in-prod') {
    factors.push('exposed-in-prod');
  }

  // Toxicity nudge: toxicityScore is unbounded but typically caps around
  // 150 on the noisiest findings. Scale by /10 and cap at +15 so it can
  // tie-break peers but never dominate.
  if (typeof f.toxicityScore === 'number' && Number.isFinite(f.toxicityScore) && f.toxicityScore > 0) {
    const nudge = Math.min(15, f.toxicityScore / 10);
    base += nudge;
    factors.push(`toxicity+${nudge.toFixed(1)}`);
  }

  // KEV / EPSS-now overrides — even when other signals are weak, an
  // actively-weaponized CVE deserves attention. Floor at high-tier.
  if (f.kev === true || f.kevListed === true || f.weaponized === true) {
    base = Math.max(base, 80);
    factors.push('kev-floor:80');
  }
  if (f.exploitedNow === true) {
    base = Math.max(base, 75);
    factors.push('exploited-now-floor:75');
  }

  const score = Math.round(Math.max(0, Math.min(100, base)));
  return { score, factors };
}

export function annotateCompositeRisk(findings) {
  if (!Array.isArray(findings)) return findings;
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    try {
      const { score, factors } = scoreOne(f);
      f.compositeRisk = score;
      f.compositeRiskTier = tierFor(score);
      f.compositeRiskFactors = factors;
    } catch (_) {
      // No-throw contract for posture annotators (see posture/CLAUDE.md).
      f.compositeRisk = null;
      f.compositeRiskTier = null;
      f.compositeRiskFactors = [];
    }
  }
  return findings;
}
