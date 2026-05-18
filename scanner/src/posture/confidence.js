// Calibrated confidence score (0.0–1.0) per finding.
//
// Layered on top of the existing triage score, evidence count, parser type,
// and sanitizer signals. Maps the engine's various internal trust signals
// into a single normalized field that downstream consumers (Claude Code UX,
// SARIF emit, validator pipelines) can rely on.
//
// Output:
//   f.confidence ∈ [0,1]   — combined confidence the finding is real
//   f.confidenceTier       — 'high' | 'medium' | 'low' | 'very-low'
//
// Existing fields preserved (triageScore/triageLabel are unchanged).

const PARSER_PRIOR = {
  AST: 0.10,        // AST detectors are precise
  CHAIN: 0.12,      // attack chains are confirmed by multiple findings
  CONFIRMED: 0.20,  // explicitly confirmed by cross-file taint
  VALIDATOR: 0.25,  // LLM validator accepted
};

const SEVERITY_PRIOR = {
  critical: 0.85,
  high: 0.75,
  medium: 0.55,
  low: 0.35,
  info: 0.20,
};

export function annotateConfidence(findings) {
  if (!Array.isArray(findings)) return;
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    // If the finding already shipped with a hand-tuned confidence (e.g. jwt-exp
    // emits 0.85/0.95), keep that but still normalize the tier label.
    let conf = typeof f.confidence === 'number' ? f.confidence : null;
    if (conf == null) {
      conf = SEVERITY_PRIOR[f.severity] ?? 0.40;
      // Triage score in [0,100] is the strongest signal we have today; weight it.
      if (typeof f.triageScore === 'number') {
        conf = 0.5 * conf + 0.5 * (f.triageScore / 100);
      }
      const parserBoost = PARSER_PRIOR[f.parser] || 0;
      conf = Math.min(1, conf + parserBoost);
      if (f.evidence && f.evidence.length > 1) conf = Math.min(1, conf + 0.05 * (f.evidence.length - 1));
      if (f.sanitizerMismatch) conf = Math.min(1, conf + 0.05);
      if (f.isSanitized) conf *= 0.10;
      if (f.routeRooted) conf = Math.min(1, conf + 0.05);
      if (f.guards && f.guards.length) conf *= 0.80;
      if (f.reachable === false) conf *= 0.55;
      if (f.unvalidated) conf *= 0.85;   // LLM validator unavailable
      if (f.llmOnly) conf *= 0.70;       // LLM-only finding, no Layer-2 path
    }
    conf = Math.max(0, Math.min(1, conf));
    f.confidence = Math.round(conf * 1000) / 1000;
    if (f.confidence >= 0.75) f.confidenceTier = 'high';
    else if (f.confidence >= 0.50) f.confidenceTier = 'medium';
    else if (f.confidence >= 0.25) f.confidenceTier = 'low';
    else f.confidenceTier = 'very-low';
  }
}
