// Layer-3 LLM validator (Sentinel-parity FR-L3).
//
// Takes a candidate finding emitted by the Layer-2 (pattern + heuristic +
// cross-file taint) pipeline and asks an LLM endpoint:
//
//   "Is this finding exploitable as described, given this source-to-sink path
//    and the surrounding code? Reply with a JSON object {verdict, confidence,
//    reasoning}."
//
// Outputs (annotated onto the finding in place):
//   f.validator_verdict   : 'accept' | 'reject' | 'escalate' | 'unvalidated'
//   f.llm_confidence      : 0.0 – 1.0  (validator's own score)
//   f.validator_reasoning : string     (truncated to 280 chars)
//
// Determinism: cache key = sha256(file_content || path_signature || prompt
// version || model id). Persisted at .agentic-security/llm-cache/<key>.json.
// Cache hit → byte-identical output (no LLM call).
//
// Graceful degradation: if no endpoint configured, every finding gets
// `unvalidated: true`. The combined-confidence calculation in
// posture/confidence.js already accounts for this.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

const PROMPT_VERSION = 'v1.0';
const CACHE_DIR = '.agentic-security/llm-cache';

const PROMPT_TEMPLATE = `You are a senior application security engineer reviewing a candidate finding from a SAST scanner. Your job is to decide whether the finding is REAL (exploitable as described) or a FALSE POSITIVE.

Reply with ONLY a JSON object — no prose around it — with these keys:
{
  "verdict": "accept" | "reject" | "escalate",
  "confidence": <float between 0 and 1>,
  "reasoning": "<one sentence>"
}

Use "accept" when you are confident the finding is exploitable.
Use "reject" when you are confident it is a false positive (sanitizer present, dead code, validated upstream, etc.).
Use "escalate" when you cannot decide without more code context.

--- FINDING ---
Vuln:         {{vuln}}
Severity:     {{severity}}
CWE:          {{cwe}}
File:         {{file}}:{{line}}
Snippet:      {{snippet}}

--- SOURCE-TO-SINK PATH ---
{{path_summary}}

--- SURROUNDING CODE ---
{{context}}
`;

function endpointConfig() {
  const endpoint = process.env.AGENTIC_SECURITY_LLM_ENDPOINT;
  const apiKey = process.env.AGENTIC_SECURITY_LLM_API_KEY;
  const model = process.env.AGENTIC_SECURITY_LLM_MODEL || 'unknown';
  return endpoint ? { endpoint, apiKey, model } : null;
}

function ensureCacheDir(scanRoot) {
  const dir = path.join(scanRoot || process.cwd(), CACHE_DIR);
  try { fs.mkdirSync(dir, { recursive: true }); } catch {}
  return dir;
}

function cacheKey(finding, fileHash, modelId) {
  const pathSig = (finding.source ? `${finding.source.file}:${finding.source.line}` : '') +
                  '->' +
                  (finding.sink ? `${finding.sink.file}:${finding.sink.line}` : `${finding.file}:${finding.line}`);
  const material = `${fileHash}||${pathSig}||${PROMPT_VERSION}||${modelId}`;
  return crypto.createHash('sha256').update(material).digest('hex');
}

function readCache(scanRoot, key) {
  const fp = path.join(scanRoot || process.cwd(), CACHE_DIR, key + '.json');
  if (!fs.existsSync(fp)) return null;
  try { return JSON.parse(fs.readFileSync(fp, 'utf8')); } catch { return null; }
}

function writeCache(scanRoot, key, value) {
  ensureCacheDir(scanRoot);
  const fp = path.join(scanRoot || process.cwd(), CACHE_DIR, key + '.json');
  try { fs.writeFileSync(fp, JSON.stringify(value, null, 2)); } catch {}
}

function fileHashOf(fileContents, file) {
  if (!file) return '';
  const c = fileContents?.[file];
  if (!c) return '';
  return crypto.createHash('sha256').update(c).digest('hex').slice(0, 32);
}

function renderPrompt(finding, fileContents) {
  const code = fileContents?.[finding.file];
  let context = '';
  if (code && finding.line) {
    const lines = code.split('\n');
    const start = Math.max(0, finding.line - 21);
    const end = Math.min(lines.length, finding.line + 20);
    context = lines.slice(start, end).map((l, i) => `${start + i + 1}: ${l}`).join('\n');
  }
  const pathSummary = finding.source && finding.sink
    ? `${finding.source.file || finding.file}:${finding.source.line || finding.line} [${finding.source.label || '?'}]\n  -> ${finding.sink.file || finding.file}:${finding.sink.line || finding.line} [${finding.sink.label || '?'}]`
    : `${finding.file}:${finding.line} [single-point detection, no cross-file path]`;
  return PROMPT_TEMPLATE
    .replace('{{vuln}}', finding.vuln || 'unknown')
    .replace('{{severity}}', finding.severity || 'unknown')
    .replace('{{cwe}}', finding.cwe || 'unknown')
    .replace('{{file}}', finding.file || '')
    .replace('{{line}}', String(finding.line || ''))
    .replace('{{snippet}}', (finding.snippet || '').slice(0, 400))
    .replace('{{path_summary}}', pathSummary)
    .replace('{{context}}', context || '(no surrounding code available)');
}

async function callEndpoint(endpoint, apiKey, model, prompt) {
  const headers = { 'Content-Type': 'application/json' };
  if (apiKey) headers['Authorization'] = `Bearer ${apiKey}`;
  const body = { prompt, model };
  try {
    const r = await fetch(endpoint, { method: 'POST', headers, body: JSON.stringify(body) });
    if (!r.ok) return { ok: false, error: `HTTP ${r.status}` };
    const j = await r.json().catch(() => null);
    const text = (j && (j.response || j.text || j.content || j.output ||
      j.choices?.[0]?.message?.content || j.message?.content)) || '';
    return { ok: true, text: String(text) };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

function parseLlmResponse(text) {
  if (!text) return null;
  // Extract a JSON object — most models reply with prose around it.
  const m = text.match(/\{[\s\S]*?\}/);
  if (!m) return null;
  try {
    const obj = JSON.parse(m[0]);
    const verdict = ['accept', 'reject', 'escalate'].includes(obj.verdict) ? obj.verdict : 'escalate';
    const confidence = typeof obj.confidence === 'number'
      ? Math.max(0, Math.min(1, obj.confidence))
      : 0.5;
    const reasoning = String(obj.reasoning || '').slice(0, 280);
    return { verdict, confidence, reasoning };
  } catch { return null; }
}

// Validate a single finding. Returns the verdict object (also annotated onto
// the finding). Cache-deterministic by file content + path signature.
export async function validateOne(finding, fileContents, scanRoot) {
  const cfg = endpointConfig();
  if (!cfg) {
    finding.validator_verdict = 'unvalidated';
    finding.unvalidated = true;
    return { verdict: 'unvalidated' };
  }
  const fh = fileHashOf(fileContents, finding.file);
  const key = cacheKey(finding, fh, cfg.model);
  const cached = readCache(scanRoot, key);
  if (cached) {
    finding.validator_verdict = cached.verdict;
    finding.llm_confidence = cached.confidence;
    finding.validator_reasoning = cached.reasoning;
    finding._validatorCache = 'hit';
    return cached;
  }
  const prompt = renderPrompt(finding, fileContents);
  const resp = await callEndpoint(cfg.endpoint, cfg.apiKey, cfg.model, prompt);
  if (!resp.ok) {
    finding.validator_verdict = 'unvalidated';
    finding.unvalidated = true;
    finding._validatorError = resp.error;
    return { verdict: 'unvalidated', error: resp.error };
  }
  const parsed = parseLlmResponse(resp.text);
  if (!parsed) {
    finding.validator_verdict = 'unvalidated';
    finding.unvalidated = true;
    finding._validatorError = 'unparseable-response';
    return { verdict: 'unvalidated', error: 'unparseable-response' };
  }
  writeCache(scanRoot, key, { ...parsed, model: cfg.model, prompt_version: PROMPT_VERSION });
  finding.validator_verdict = parsed.verdict;
  finding.llm_confidence = parsed.confidence;
  finding.validator_reasoning = parsed.reasoning;
  finding._validatorCache = 'miss';
  return parsed;
}

// Validate many findings. Skipped findings get unvalidated:true. Respects an
// opt-in env (AGENTIC_SECURITY_LLM_VALIDATE=1) so the validator only runs
// when explicitly enabled — otherwise we annotate unvalidated:true without
// any network calls.
export async function validateMany(findings, { fileContents, scanRoot, concurrency = 4 } = {}) {
  if (!Array.isArray(findings) || findings.length === 0) return findings;
  const enabled = process.env.AGENTIC_SECURITY_LLM_VALIDATE === '1' && !!endpointConfig();
  if (!enabled) {
    for (const f of findings) {
      f.validator_verdict = 'unvalidated';
      f.unvalidated = true;
    }
    return findings;
  }
  // Only validate findings that could plausibly benefit — high+ severity, or
  // findings the engine already flagged as low-confidence.
  const candidates = findings.filter(f =>
    /critical|high/.test(f.severity || '') ||
    (typeof f.confidence === 'number' && f.confidence < 0.6) ||
    f.parser === 'AST');
  // Bounded concurrency.
  let i = 0;
  async function worker() {
    while (i < candidates.length) {
      const idx = i++;
      try { await validateOne(candidates[idx], fileContents, scanRoot); }
      catch (e) {
        candidates[idx].validator_verdict = 'unvalidated';
        candidates[idx].unvalidated = true;
        candidates[idx]._validatorError = e.message;
      }
    }
  }
  await Promise.all(Array.from({ length: Math.max(1, concurrency) }, () => worker()));
  // Findings not in candidates are explicitly unvalidated.
  for (const f of findings) {
    if (f.validator_verdict) continue;
    f.validator_verdict = 'unvalidated';
    f.unvalidated = true;
  }
  return findings;
}

// Apply validator verdicts: reject → drop, escalate → keep but mark, accept →
// boost confidence. Returns { kept, dropped }.
export function applyValidatorVerdicts(findings) {
  const kept = [];
  const dropped = [];
  for (const f of findings) {
    if (f.validator_verdict === 'reject') {
      f._droppedBy = 'llm-validator';
      dropped.push(f);
      continue;
    }
    if (f.validator_verdict === 'accept' && typeof f.llm_confidence === 'number') {
      f.confidence = Math.max(f.confidence || 0, Math.min(1, f.llm_confidence + 0.05));
    }
    kept.push(f);
  }
  return { kept, dropped };
}

export const _internal = { PROMPT_VERSION, renderPrompt, parseLlmResponse, cacheKey };
