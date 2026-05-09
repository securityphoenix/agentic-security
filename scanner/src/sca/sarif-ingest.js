// 0.7.0 Feat-7: SARIF 2.1.0 ingest — normalizes and merges external scanner findings into unified report.
//
// Reads SARIF 2.1.0 from gitleaks / Semgrep / Bandit / Trivy / Checkov / SonarQube
// and merges into our scan. Findings are normalised + deduplicated against our
// own findings via a fingerprint of (CWE/CVE, file, line ±2, rule), and a
// `sources[]` array is added to the merged finding so attribution is preserved.
//
// Pure ESM, no external deps. Reads JSON only — no schema validation library.

import * as fs from 'node:fs';
import * as crypto from 'node:crypto';

// Tool-name → (kind, defaultSeverityIfUnset)
const TOOL_PROFILE = {
  'semgrep':       { kind: 'sast',   defSev: 'medium' },
  'opengrep':      { kind: 'sast',   defSev: 'medium' },
  'bandit':        { kind: 'sast',   defSev: 'medium' },
  'eslint':        { kind: 'sast',   defSev: 'low' },
  'sonarqube':     { kind: 'sast',   defSev: 'medium' },
  'codeql':        { kind: 'sast',   defSev: 'high' },
  'gitleaks':      { kind: 'secret', defSev: 'high' },
  'trufflehog':    { kind: 'secret', defSev: 'high' },
  'detect-secrets':{ kind: 'secret', defSev: 'high' },
  'trivy':         { kind: 'sca',    defSev: 'high' },
  'grype':         { kind: 'sca',    defSev: 'high' },
  'osv-scanner':   { kind: 'sca',    defSev: 'high' },
  'checkov':       { kind: 'iac',    defSev: 'medium' },
  'tfsec':         { kind: 'iac',    defSev: 'medium' },
  'kics':          { kind: 'iac',    defSev: 'medium' },
};

// SARIF level → our severity tier
const LEVEL_MAP = { error: 'critical', warning: 'high', note: 'medium', none: 'low' };

// Normalize a tool name into a TOOL_PROFILE key (case + version-agnostic)
function _toolKey(rawName) {
  if (!rawName) return null;
  const n = String(rawName).toLowerCase().replace(/[^a-z0-9-]/g, '');
  for (const k of Object.keys(TOOL_PROFILE)) if (n.includes(k)) return k;
  return null;
}

function _fingerprint(file, line, vuln, cwe) {
  // Bucketed line (±2) so that off-by-one rule reports merge correctly.
  const bucket = Math.floor((line || 0) / 2) * 2;
  const key = `${file}:${bucket}:${(cwe || '').toUpperCase()}:${(vuln || '').replace(/\W+/g, '_').toLowerCase()}`;
  return crypto.createHash('sha256').update(key).digest('hex').slice(0, 16);
}

function _extractCWE(rule) {
  // SARIF rules can carry CWE in `properties.tags`, `properties.cwe`, or `helpUri`.
  const tags = rule?.properties?.tags || [];
  for (const t of tags) {
    const m = String(t).match(/CWE-?(\d+)/i);
    if (m) return `CWE-${m[1]}`;
  }
  if (rule?.properties?.cwe) {
    const m = String(rule.properties.cwe).match(/(\d+)/);
    if (m) return `CWE-${m[1]}`;
  }
  if (rule?.helpUri) {
    const m = rule.helpUri.match(/cwe\.mitre\.org\/data\/definitions\/(\d+)/i);
    if (m) return `CWE-${m[1]}`;
  }
  return null;
}

function _extractCVE(result) {
  // Trivy / Grype / osv-scanner put CVE in ruleId or properties.
  const id = result?.ruleId || '';
  const m = id.match(/(CVE-\d{4}-\d{4,7})/i);
  if (m) return m[1].toUpperCase();
  const tags = result?.properties?.tags || [];
  for (const t of tags) {
    const tm = String(t).match(/(CVE-\d{4}-\d{4,7})/i);
    if (tm) return tm[1].toUpperCase();
  }
  return null;
}

// Convert a single SARIF result + its run context into our normalized finding.
function _resultToFinding(result, run, toolKey, defSev) {
  const loc = result.locations?.[0]?.physicalLocation;
  const file = loc?.artifactLocation?.uri || result?.fingerprints?.path || '(unknown)';
  const line = loc?.region?.startLine || 0;
  const ruleId = result.ruleId || '';
  const rule = (run.tool?.driver?.rules || []).find(r => r.id === ruleId);
  const message = result.message?.text || rule?.fullDescription?.text || rule?.shortDescription?.text || ruleId;
  const sev = LEVEL_MAP[result.level] || defSev;
  const cwe = _extractCWE(rule || result);
  const cve = _extractCVE(result);
  const profile = TOOL_PROFILE[toolKey] || { kind: 'sast', defSev: 'medium' };
  return {
    file: file.replace(/^file:\/\//, ''),
    line,
    severity: sev,
    vuln: cve ? `${cve}: ${message}`.slice(0, 240) : message.slice(0, 240),
    cwe,
    cve,
    kind: profile.kind,
    ruleId,
    snippet: result.locations?.[0]?.physicalLocation?.contextRegion?.snippet?.text
          || result.locations?.[0]?.physicalLocation?.region?.snippet?.text
          || '',
    sources: [run.tool?.driver?.name || toolKey],
  };
}

// Load and parse a SARIF file. Returns an array of normalized findings.
export function ingestSARIFFile(filePath) {
  let raw;
  try { raw = fs.readFileSync(filePath, 'utf8'); }
  catch (e) { throw new Error(`Cannot read SARIF file ${filePath}: ${e.message}`); }
  let doc;
  try { doc = JSON.parse(raw); }
  catch (e) { throw new Error(`Invalid JSON in SARIF file ${filePath}: ${e.message}`); }
  if (!doc || !Array.isArray(doc.runs)) {
    throw new Error(`Not a SARIF document (missing runs[]): ${filePath}`);
  }
  const out = [];
  for (const run of doc.runs) {
    const toolName = run.tool?.driver?.name;
    const toolKey = _toolKey(toolName);
    const profile = TOOL_PROFILE[toolKey] || { kind: 'sast', defSev: 'medium' };
    for (const result of (run.results || [])) {
      try { out.push(_resultToFinding(result, run, toolKey || (toolName||'').toLowerCase(), profile.defSev)); }
      catch (_) {}
    }
  }
  return out;
}

// Merge an array of external findings into the scan result. Mutates `scan` in place.
// Behaviour:
//   - Findings whose fingerprint matches an existing scan.findings entry have their
//     source tool name appended to scan.findings[i].sources[] and (if the external
//     finding's severity is higher) the existing severity is bumped.
//   - New findings (no match) are appended to scan.findings, scan.secrets, or
//     scan.supplyChain depending on `kind`.
export function mergeSARIFFindings(scan, externals) {
  // Index existing findings by fingerprint
  const existingFP = new Map();
  for (const f of (scan.findings || [])) {
    const fp = _fingerprint((f.file||'').split(' -> ').pop(), f.line||f.source?.line||f.sink?.line||0, f.vuln||f.type, f.cwe);
    existingFP.set(fp, f);
  }
  let merged = 0, added = 0;
  const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  for (const ext of externals) {
    const fp = _fingerprint(ext.file, ext.line, ext.vuln, ext.cwe);
    const existing = existingFP.get(fp);
    if (existing) {
      existing.sources = Array.from(new Set([...(existing.sources || ['agentic-security']), ...ext.sources]));
      // Bump severity if the external tool reported higher
      if ((SEV_RANK[ext.severity] || 0) > (SEV_RANK[existing.severity] || 0)) {
        existing.severity = ext.severity;
      }
      merged++;
      continue;
    }
    // Append as new finding into the right bucket
    const id = `sarif-ingest:${fp}`;
    const newFinding = {
      id, kind: ext.kind, severity: ext.severity, vuln: ext.vuln,
      cwe: ext.cwe, file: ext.file, line: ext.line, snippet: ext.snippet || '',
      sources: ext.sources, parser: 'SARIF',
    };
    if (ext.kind === 'secret') (scan.secrets = scan.secrets || []).push(newFinding);
    else if (ext.kind === 'sca') (scan.supplyChain = scan.supplyChain || []).push({ ...newFinding, type: 'vulnerable_dep' });
    else if (ext.kind === 'iac' || ext.kind === 'sast' || ext.kind === 'logic') (scan.findings = scan.findings || []).push(newFinding);
    added++;
  }
  return { merged, added };
}

export function ingestAndMerge(scan, sarifPaths) {
  let totalMerged = 0, totalAdded = 0;
  for (const p of sarifPaths) {
    let externals;
    try { externals = ingestSARIFFile(p); }
    catch (e) { /* swallow per-file errors so one bad SARIF doesn't break the run */ continue; }
    const { merged, added } = mergeSARIFFindings(scan, externals);
    totalMerged += merged;
    totalAdded += added;
  }
  return { merged: totalMerged, added: totalAdded };
}
