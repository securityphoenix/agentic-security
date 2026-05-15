// Custom pattern-rule DSL — Semgrep-lite for in-repo rules.
//
// Lives alongside the existing source/sink/sanitizer custom rules in
// engine.js's `_loadCustomRules`. Pattern rules are simpler: a regex (or a
// list of regexes that must ALL match within N lines), a severity, a CWE,
// and a remediation hint. Authors get findings produced directly without
// needing to model dataflow.
//
// File location: .agentic-security/rules/*.yml
//
// Example rule:
//   id: my-org/no-eval
//   title: "Use of eval() is forbidden"
//   severity: high
//   cwe: CWE-95
//   languages: [javascript, typescript]
//   match:
//     pattern: "\\beval\\s*\\("
//   message: "eval() bypasses our static-analysis controls; use JSON.parse or a sandbox."
//
// Supports:
//   match.pattern         — single regex
//   match.allOf: [regex…] — every regex must match somewhere in the file
//   match.notMatch: regex — kill if this regex matches
//   match.window: N       — when allOf is set, all matches must fall within N lines
//
// `agentic-security rule test <fixture-glob>` runs every rule against every
// file and prints PASS/FAIL.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as yaml from 'js-yaml';
import fg from 'fast-glob';

const LANG_EXTS = {
  javascript: ['.js', '.mjs', '.cjs', '.jsx'],
  typescript: ['.ts', '.tsx'],
  python:     ['.py'],
  go:         ['.go'],
  ruby:       ['.rb'],
  java:       ['.java'],
  rust:       ['.rs'],
  csharp:     ['.cs'],
  php:        ['.php'],
  yaml:       ['.yml', '.yaml'],
  any:        null,
};

function rulesDir(scanRoot) {
  return path.join(scanRoot, '.agentic-security', 'rules');
}

export function loadCustomRules(scanRoot) {
  const dir = rulesDir(scanRoot);
  const out = [];
  if (!fs.existsSync(dir)) return out;
  let files = [];
  try {
    files = fs.readdirSync(dir)
      .filter(f => /\.(ya?ml)$/i.test(f))
      .map(f => path.join(dir, f));
  } catch { return out; }
  for (const fp of files) {
    let raw;
    try { raw = yaml.load(fs.readFileSync(fp, 'utf8')); } catch (e) {
      console.error(`agentic-security: bad YAML in ${path.basename(fp)}: ${e.message}`);
      continue;
    }
    const list = Array.isArray(raw) ? raw : (raw?.rules ? raw.rules : [raw]);
    for (const r of list) {
      const norm = normalizeRule(r, fp);
      if (norm) out.push(norm);
    }
  }
  return out;
}

function normalizeRule(r, fp) {
  if (!r || !r.id || !r.match) return null;
  const m = r.match;
  let patterns = [];
  if (typeof m.pattern === 'string') patterns = [m.pattern];
  else if (Array.isArray(m.allOf)) patterns = m.allOf;
  else return null;

  let regexes;
  try { regexes = patterns.map(p => new RegExp(p, 'gm')); }
  catch (e) {
    console.error(`agentic-security: invalid regex in ${r.id}: ${e.message}`);
    return null;
  }
  let notMatch = null;
  if (m.notMatch) { try { notMatch = new RegExp(m.notMatch, 'm'); } catch {} }

  return {
    id: r.id,
    title: r.title || r.id,
    severity: r.severity || 'medium',
    cwe: r.cwe || '',
    message: r.message || r.title || r.id,
    remediation: r.remediation || '',
    languages: Array.isArray(r.languages) ? r.languages : (r.languages ? [r.languages] : ['any']),
    regexes,
    notMatch,
    requireAll: Array.isArray(m.allOf),
    windowLines: m.window || 50,
    sourceFile: fp,
  };
}

function fileMatchesLang(file, languages) {
  if (!languages || languages.includes('any')) return true;
  const ext = path.extname(file).toLowerCase();
  for (const lang of languages) {
    const exts = LANG_EXTS[lang];
    if (!exts) continue;
    if (exts.includes(ext)) return true;
  }
  return false;
}

// Run a rule against a (file, content) pair and return Finding[].
export function runRule(rule, file, content) {
  if (!fileMatchesLang(file, rule.languages)) return [];
  if (rule.notMatch && rule.notMatch.test(content)) return [];

  // Pre-compute line-offset table for fast line-number lookups.
  const lines = content.split('\n');
  const lineStarts = [0];
  for (let i = 0; i < lines.length; i++) lineStarts.push(lineStarts[i] + lines[i].length + 1);
  const offsetToLine = (off) => {
    let lo = 0, hi = lineStarts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (lineStarts[mid + 1] <= off) lo = mid + 1; else hi = mid;
    }
    return lo + 1;
  };

  const matches = rule.regexes.map(rx => {
    const list = [];
    rx.lastIndex = 0;
    let m; while ((m = rx.exec(content)) !== null) {
      list.push({ index: m.index, line: offsetToLine(m.index), text: m[0] });
      if (m.index === rx.lastIndex) rx.lastIndex++;
    }
    return list;
  });

  const findings = [];
  if (rule.requireAll) {
    if (matches.some(l => l.length === 0)) return [];
    // Pick the earliest match in the first list, verify the others fall within window.
    const anchor = matches[0][0];
    const close = matches.slice(1).every(list =>
      list.some(x => Math.abs(x.line - anchor.line) <= rule.windowLines)
    );
    if (!close) return [];
    findings.push(toFinding(rule, file, anchor));
  } else {
    for (const m of matches[0]) findings.push(toFinding(rule, file, m));
  }
  return findings;
}

function toFinding(rule, file, m) {
  return {
    id: `custom:${rule.id}:${file}:${m.line}`,
    title: rule.title,
    vuln: rule.title,
    severity: rule.severity,
    file,
    line: m.line,
    cwe: rule.cwe,
    description: rule.message,
    remediation: rule.remediation,
    snippet: m.text,
    confidence: 0.9,
    source: 'custom-rule',
    customRuleId: rule.id,
  };
}

// Run every loaded rule across every file. Used by the engine as a final pass.
export function applyCustomRules(scanRoot, fileContents) {
  const rules = loadCustomRules(scanRoot);
  if (!rules.length) return [];
  const out = [];
  for (const [file, content] of Object.entries(fileContents)) {
    if (!content || content.length > 500_000) continue;
    for (const r of rules) out.push(...runRule(r, file, content));
  }
  return out;
}

// `agentic-security rule test <fixture-glob>` — runs all loaded rules against
// the given fixture files and prints which rule fired on which file.
export async function runRuleTests(scanRoot, fixtureGlob) {
  const rules = loadCustomRules(scanRoot);
  if (!rules.length) {
    console.log(`No custom rules found in ${rulesDir(scanRoot)}`);
    return { ok: true, rules: 0, fired: 0 };
  }
  const files = await fg(fixtureGlob, { dot: false, onlyFiles: true });
  console.log(`Loaded ${rules.length} rule(s); testing against ${files.length} file(s).\n`);
  let fired = 0;
  for (const fp of files) {
    let content = '';
    try { content = fs.readFileSync(fp, 'utf8'); } catch { continue; }
    const expectFire = /vulnerable/i.test(fp);
    const expectClean = /clean/i.test(fp);
    for (const r of rules) {
      const findings = runRule(r, fp, content);
      if (findings.length) {
        fired++;
        const verdict = expectClean ? 'FAIL (false positive)' : 'PASS';
        console.log(`  [${verdict}] ${r.id} → ${fp}:${findings[0].line}`);
      } else if (expectFire) {
        console.log(`  [FAIL (missed)] ${r.id} → ${fp}`);
      }
    }
  }
  console.log(`\n${fired} match(es) across ${files.length} file(s).`);
  return { ok: true, rules: rules.length, fired };
}
