// LLM / prompt-injection detector — F1-scored fixture evaluation.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../src/runScan.js';
import { normalizeFindings } from '../src/report/index.js';
import { evaluateF1 } from './helpers/f1.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (name) => path.join(__dirname, 'fixtures', name);

const LABELS = [
  { file: 'vuln-direct.js',              positive: true,  matcher: /Prompt Injection.*HTTP user input/i },
  { file: 'vuln-template.js',            positive: true,  matcher: /Prompt Injection/i },
  { file: 'vuln-indirect.js',            positive: true,  matcher: /Indirect Prompt Injection|Prompt Injection/i },
  { file: 'vuln-tool.js',                positive: true,  matcher: /Insecure LLM Tool Definition/i },
  { file: 'vuln-output-xss.js',          positive: true,  matcher: /Unsanitized LLM Output/i },
  { file: 'vuln-py.py',                  positive: true,  matcher: /Prompt Injection/i },
  { file: 'safe-static-prompt.js',       positive: false, matcher: /Prompt Injection|LLM/i },
  { file: 'safe-tool-allowlist.js',      positive: false, matcher: /Insecure LLM Tool/i },
  { file: 'safe-static-rendering.js',    positive: false, matcher: /Unsanitized LLM Output/i },
  { file: 'decoy-no-llm.js',             positive: false, matcher: /Prompt Injection|LLM/i },
  { file: 'decoy-langchain-noinput.js',  positive: false, matcher: /Prompt Injection/i },
];

test('LLM detector — F1 evaluation across positives and negatives', async () => {
  await evaluateF1({
    name: 'LLM-detector',
    fixtureDir: 'llm-prompt-injection',
    labels: LABELS,
    floors: { f1: 0.9, precision: 0.85, recall: 0.85 },
  });
});

test('LLM detector — vuln-direct.js fires HTTP-user-input PI with chain', async () => {
  const { scan } = await runScan(FIX('llm-prompt-injection'));
  const findings = normalizeFindings(scan);
  const f = findings.find(x => x.file.endsWith('vuln-direct.js') && /Prompt Injection/.test(x.vuln));
  assert.ok(f, 'expected a PI finding on vuln-direct.js');
  assert.equal(f.severity, 'high');
  assert.ok(Array.isArray(f.chain), 'finding should carry chain[]');
});

test('LLM detector — decoy-no-llm.js produces zero LLM findings', async () => {
  const { scan } = await runScan(FIX('llm-prompt-injection'));
  const f = normalizeFindings(scan).filter(x => x.file.endsWith('decoy-no-llm.js') && /(Prompt Injection|LLM)/.test(x.vuln));
  assert.equal(f.length, 0, `decoy must be silent; got: ${f.map(x => x.vuln).join(', ')}`);
});
