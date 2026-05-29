// Tests for ml-supply-chain.js — MLflow / ONNX / HF datasets / agent tools.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

import { scanMlSupplyChain } from '../src/sast/ml-supply-chain.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const FIX = path.join(__dirname, 'fixtures', 'ml-supply-chain');
const read = (p) => fs.readFileSync(p, 'utf8');

test('ml-supply: mlflow.load_model without pinned version flagged', () => {
  const out = scanMlSupplyChain('mlflow_pipeline.py', read(path.join(FIX, 'vulnerable/mlflow_pipeline.py')));
  assert.ok(out.some(f => f.family === 'mlflow-untrusted-uri'),
    `expected mlflow-untrusted-uri; got ${out.map(f => f.family).join(',')}`);
});

test('ml-supply: ONNX without providers flagged', () => {
  const out = scanMlSupplyChain('mlflow_pipeline.py', read(path.join(FIX, 'vulnerable/mlflow_pipeline.py')));
  assert.ok(out.some(f => f.family === 'onnx-providers'));
});

test('ml-supply: HF datasets trust_remote_code=True flagged critical', () => {
  const out = scanMlSupplyChain('mlflow_pipeline.py', read(path.join(FIX, 'vulnerable/mlflow_pipeline.py')));
  const f = out.find(x => x.family === 'hf-datasets-rce');
  assert.ok(f);
  assert.equal(f.severity, 'critical');
});

test('ml-supply: system prompt from env / URL flagged', () => {
  const out = scanMlSupplyChain('mlflow_pipeline.py', read(path.join(FIX, 'vulnerable/mlflow_pipeline.py')));
  const fams = out.filter(f => f.family === 'prompt-integrity').length;
  assert.ok(fams >= 2, `expected ≥2 prompt-integrity findings, got ${fams}`);
});

// Agent tool exposing os.system / subprocess is detected by
// sast/llm-app.js detectToolExec — not duplicated in ml-supply-chain.

test('ml-supply: gradio share=True without auth flagged high', () => {
  const out = scanMlSupplyChain('mlflow_pipeline.py', read(path.join(FIX, 'vulnerable/mlflow_pipeline.py')));
  const f = out.find(x => x.family === 'gradio-auth');
  assert.ok(f);
  assert.equal(f.severity, 'high');
});

test('ml-supply: custom HF Hub endpoint flagged', () => {
  const out = scanMlSupplyChain('mlflow_pipeline.py', read(path.join(FIX, 'vulnerable/mlflow_pipeline.py')));
  assert.ok(out.some(f => f.family === 'hf-endpoint-override'));
});

test('ml-supply: .pt format loading nudges to safetensors', () => {
  const out = scanMlSupplyChain('mlflow_pipeline.py', read(path.join(FIX, 'vulnerable/mlflow_pipeline.py')));
  assert.ok(out.some(f => f.family === 'model-format'));
});

test('ml-supply: clean fixture is silent on all critical/high gates', () => {
  const out = scanMlSupplyChain('safe_pipeline.py', read(path.join(FIX, 'clean/safe_pipeline.py')));
  const critical = out.filter(f => f.severity === 'critical' || f.severity === 'high');
  assert.equal(critical.length, 0, `unexpected critical/high on clean: ${critical.map(f => f.family).join(',')}`);
});

test('ml-supply: non-ML file is silent', () => {
  const out = scanMlSupplyChain('regular.py', 'def add(a, b):\n    return a + b\n');
  assert.equal(out.length, 0);
});

test('ml-supply: non-Python file is silent', () => {
  const out = scanMlSupplyChain('app.js', 'import mlflow from "mlflow";\nmlflow.load_model("x");\n');
  assert.equal(out.length, 0);
});

test('ml-supply: NO_ML_SUPPLY disables', () => {
  process.env.AGENTIC_SECURITY_NO_ML_SUPPLY = '1';
  try {
    const out = scanMlSupplyChain('mlflow_pipeline.py', read(path.join(FIX, 'vulnerable/mlflow_pipeline.py')));
    assert.equal(out.length, 0);
  } finally { delete process.env.AGENTIC_SECURITY_NO_ML_SUPPLY; }
});

test('ml-supply: test/ path is suppressed (non-prod heuristic)', () => {
  const out = scanMlSupplyChain('tests/test_model.py', 'import mlflow\nmlflow.pyfunc.load_model("path")\n');
  assert.equal(out.length, 0);
});
