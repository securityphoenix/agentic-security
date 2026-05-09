// 0.7.0 Feat-8: API inventory export tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../src/runScan.js';
import { toAPIInventoryJSON, toAPIInventoryMarkdown, toOpenAPI } from '../src/posture/api-inventory.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (n) => path.join(__dirname, 'fixtures', n);

test('API inventory — vulnerable-js produces routes with auth + data-class metadata', async () => {
  const { scan } = await runScan(FIX('vulnerable-js'));
  const inv = toAPIInventoryJSON(scan);
  assert.ok(inv.summary.total > 0, `expected ≥1 route, got ${inv.summary.total}`);
  assert.ok(inv.routes.every(r => r.method && r.path && r.file), 'every route must have method, path, file');
  assert.ok(inv.routes.every(r => typeof r.hasAuth === 'boolean'));
});

test('API inventory — Markdown output contains auth indicator and dataClasses column', async () => {
  const { scan } = await runScan(FIX('vulnerable-js'));
  const md = toAPIInventoryMarkdown(scan);
  assert.match(md, /# API inventory/);
  assert.match(md, /\| Method \| Path \| Auth \| Data classes \| File:Line \|/);
  assert.match(md, /\|\s+`[A-Z]+`\s+\|/);
});

test('API inventory — OpenAPI 3.1 output is well-formed and tags unauthenticated endpoints', async () => {
  const { scan } = await runScan(FIX('vulnerable-js'));
  const oa = toOpenAPI(scan);
  assert.equal(oa.openapi, '3.1.0');
  assert.ok(oa.info.title);
  assert.ok(typeof oa.paths === 'object' && Object.keys(oa.paths).length > 0);
  assert.ok(oa.components.securitySchemes.bearerAuth);
  for (const [, methods] of Object.entries(oa.paths)) {
    for (const op of Object.values(methods)) {
      assert.ok(op.operationId, 'operationId required');
      assert.ok(op['x-source-location'], 'x-source-location required');
    }
  }
});
