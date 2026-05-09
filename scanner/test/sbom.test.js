// 0.7.0 Feat-6: SBOM (CycloneDX 1.6 + SPDX 2.3) smoke + shape tests.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../src/runScan.js';
import { toCycloneDX, toSPDX } from '../src/posture/sbom.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIX = (n) => path.join(__dirname, 'fixtures', n);

test('SBOM — CycloneDX 1.6 has correct top-level fields', async () => {
  const { scan, meta } = await runScan(FIX('vulnerable-js'));
  const cdx = toCycloneDX(scan, meta);
  assert.equal(cdx.bomFormat, 'CycloneDX');
  assert.equal(cdx.specVersion, '1.6');
  assert.match(cdx.serialNumber, /^urn:uuid:/);
  assert.equal(cdx.metadata.tools[0].name, 'agentic-security');
  assert.ok(Array.isArray(cdx.components), 'components is array');
  // Every component has required fields
  for (const c of cdx.components) {
    assert.ok(c.type === 'library', 'type is library');
    assert.ok(c.name && c.version && c.purl, `missing fields on ${JSON.stringify(c)}`);
    assert.ok(c['bom-ref'], 'bom-ref required');
    assert.match(c.purl, /^pkg:/);
  }
  // If supplyChain has CVEs, CycloneDX should expose them as `vulnerabilities[]`
  if ((scan.supplyChain || []).some(s => s.type === 'vulnerable_dep')) {
    assert.ok(Array.isArray(cdx.vulnerabilities) && cdx.vulnerabilities.length > 0,
      'expected vulnerabilities[] when CVEs are present');
    const v = cdx.vulnerabilities[0];
    assert.ok(v.id, 'vuln id required');
    assert.ok(Array.isArray(v.affects), 'affects[] required');
  }
});

test('SBOM — SPDX 2.3 has correct top-level fields', async () => {
  const { scan, meta } = await runScan(FIX('vulnerable-js'));
  const spdx = toSPDX(scan, meta);
  assert.equal(spdx.spdxVersion, 'SPDX-2.3');
  assert.equal(spdx.dataLicense, 'CC0-1.0');
  assert.equal(spdx.SPDXID, 'SPDXRef-DOCUMENT');
  assert.match(spdx.documentNamespace, /^https?:\/\//);
  assert.ok(Array.isArray(spdx.packages), 'packages is array');
  for (const p of spdx.packages) {
    assert.match(p.SPDXID, /^SPDXRef-Package-\d+$/);
    assert.ok(p.name && p.versionInfo, 'name + versionInfo required');
    assert.ok(p.externalRefs.some(r => r.referenceType === 'purl'), 'purl externalRef required');
  }
  // Relationships must reference DOCUMENT and each package
  assert.equal(spdx.relationships.length, spdx.packages.length);
});
