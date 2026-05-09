// 0.9.0 Feat-14: Container layer scan — F1 over labelled Dockerfile fixtures.
import { test } from 'node:test';
import { evaluateF1 } from './helpers/f1.js';

const LABELS = [
  { file: 'vuln-debian9.dockerfile',   positive: true,  matcher: /Container base image.*EOL/i },
  { file: 'vuln-node12.dockerfile',    positive: true,  matcher: /Container base image.*EOL/i },
  { file: 'vuln-python27.dockerfile',  positive: true,  matcher: /Container base image.*EOL/i },
  { file: 'vuln-floating.dockerfile',  positive: true,  matcher: /Container base image.*floating/i },
  { file: 'safe-modern.dockerfile',    positive: false, matcher: /Container base image/i },
  { file: 'safe-pinned.dockerfile',    positive: false, matcher: /Container base image/i },
];

test('Container scan — F1 evaluation', async () => {
  await evaluateF1({
    name: 'Container-detector',
    fixtureDir: 'container',
    labels: LABELS,
    floors: { f1: 0.85, precision: 0.83, recall: 0.83 },
  });
});
