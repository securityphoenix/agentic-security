// Business-logic detector — F1-scored fixture evaluation.
import { test } from 'node:test';
import { evaluateF1 } from './helpers/f1.js';

const LABELS = [
  { file: 'vuln-or-auth.js',         positive: true,  matcher: /Always-True Authorization/i },
  { file: 'vuln-client-amount.js',   positive: true,  matcher: /Client-Controlled Monetary/i },
  { file: 'vuln-priv-mass-assign.js',positive: true,  matcher: /Privilege Field Set from Request Body/i },
  { file: 'vuln-toctou.js',          positive: true,  matcher: /TOCTOU/i },
  { file: 'vuln-state.js',           positive: true,  matcher: /Terminal State Set Without Prior-State Guard/i },
  { file: 'vuln-coupon.js',          positive: true,  matcher: /Client-Controlled Discount/i },
  { file: 'safe-and-auth.js',        positive: false, matcher: /Always-True Authorization/i },
  { file: 'safe-server-amount.js',   positive: false, matcher: /Client-Controlled Monetary|Discount/i },
  { file: 'safe-allowlist-update.js',positive: false, matcher: /Privilege Field Set from Request Body/i },
  { file: 'safe-state-guarded.js',   positive: false, matcher: /Terminal State Set Without Prior-State Guard/i },
  { file: 'decoy-or-noisy.js',       positive: false, matcher: /Always-True Authorization/i },
];

test('Business-logic detector — F1 evaluation across positives and negatives', async () => {
  await evaluateF1({
    name: 'Logic-detector',
    fixtureDir: 'business-logic',
    labels: LABELS,
    floors: { f1: 0.9, precision: 0.85, recall: 0.85 },
  });
});
