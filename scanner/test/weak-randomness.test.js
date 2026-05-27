import { test } from 'node:test';
import { evaluateF1 } from './helpers/f1.js';

test('Weak randomness detector: vulnerable fixtures fire, clean fixtures are silent', async () => {
  await evaluateF1({
    name: 'weak-randomness',
    fixtureDir: 'weak-randomness',
    labels: [
      { file: 'vulnerable/app.js', positive: true, matcher: /Insecure Randomness.*Math\.random/i },
      { file: 'vulnerable/app.py', positive: true, matcher: /Insecure Randomness.*random/i },
      { file: 'vulnerable/app.go', positive: true, matcher: /Insecure Randomness.*rand/i },
      { file: 'clean/app.js',      positive: false, matcher: /Insecure Randomness/i },
      { file: 'clean/app.py',      positive: false, matcher: /Insecure Randomness/i },
    ],
    floors: { precision: 0.85, recall: 0.85, f1: 0.85 },
  });
});
