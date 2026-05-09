// 0.9.0 Feat-18: OSSF Scorecard enrichment — opt-in test.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { _enrichWithScorecard } from '../src/engine.js';

test('Scorecard — opt-out by default (no flag → no enrichment)', async () => {
  delete process.env.AGENTIC_SECURITY_SCORECARD;
  const c = [{ ecosystem: 'npm', name: 'express', version: '4.18.0' }];
  await _enrichWithScorecard(c);
  assert.equal(c[0].scorecardScore, undefined);
});

test('Scorecard — opt-in but offline → no outbound, no scorecard', async () => {
  process.env.AGENTIC_SECURITY_SCORECARD = '1';
  process.env.AGENTIC_SECURITY_OFFLINE = '1';
  try {
    const c = [{ ecosystem: 'npm', name: 'express', version: '4.18.0', homepage: 'https://github.com/expressjs/express' }];
    await _enrichWithScorecard(c);
    assert.equal(c[0].scorecardScore, undefined);
  } finally {
    delete process.env.AGENTIC_SECURITY_SCORECARD;
    delete process.env.AGENTIC_SECURITY_OFFLINE;
  }
});
