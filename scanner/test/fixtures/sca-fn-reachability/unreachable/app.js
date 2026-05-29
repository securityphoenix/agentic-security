// NEGATIVE: vulnerable function present, but lives in an unused helper
// (not invoked, not exported — truly module-internal).
// Expected: supplyChain.functionReachable === 'unreachable'
import express from 'express';
import _ from 'lodash';

const app = express();

app.get('/health', (_req, res) => res.json({ ok: true }));

function unusedHelper(input) {
  return _.merge({}, input);
}

export default app;
