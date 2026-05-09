// NEGATIVE: vulnerable lodash.merge present, but lives in a helper that no route invokes.
// Expected: supplyChain.functionReachable === 'unreachable'
import express from 'express';
import _ from 'lodash';

const app = express();

function unusedHelper(input) {
  return _.merge({}, input);
}

app.get('/health', (_req, res) => res.json({ ok: true }));

export default app;
export { unusedHelper };
