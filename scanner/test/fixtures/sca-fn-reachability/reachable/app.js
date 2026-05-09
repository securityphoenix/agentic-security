// POSITIVE: vulnerable lodash.merge invoked inside a route handler.
// Expected: supplyChain.functionReachable === 'reachable'
import express from 'express';
import _ from 'lodash';

const app = express();

app.post('/profile', (req, res) => {
  const merged = _.merge({}, req.body);
  res.json(merged);
});

export default app;
