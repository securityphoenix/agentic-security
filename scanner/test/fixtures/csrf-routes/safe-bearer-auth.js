// Safe: Authorization: Bearer token auth — CSRF doesn't apply.
const express = require('express');
const app = express();

app.post('/api/transfer', (req, res) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).end();
  doTransfer(verifyJWT(auth.slice(7)), req.body.to, req.body.amount);
  res.json({ ok: true });
});
