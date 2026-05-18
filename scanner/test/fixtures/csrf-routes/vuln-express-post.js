// Vuln: POST/PUT/DELETE without CSRF middleware, no token check, cookie auth.
const express = require('express');
const session = require('express-session');
const app = express();
app.use(session({ secret: 'x', cookie: { sameSite: false } }));

app.post('/transfer', (req, res) => {
  // No csurf, no token, cookie-authed.
  doTransfer(req.session.user, req.body.to, req.body.amount);
  res.json({ ok: true });
});

app.delete('/account', (req, res) => {
  deleteAccount(req.session.user);
  res.json({ ok: true });
});
