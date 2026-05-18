// Safe: csurf middleware in scope.
const express = require('express');
const csurf = require('csurf');
const csrfProtection = csurf({ cookie: true });
const app = express();
app.use(csrfProtection);

app.post('/transfer', (req, res) => {
  doTransfer(req.session.user, req.body.to, req.body.amount);
  res.json({ ok: true });
});
