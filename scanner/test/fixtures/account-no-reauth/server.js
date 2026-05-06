// Sensitive route WITHOUT re-auth check — should fire.
const express = require('express');
const User = require('./models/user');
const app = express();

app.post('/change-email', async (req, res) => {
  await User.update({ email: req.body.email }, { where: { id: req.user.id } });
  res.json({ ok: true });
});

module.exports = app;
