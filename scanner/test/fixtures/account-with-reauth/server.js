// Sensitive route with re-auth check — should NOT fire.
const express = require('express');
const bcrypt = require('bcrypt');
const User = require('./models/user');
const app = express();

app.post('/change-email', async (req, res) => {
  const user = await User.findByPk(req.user.id);
  const valid = await bcrypt.compare(req.body.currentPassword, user.password);
  if (!valid) return res.status(403).json({ error: 'Re-auth required' });
  await user.update({ email: req.body.email });
  res.json({ ok: true });
});

module.exports = app;
