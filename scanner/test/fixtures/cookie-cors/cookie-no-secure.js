// Missing `secure` flag — should fire 1 finding.
const express = require('express');
const app = express();

app.post('/login', (req, res) => {
  res.cookie('token', 'value', { httpOnly: true, sameSite: 'strict' });
  res.send('ok');
});
