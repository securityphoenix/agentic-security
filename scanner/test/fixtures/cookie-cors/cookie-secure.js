// All three flags set — should NOT fire.
const express = require('express');
const app = express();

app.post('/login', (req, res) => {
  res.cookie('token', 'value', { httpOnly: true, secure: true, sameSite: 'strict' });
  res.send('ok');
});
