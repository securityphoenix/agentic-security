// No options object at all — should fire 1 finding.
const express = require('express');
const app = express();

app.post('/login', (req, res) => {
  res.cookie('token', 'value');
  res.send('ok');
});
