// Sanitizer is called but its return value is discarded — vulnerability remains.
const express = require('express');
const escapeHtml = require('escape-html');
const app = express();

app.get('/echo', (req, res) => {
  const s = req.query.input;
  escapeHtml(s);          // RETURN VALUE DISCARDED — does nothing for `s`
  res.send(s);            // Still tainted — should NOT be downgraded
});

module.exports = app;
