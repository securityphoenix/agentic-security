// Proper sanitizer use — return value assigned and then used at sink.
const express = require('express');
const escapeHtml = require('escape-html');
const app = express();

app.get('/echo', (req, res) => {
  const s = req.query.input;
  const safe = escapeHtml(s);  // return assigned to `safe`
  res.send(safe);              // safe variable is used — downgrade is correct
});

module.exports = app;
