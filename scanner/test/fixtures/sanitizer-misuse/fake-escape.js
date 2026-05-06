// Custom function whose name suggests escaping but body doesn't actually escape.
// inferSanitizers should not promote this to a sanitizer.
const express = require('express');
const app = express();

function escapeError(e) {
  // Fake escape — just rethrows. NOT a real sanitizer.
  throw e;
}

app.get('/echo', (req, res) => {
  const s = req.query.input;
  const safe = escapeError(s);  // would never run safely; even if it did, no escaping
  res.send(safe);
});

module.exports = app;
