// Server-side handler. Has a SQL injection vuln — the cross-lang detector
// should propagate this to any client call hitting /users/:id.
const express = require('express');
const app = express();

app.get('/users/:id', (req, res) => {
  const id = req.params.id;
  db.query("SELECT * FROM users WHERE id = '" + id + "'", (err, row) => {
    res.json(row);
  });
});
