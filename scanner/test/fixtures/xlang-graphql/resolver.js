// Resolver for the `user` query — has a SQL injection vuln.
// We additionally include an Express route that calls the same resolver
// so the engine's source-detector (req.params) recognizes the taint and
// emits a SQL Injection finding on this file. Cross-lang then chains the
// client query → resolver → SQLi.
const express = require('express');
const app = express();

const resolvers = {
  Query: {
    user(parent, args, ctx) {
      const id = args.id;
      return db.query("SELECT * FROM users WHERE id = '" + id + "'");
    },
  },
};

app.get('/users/:id', (req, res) => {
  const id = req.params.id;
  db.query("SELECT * FROM users WHERE id = '" + id + "'", (err, row) => res.json(row));
});

module.exports = resolvers;
