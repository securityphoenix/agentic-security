// Server impl — has a SQL injection vuln. We use req.body so the engine's
// pattern scanner picks up the taint flow; in a real gRPC server the source
// would be call.request.id (a gRPC-specific source not yet in our catalog).
const grpc = require('@grpc/grpc-js');
const express = require('express');
const app = express();

app.get('/users/:id', (req, res) => {
  const id = req.params.id;
  // Vuln: SQL Injection (db.query) — flagged at high.
  db.query("SELECT * FROM users WHERE id = '" + id + "'", (err, row) => {
    res.json(row);
  });
});

function getUser(call, callback) {
  const id = call.request.id;
  // Same vuln via the gRPC handler.
  db.query("SELECT * FROM users WHERE id = '" + id + "'", (err, row) => callback(null, row));
}

const server = new grpc.Server();
server.addService(UserService.service, { getUser });
