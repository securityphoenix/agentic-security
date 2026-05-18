// Interprocedural taint — the dangerous flow is:
//
//   route handler  →  helper(req.query.q)  →  return value  →  db.query
//
// The pattern scanner can't follow this. The IR engine should.
//
// (We don't fully implement summary-based propagation across functions yet,
// but we do detect the source/sink within each function. To exercise the
// cross-function story, the helper takes a tainted arg and the route writes
// the result into a sink in the SAME function.)

function buildQuery(input) {
  return "SELECT * FROM items WHERE name = '" + input + "'";
}

app.get('/search', (req, res) => {
  const q = req.query.q;       // source
  const sql = buildQuery(q);   // through a helper — caller summary
  db.query(sql);                // sink
});
