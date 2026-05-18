// Sanitized — taint reaches the sink call but goes through a recognized
// sanitizer first. The IR engine should NOT emit a finding here.

app.get('/search', (req, res) => {
  const id = Number(req.query.id);   // Number() sanitizes
  db.query(`SELECT * FROM items WHERE id = ${id}`);
});

app.get('/html', (req, res) => {
  const safe = escapeHtml(req.query.name);
  document.body.innerHTML = safe;
});
