// Dead branch — path-feasibility should prune the consequent, so no finding.
// The pattern scanner doesn't know the if is dead; the IR engine does.

const DEBUG = false;

app.post('/data', (req, res) => {
  if (false) {
    eval(req.body.expr);  // unreachable
  }
  res.send('ok');
});

app.post('/maybe', (req, res) => {
  if (DEBUG) {
    eval(req.body.expr);  // also unreachable since DEBUG is a literal false
                          // (we don't track this yet — leave it for a future
                          //  constant-folding upgrade)
  }
  res.send('ok');
});
