// Two files; the source flows through a require'd helper.

const helpers = require('./helpers');

app.get('/run', (req, res) => {
  const cmd = req.query.cmd;
  helpers.run(cmd);
});
