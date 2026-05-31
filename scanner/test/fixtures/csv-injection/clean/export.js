const { stringify } = require('csv-stringify');
function exportUsers(req, res) {
  const safe = escapeFormula(req.body.name);
  csvStringify([{ name: safe, columns: true }]);
}
