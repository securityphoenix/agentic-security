const { stringify } = require('csv-stringify');
function exportUsers(req, res) {
  csvStringify([{ name: req.body.name, email: req.body.email, columns: true }]);
}
