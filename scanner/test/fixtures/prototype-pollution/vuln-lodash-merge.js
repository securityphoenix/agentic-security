const _ = require('lodash');
const cfg = {};
function handler(req) {
  _.merge(cfg, req.body);  // Vuln: deep merge from untrusted source.
  return cfg;
}
module.exports = handler;
