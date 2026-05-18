const axios = require('axios');
async function proxyFetch(req, res) {
  // Vuln: user-controlled URL into HTTP client, no metadata guard.
  const r = await axios.get(req.query.url);
  res.send(r.data);
}
module.exports = proxyFetch;
