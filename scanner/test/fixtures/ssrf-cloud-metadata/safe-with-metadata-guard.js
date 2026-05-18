const axios = require('axios');
const dns = require('dns').promises;

async function proxyFetch(req, res) {
  const target = new URL(req.query.url);
  const { address } = await dns.lookup(target.hostname);
  // Safe: explicit deny-list of cloud metadata + private ranges.
  if (address === '169.254.169.254' || /^(?:10|127|172\.16|192\.168)/.test(address)
      || /metadata\.google\.internal|metadata\.azure\.com/.test(target.hostname)) {
    return res.status(403).end();
  }
  const r = await axios.get(req.query.url);
  res.send(r.data);
}
module.exports = proxyFetch;
