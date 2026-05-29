const https = require('https');
const tls = require('tls');

// BUG: rejectUnauthorized: false disables TLS cert verification.
const insecureAgent = new https.Agent({ rejectUnauthorized: false });

// BUG: minVersion is TLS 1.0.
const oldTlsCtx = tls.createSecureContext({ minVersion: 'TLSv1' });

// BUG: jwt.verify without algorithms allowlist.
const jwt = require('jsonwebtoken');
function verify(token, key) {
  return jwt.verify(token, key);
}

// BUG: Math.random for session token.
function makeSessionToken() {
  return Math.random().toString(36).substring(2);
}
