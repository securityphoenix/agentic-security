const crypto = require('crypto');
const tls = require('tls');
const jwt = require('jsonwebtoken');

const ctx = tls.createSecureContext({ minVersion: 'TLSv1.3' });

function verify(token, key) {
  return jwt.verify(token, key, { algorithms: ['RS256'] });
}

function makeSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

function hashPassword(pw, salt) {
  return crypto.pbkdf2Sync(pw, salt, 600000, 32, 'sha256');
}
