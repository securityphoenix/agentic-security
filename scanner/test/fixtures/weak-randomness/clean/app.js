const crypto = require('crypto');
const safeValue = crypto.randomBytes(32).toString('hex');

const dice = Math.random();
const color = Math.random() > 0.5 ? 'red' : 'blue';
const delay = Math.floor(Math.random() * 1000);
