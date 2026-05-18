// Vuln: Object.assign on a user object with the entire request body.
const express = require('express');
const app = express();

app.post('/profile', (req, res) => {
  const user = getCurrentUser();
  Object.assign(user, req.body);
  user.save();
  res.json(user);
});
