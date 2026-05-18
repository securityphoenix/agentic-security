const User = require('./user-model');
async function login(req, res) {
  const u = await User.findOne(req.body);  // Vuln: NoSQL operator injection.
  res.json(u);
}
module.exports = login;
