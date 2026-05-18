// Vuln: Mongoose create() takes the entire request body — client can set is_admin.
const User = require('./user-model');

module.exports = async function register(req, res) {
  const u = await User.create(req.body);
  res.json(u);
};
