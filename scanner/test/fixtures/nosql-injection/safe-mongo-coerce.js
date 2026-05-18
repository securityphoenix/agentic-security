const User = require('./user-model');
async function login(req, res) {
  const u = await User.findOne({
    email: String(req.body.email),
    passwordHash: hashPassword(String(req.body.password)),
  });
  res.json(u);
}
module.exports = login;
