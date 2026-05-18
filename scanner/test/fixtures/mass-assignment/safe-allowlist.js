// Safe: explicit allow-list before write.
const _ = require('lodash');

module.exports = async function update(req, res) {
  const allowed = _.pick(req.body, ['name', 'email']);
  const user = await User.create(allowed);
  res.json(user);
};
