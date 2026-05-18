const ldap = require('ldapjs');
function search(req, res) {
  const name = req.query.name;
  // Safe: typed filter, never concatenated.
  client.search('ou=users,dc=ex,dc=com', {
    filter: new ldap.EqualityFilter({ attribute: 'uid', value: name }),
  }, (err, r) => { /* ... */ });
}
module.exports = search;
