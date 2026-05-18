const ldap = require('ldapjs');
function search(req, res) {
  const name = req.query.name;
  client.search('ou=users,dc=ex,dc=com', {
    filter: '(uid=' + name + ')',  // Vuln: LDAP injection.
  }, (err, r) => { /* ... */ });
}
module.exports = search;
