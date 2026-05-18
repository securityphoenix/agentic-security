// Safe: Object.assign with a fresh target, no proto-walk possible because target
// has no prototype linkage to the dangerous keys.
function handler(req) {
  return Object.assign(Object.create(null), { name: req.body.name });
}
module.exports = handler;
