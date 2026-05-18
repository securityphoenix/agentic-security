// Vuln: hand-rolled deep merge with no proto-key filter, fed by req.body.
function merge(target, src) {
  for (const k in src) {
    if (typeof src[k] === 'object' && src[k] !== null) {
      target[k] = target[k] || {};
      merge(target[k], src[k]);
    } else {
      target[k] = src[k];
    }
  }
}
module.exports = (req) => merge({}, req.body);
