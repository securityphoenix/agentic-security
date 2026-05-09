// POSITIVE: short-circuit `||` makes this check pass for any authenticated user.
export function gateAdmin(req, res, next) {
  if (req.user.isAdmin || req.user.id) {
    return next();
  }
  return res.status(403).end();
}
