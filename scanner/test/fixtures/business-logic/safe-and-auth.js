// NEGATIVE: AND — both sides must be true. Recommended pattern.
export function gateAdmin(req, res, next) {
  if (req.user.isAdmin && req.user.mfaVerified) {
    return next();
  }
  return res.status(403).end();
}
