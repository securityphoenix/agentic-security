// NEGATIVE: `||` used here is a normal default-value pattern, not auth.
// Must NOT trigger ALWAYS_TRUE_AUTH.
export function pickName(req) {
  const display = req.body.name || req.user.email || 'Anonymous';
  return display;
}
