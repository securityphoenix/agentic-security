// NEGATIVE: explicit allowlist; isAdmin can't be set from the request body.
const MUTABLE = ['name', 'email', 'avatarUrl'];

export async function updateUser(req, res) {
  const patch = {};
  for (const k of MUTABLE) if (k in req.body) patch[k] = req.body[k];
  await db.users.update({ id: req.params.id }, patch);
  res.json({ ok: true });
}
