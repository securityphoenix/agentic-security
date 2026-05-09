// POSITIVE: privilege field set directly from request body.
export async function updateUser(req, res) {
  await db.users.update({ id: req.params.id }, {
    name: req.body.name,
    isAdmin: req.body.isAdmin,
  });
  res.json({ ok: true });
}
