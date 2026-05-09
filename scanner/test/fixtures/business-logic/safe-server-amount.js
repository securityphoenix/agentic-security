// NEGATIVE: amount is recomputed on the server from authoritative records.
export async function checkout(req, res) {
  const cart = await db.carts.findById(req.user.cartId);
  const amount = cart.items.reduce((sum, it) => sum + it.unitPriceCents * it.qty, 0);
  await db.orders.insert({ userId: req.user.id, amount });
  res.json({ amount });
}
