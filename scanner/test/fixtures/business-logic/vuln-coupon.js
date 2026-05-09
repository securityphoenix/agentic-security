// POSITIVE: discount taken straight from the body without server lookup.
export async function applyDiscount(req, res) {
  const total = req.body.subtotal - req.body.discount;
  await db.orders.update({ id: req.body.orderId }, { total });
  res.json({ total });
}
