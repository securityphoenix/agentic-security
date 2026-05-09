// POSITIVE: client controls the amount stored in the DB.
export async function checkout(req, res) {
  const order = {
    userId: req.user.id,
    amount: req.body.amount,
    currency: 'USD',
  };
  await db.orders.insert(order);
  res.json(order);
}
