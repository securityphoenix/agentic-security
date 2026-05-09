// POSITIVE: order.status set to 'paid' with no prior-state guard.
export async function markPaid(req, res) {
  const order = await db.orders.findById(req.params.id);
  order.status = 'paid';
  await order.save();
  res.json(order);
}
