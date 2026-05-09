// NEGATIVE: terminal state transition is gated by a prior-state check.
export async function markPaid(req, res) {
  const order = await db.orders.findById(req.params.id);
  if (order.status !== 'pending') {
    return res.status(409).json({ error: 'order not pending' });
  }
  order.status = 'paid';
  await order.save();
  res.json(order);
}
