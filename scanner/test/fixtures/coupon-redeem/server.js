// Coupon mutation path — should fire.
const express = require('express');
const Coupon = require('./models/coupon');
const app = express();

app.post('/coupons/:code/redeem', async (req, res) => {
  const coupon = await Coupon.findOne({ code: req.params.code });
  await coupon.update({ used: true, redeemedBy: req.user.id });
  res.json({ ok: true });
});

module.exports = app;
