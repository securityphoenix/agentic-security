// E-commerce app — Order model exists.
// Review.create without purchase check SHOULD fire "Without Purchase Verification".
const express = require('express');
const Order = require('./models/order');
const Review = require('./models/review');
const app = express();

app.post('/products/:id/review', async (req, res) => {
  // No Order lookup — direct review creation
  const r = await Review.create({ productId: req.params.id, rating: req.body.rating });
  res.json(r);
});

module.exports = app;
