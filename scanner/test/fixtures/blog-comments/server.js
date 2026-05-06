// Blog comment system — no Order / Purchase / Cart anywhere.
// Comment.create(...) should NOT be flagged as "Without Purchase Verification".
const express = require('express');
const Comment = require('./models/comment');
const app = express();

app.post('/posts/:id/comments', async (req, res) => {
  const c = await Comment.create({ postId: req.params.id, body: req.body.text });
  res.json(c);
});

module.exports = app;
