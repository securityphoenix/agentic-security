// POSITIVE: HTTP user input flows directly into Anthropic system prompt.
import Anthropic from '@anthropic-ai/sdk';
const anthropic = new Anthropic();

export async function summarize(req, res) {
  const userText = req.body.text;
  const reply = await anthropic.messages.create({
    model: 'claude-sonnet-4-6',
    max_tokens: 256,
    system: `You are a summarizer. Summarize: ${userText}`,
    messages: [{ role: 'user', content: 'Go.' }],
  });
  res.json({ reply });
}
