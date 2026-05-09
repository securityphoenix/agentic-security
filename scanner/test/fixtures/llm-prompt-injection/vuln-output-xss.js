// POSITIVE: LLM output rendered as HTML without sanitization.
import Anthropic from '@anthropic-ai/sdk';
const anthropic = new Anthropic();

export async function renderReply(req) {
  const reply = await anthropic.messages.create({
    model: 'claude-sonnet-4-6',
    max_tokens: 256,
    messages: [{ role: 'user', content: 'Make me a card' }],
  });
  const html = reply.content[0].text;
  document.querySelector('#card').innerHTML = html;
}
