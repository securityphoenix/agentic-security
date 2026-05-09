// NEGATIVE: LLM output is rendered as text only, never as HTML.
import Anthropic from '@anthropic-ai/sdk';
const anthropic = new Anthropic();

export async function renderReply() {
  const reply = await anthropic.messages.create({ model: 'claude-sonnet-4-6', max_tokens: 256, messages: [{ role: 'user', content: 'hi' }] });
  const text = reply.content[0].text;
  document.querySelector('#card').textContent = text;
}
