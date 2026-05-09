// NEGATIVE: pure-literal system prompt; user text is in a user-role message only.
// This is the recommended pattern and must NOT trigger.
import Anthropic from '@anthropic-ai/sdk';
const anthropic = new Anthropic();

export async function summarize(req) {
  const userText = String(req.body.text || '').slice(0, 4000);
  return anthropic.messages.create({
    model: 'claude-sonnet-4-6',
    max_tokens: 256,
    system: 'You are a summarizer. Read the user message carefully and respond concisely.',
    messages: [{ role: 'user', content: userText }],
  });
}
