// POSITIVE: indirect prompt injection — fetched URL contents flow into LLM call.
import Anthropic from '@anthropic-ai/sdk';
const anthropic = new Anthropic();

export async function analyzeDoc(url) {
  const docText = await fetch(url).then(r => r.text());
  return anthropic.messages.create({
    model: 'claude-sonnet-4-6',
    max_tokens: 256,
    system: `You are a doc analyzer. The doc to analyze is below. ${docText}`,
    messages: [{ role: 'user', content: 'Analyze.' }],
  });
}
