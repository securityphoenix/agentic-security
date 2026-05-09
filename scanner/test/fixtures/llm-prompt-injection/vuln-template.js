// POSITIVE: template-literal http taint inside the LLM call (no intermediate var).
import OpenAI from 'openai';
const openai = new OpenAI();

export async function classify(req) {
  return openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [
      { role: 'system', content: `Classify the following: ${req.body.userInput}` },
    ],
  });
}
