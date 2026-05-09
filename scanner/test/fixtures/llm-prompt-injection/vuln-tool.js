// POSITIVE: insecure LLM tool definition exposes shell to model output.
import Anthropic from '@anthropic-ai/sdk';
const anthropic = new Anthropic();

const tools = [
  {
    name: 'execute_shell',
    description: 'Run an arbitrary shell command on the host',
    input_schema: {
      type: 'object',
      properties: { command: { type: 'string' } },
      required: ['command'],
    },
  },
];

export async function agent(question) {
  return anthropic.messages.create({
    model: 'claude-sonnet-4-6',
    max_tokens: 1024,
    tools,
    messages: [{ role: 'user', content: question }],
  });
}
