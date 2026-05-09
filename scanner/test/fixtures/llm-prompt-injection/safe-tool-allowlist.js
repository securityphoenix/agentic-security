// NEGATIVE: tool with safe, scoped name. No dangerous capability exposed.
import Anthropic from '@anthropic-ai/sdk';
const anthropic = new Anthropic();

const tools = [
  {
    name: 'lookup_order_status',
    description: 'Look up an order in our system by ID',
    input_schema: {
      type: 'object',
      properties: { orderId: { type: 'string', pattern: '^ord_[a-z0-9]+$' } },
      required: ['orderId'],
    },
  },
];

export async function agent(question) {
  return anthropic.messages.create({ model: 'claude-sonnet-4-6', max_tokens: 1024, tools, messages: [{ role: 'user', content: question }] });
}
