// NEGATIVE: LangChain chain.invoke called with literal data; no taint.
import { ChatPromptTemplate } from '@langchain/core/prompts';
import { ChatAnthropic } from '@langchain/anthropic';

const prompt = ChatPromptTemplate.fromTemplate('Tell me a joke about {topic}.');
const model = new ChatAnthropic({});
const chain = prompt.pipe(model);

export async function joke() {
  return chain.invoke({ topic: 'cats' });
}
