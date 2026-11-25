// Shopping assistant widget, as an AI assistant first wrote it. Demo flaw: never ship this.
import OpenAI from "openai";

const client = new OpenAI({
  apiKey: import.meta.env.VITE_OPENAI_API_KEY,
  dangerouslyAllowBrowser: true,
});

export async function ask(question) {
  const reply = await client.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: question }],
  });
  return reply.choices[0].message.content;
}
