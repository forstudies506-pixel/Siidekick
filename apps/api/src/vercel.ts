import type { IncomingMessage, ServerResponse } from "node:http";
import { makeRouter } from "./router.js";
import { createStore, redisUrl, upstashEnv } from "./store.js";

// With Upstash or Redis configured, records outlive the function instance. Without either, a Vercel
// function may only write to /tmp, and records live as long as the instance does.
if (!process.env.STORAGE && upstashEnv()) process.env.STORAGE = "upstash";
if (!process.env.STORAGE && redisUrl()) process.env.STORAGE = "redis";
process.env.DATA_DIR ??= "/tmp/siidekick";

const router = makeRouter({ store: createStore() });

/** Node handler for a Vercel function. Same contract as local.ts; scripts/deploy-vercel.sh bundles it. */
export default async function handler(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const send = (status: number, body: unknown) => {
    res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
    res.end(JSON.stringify(body));
  };
  try {
    let raw = "";
    for await (const chunk of req) raw += chunk as string;
    let body: unknown;
    try {
      body = raw ? JSON.parse(raw) : undefined;
    } catch {
      return send(400, { error: "the request body is not valid JSON" });
    }
    const path = new URL(req.url ?? "/", "http://x").pathname;
    const result = await router.handle({ method: req.method ?? "GET", path, body });
    send(result.status, result.body);
  } catch (err) {
    console.error(err);
    send(500, { error: "internal" });
  }
}
