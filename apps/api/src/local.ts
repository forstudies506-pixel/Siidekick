import { createServer } from "node:http";
import { makeRouter } from "./router.js";
import { createStore } from "./store.js";

const router = makeRouter({ store: createStore() });

const server = createServer(async (req, res) => {
  res.setHeader("content-type", "application/json");
  res.setHeader("cache-control", "no-store");
  try {
    let body = "";
    for await (const chunk of req) {
      body += chunk as string;
    }
    const parsed = body ? JSON.parse(body) : undefined;
    const result = await router.handle({
      method: req.method ?? "GET",
      path: req.url ?? "/",
      body: parsed,
    });
    res.writeHead(result.status, { "content-type": "application/json", "cache-control": "no-store" });
    res.end(JSON.stringify(result.body));
  } catch (err) {
    console.error(err);
    res.writeHead(500, { "content-type": "application/json", "cache-control": "no-store" });
    res.end(JSON.stringify({ error: "internal" }));
  }
});

const port = Number(process.env.PORT) || 8787;
server.listen(port, () => {
  console.log(`siidekick api listening on :${port}`);
});
