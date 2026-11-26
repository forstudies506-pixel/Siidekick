import { describe, expect, it, afterEach } from "vitest";
import { randomBytes } from "node:crypto";
import { createStore, createUpstashStore, RecordTooLargeError, type ScanRecord } from "../src/store.js";

const URL_ = "https://example-db.upstash.io";
const TOKEN = "test-" + "token-not-real";

/** In-memory stand-in for the Upstash REST endpoint: GET and SET ... EX only. */
function fakeUpstash() {
  const data = new Map<string, string>();
  const calls: Array<{ args: Array<string | number>; auth: string | null }> = [];
  const fetchFn = (async (_url: string, init: RequestInit) => {
    const args = JSON.parse(String(init.body)) as Array<string | number>;
    const auth = new Headers(init.headers).get("authorization");
    calls.push({ args, auth });
    if (auth !== `Bearer ${TOKEN}`) return Response.json({ error: "Unauthorized" }, { status: 401 });
    if (args[0] === "GET") return Response.json({ result: data.get(String(args[1])) ?? null });
    if (args[0] === "SET") {
      data.set(String(args[1]), String(args[2]));
      return Response.json({ result: "OK" });
    }
    return Response.json({ error: "ERR unknown command" }, { status: 400 });
  }) as unknown as typeof fetch;
  return { data, calls, fetchFn };
}

const record = (content: string): ScanRecord =>
  ({
    id: "8b0c6f1e-2f1a-4c7e-9a52-0d3f6b7e1a10",
    createdAt: "2026-11-26T00:00:00.000Z",
    repo: { name: "tiny", files: [{ path: "a.js", content }] },
    report: { score: 50, results: [] },
  }) as unknown as ScanRecord;

afterEach(() => {
  delete process.env.STORAGE;
  delete process.env.UPSTASH_REDIS_REST_URL;
  delete process.env.UPSTASH_REDIS_REST_TOKEN;
});

describe("createUpstashStore", () => {
  it("round-trips a record with a 7-day expiry and the bearer token", async () => {
    const up = fakeUpstash();
    const store = createUpstashStore({ url: URL_, token: TOKEN, fetch: up.fetchFn });
    const rec = record("console.log(1);\n");
    await store.put(rec.id, rec);
    expect(await store.get(rec.id)).toEqual(rec);
    const set = up.calls.find((c) => c.args[0] === "SET")!;
    expect(set.args[1]).toBe(`siidekick:scan:${rec.id}`);
    expect(set.args.slice(3)).toEqual(["EX", 604800]);
    expect(store.kind).toBe("upstash");
  });

  it("returns null for an unknown id", async () => {
    const up = fakeUpstash();
    const store = createUpstashStore({ url: URL_, token: TOKEN, fetch: up.fetchFn });
    expect(await store.get("00000000-0000-4000-8000-000000000000")).toBeNull();
  });

  it("throws on an Upstash error without putting the token in the message", async () => {
    const up = fakeUpstash();
    const store = createUpstashStore({ url: URL_, token: "wrong-" + "token", fetch: up.fetchFn });
    const err = await store.get("00000000-0000-4000-8000-000000000000").catch((e: Error) => e);
    expect(err).toBeInstanceOf(Error);
    expect((err as Error).message).toMatch(/upstash: Unauthorized/);
    expect((err as Error).message).not.toContain("token");
  });

  it("refuses a record past the size cap before sending it", async () => {
    const up = fakeUpstash();
    const store = createUpstashStore({ url: URL_, token: TOKEN, fetch: up.fetchFn });
    const rec = record(randomBytes(4_000_000).toString("base64"));
    await expect(store.put(rec.id, rec)).rejects.toBeInstanceOf(RecordTooLargeError);
    expect(up.calls).toHaveLength(0);
  });
});

describe("createStore with STORAGE=upstash", () => {
  it("needs the URL and token", () => {
    process.env.STORAGE = "upstash";
    expect(() => createStore()).toThrow(/UPSTASH_REDIS_REST_URL/);
  });

  it("builds the Upstash store from env", () => {
    process.env.STORAGE = "upstash";
    process.env.UPSTASH_REDIS_REST_URL = URL_;
    process.env.UPSTASH_REDIS_REST_TOKEN = TOKEN;
    expect(createStore().kind).toBe("upstash");
  });
});
