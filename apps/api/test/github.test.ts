import { describe, expect, it } from "vitest";
import { gzipSync } from "node:zlib";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseGithubUrl, fetchGithubRepo, GithubError } from "../src/github.js";
import { makeRouter } from "../src/router.js";
import { createStore } from "../src/store.js";

interface Entry {
  name: string;
  content: string | Buffer;
  typeflag?: string;
  prefix?: string;
}

function tarHeader(name: string, size: number, typeflag: string, prefix: string): Buffer {
  const header = Buffer.alloc(512);
  const put = (off: number, str: string, len: number) => header.write(str, off, len, "utf8");
  put(0, name, 100);
  put(100, "0000644\0", 8);
  put(108, "0000000\0", 8);
  put(116, "0000000\0", 8);
  put(124, size.toString(8).padStart(11, "0") + "\0", 12);
  put(136, "00000000000\0", 12);
  header.fill(0x20, 148, 156);
  header[156] = typeflag.charCodeAt(0);
  put(157, "ustar\0", 6);
  put(263, "00", 2);
  if (prefix) put(345, prefix, 155);
  let sum = 0;
  for (const b of header) sum += b;
  put(148, sum.toString(8).padStart(6, "0") + "\0 ", 8);
  return header;
}

function entry(e: Entry): Buffer {
  const data = Buffer.isBuffer(e.content) ? e.content : Buffer.from(e.content, "utf8");
  const header = tarHeader(e.name, data.length, e.typeflag ?? "0", e.prefix ?? "");
  const pad = (512 - (data.length % 512)) % 512;
  return Buffer.concat([header, data, Buffer.alloc(pad)]);
}

function buildTar(entries: Entry[]): Buffer {
  return Buffer.concat([...entries.map(entry), Buffer.alloc(1024)]);
}

function paxPath(path: string): Buffer {
  const kv = ` path=${path}\n`;
  let len = kv.length + 1;
  for (;;) {
    const s = String(len);
    if (s.length + kv.length === len) return Buffer.from(s + kv, "utf8");
    len = s.length + kv.length;
  }
}

function fakeFetch(buf: Buffer, status = 200): typeof fetch {
  const body = buf as unknown as ConstructorParameters<typeof Response>[0];
  return (async () => new Response(body, { status })) as unknown as typeof fetch;
}

describe("parseGithubUrl", () => {
  it("accepts the valid forms", () => {
    expect(parseGithubUrl("https://github.com/octocat/Hello-World")).toEqual({
      owner: "octocat",
      repo: "Hello-World",
      ref: "HEAD",
    });
    expect(parseGithubUrl("https://github.com/octocat/Hello-World/")).toEqual({
      owner: "octocat",
      repo: "Hello-World",
      ref: "HEAD",
    });
    expect(parseGithubUrl("https://github.com/octocat/Hello-World.git")).toEqual({
      owner: "octocat",
      repo: "Hello-World",
      ref: "HEAD",
    });
    expect(parseGithubUrl("https://github.com/octocat/Hello-World/tree/main")).toEqual({
      owner: "octocat",
      repo: "Hello-World",
      ref: "main",
    });
    expect(parseGithubUrl("https://github.com/octocat/Hello-World/tree/feature/foo")).toEqual({
      owner: "octocat",
      repo: "Hello-World",
      ref: "feature/foo",
    });
  });

  it("rejects evil inputs", () => {
    expect(parseGithubUrl("http://github.com/a/b")).toBeNull();
    expect(parseGithubUrl("https://github.com.evil.com/a/b")).toBeNull();
    expect(parseGithubUrl("https://user@github.com/a/b")).toBeNull();
    expect(parseGithubUrl("https://github.com:22/a/b")).toBeNull();
    expect(parseGithubUrl("https://github.com/a/b?x=1")).toBeNull();
    expect(parseGithubUrl("https://gitlab.com/a/b")).toBeNull();
    expect(parseGithubUrl("https://github.com/a/../b")).toBeNull();
    expect(parseGithubUrl("https://github.com/onlyowner")).toBeNull();
    expect(parseGithubUrl("https://github.com/a/b/tree/")).toBeNull();
  });
});

describe("fetchGithubRepo", () => {
  it("strips the top-level directory", async () => {
    const tar = buildTar([{ name: "owner-repo-sha/src/index.ts", content: "export const x = 1;\n" }]);
    const repo = await fetchGithubRepo("https://github.com/owner/repo", {
      fetch: fakeFetch(gzipSync(tar)),
    });
    expect(repo.name).toBe("owner/repo");
    expect(repo.files.map((f) => f.path)).toEqual(["src/index.ts"]);
  });

  it("applies the skip rules", async () => {
    const tar = buildTar([
      { name: "top/node_modules/dep/index.js", content: "x" },
      { name: "top/.env", content: "SECRET=1" },
      { name: "top/.env.example", content: "SECRET=" },
      { name: "top/binary.bin", content: Buffer.from([1, 0, 2, 3]) },
      { name: "top/big.txt", content: "a".repeat(600 * 1024) },
      { name: "top/keep.js", content: "keep" },
    ]);
    const repo = await fetchGithubRepo("https://github.com/owner/repo", {
      fetch: fakeFetch(gzipSync(tar)),
    });
    expect(repo.files.map((f) => f.path)).toEqual([".env.example", "keep.js"]);
  });

  it("honours a pax long path", async () => {
    const longPath = `top/${"a".repeat(120)}.txt`;
    const tar = buildTar([
      { name: "PaxHeader", typeflag: "x", content: paxPath(longPath) },
      { name: "placeholder", content: "hello" },
    ]);
    const repo = await fetchGithubRepo("https://github.com/owner/repo", {
      fetch: fakeFetch(gzipSync(tar)),
    });
    expect(repo.files).toHaveLength(1);
    expect(repo.files[0].path).toBe("a".repeat(120) + ".txt");
    expect(repo.files[0].content).toBe("hello");
  });

  it("throws GithubError on a non-200", async () => {
    await expect(
      fetchGithubRepo("https://github.com/owner/repo", { fetch: fakeFetch(Buffer.alloc(0), 404) }),
    ).rejects.toBeInstanceOf(GithubError);
  });

  it("keeps the first 500 files past the cap and counts the rest", async () => {
    const entries: Entry[] = Array.from({ length: 503 }, (_, i) => ({
      name: `top/f${i}.js`,
      content: "x",
    }));
    const repo = await fetchGithubRepo("https://github.com/owner/repo", {
      fetch: fakeFetch(gzipSync(buildTar(entries))),
    });
    expect(repo.files).toHaveLength(500);
    expect(repo.omitted).toBe(3);
    expect(repo.files.at(-1)!.path).toBe("f499.js");
  });

  it("stops keeping text at 2 MB but still takes small files that fit", async () => {
    const big = "y".repeat(400 * 1024);
    const entries: Entry[] = [
      ...Array.from({ length: 6 }, (_, i) => ({ name: `top/big${i}.js`, content: big })),
      { name: "top/small.js", content: "z" },
    ];
    const repo = await fetchGithubRepo("https://github.com/owner/repo", {
      fetch: fakeFetch(gzipSync(buildTar(entries))),
    });
    expect(repo.files.map((f) => f.path)).toEqual(["big0.js", "big1.js", "big2.js", "big3.js", "big4.js", "small.js"]);
    expect(repo.omitted).toBe(1);
  });
});
describe("POST /api/scans/github", () => {
  async function withRouter(fetchImpl: typeof fetch, run: (router: ReturnType<typeof makeRouter>) => Promise<void>) {
    const dir = await mkdtemp(join(tmpdir(), "siidekick-gh-test-"));
    process.env.STORAGE = "local";
    process.env.DATA_DIR = dir;
    try {
      await run(makeRouter({ store: createStore(), fetch: fetchImpl }));
    } finally {
      delete process.env.STORAGE;
      delete process.env.DATA_DIR;
      await rm(dir, { recursive: true, force: true });
    }
  }

  it("scans the fetched tarball and stores the report", async () => {
    const tar = gzipSync(buildTar([{ name: "shop-main/server.js", content: "app.listen(3000);\n" }]));
    await withRouter(fakeFetch(tar), async (router) => {
      const res = await router.handle({ method: "POST", path: "/api/scans/github", body: { url: "https://github.com/acme/shop" } });
      expect(res.status).toBe(201);
      const { id, report } = res.body as { id: string; report: { repo: string } };
      expect(report.repo).toBe("acme/shop");
      const again = await router.handle({ method: "GET", path: `/api/scans/${id}` });
      expect(again.status).toBe(200);
    });
  });

  it("scans a repo past the file cap and says how many files it left out", async () => {
    const entries = Array.from({ length: 502 }, (_, i) => ({ name: `big-main/f${i}.js`, content: "x" }));
    await withRouter(fakeFetch(gzipSync(buildTar(entries))), async (router) => {
      const res = await router.handle({ method: "POST", path: "/api/scans/github", body: { url: "https://github.com/acme/big" } });
      expect(res).toMatchObject({ status: 201, body: { omitted: 2 } });
      const { id } = res.body as { id: string };
      const again = await router.handle({ method: "GET", path: `/api/scans/${id}` });
      expect(again.body).toMatchObject({ omitted: 2 });
    });
  });

  it("returns 400 with the reason for a bad URL or a missing repo", async () => {
    await withRouter(fakeFetch(Buffer.alloc(0), 404), async (router) => {
      const bad = await router.handle({ method: "POST", path: "/api/scans/github", body: { url: "https://evil.example/acme/shop" } });
      expect(bad).toMatchObject({ status: 400, body: { error: "not a valid public GitHub repo URL" } });
      const missing = await router.handle({ method: "POST", path: "/api/scans/github", body: { url: "https://github.com/acme/nope" } });
      expect(missing).toMatchObject({ status: 400, body: { error: "repo not found or not public" } });
      const noBody = await router.handle({ method: "POST", path: "/api/scans/github", body: {} });
      expect(noBody.status).toBe(400);
    });
  });
});
