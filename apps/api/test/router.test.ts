import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { registry, type ScanReport, type CheckResult, type RepoSnapshot } from "@siidekick/engine";
import { cachedScanFetch, makeRouter } from "../src/router.js";
import { createStore } from "../src/store.js";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

let tmpDir: string;
let store: ReturnType<typeof createStore>;
let router: ReturnType<typeof makeRouter>;

const KEY = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc";
const tinyRepo: RepoSnapshot = {
  name: "tiny",
  files: [{ path: "server.js", content: `const STRIPE_API_KEY = '${KEY}';\n` }],
};

beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), "siidekick-api-test-"));
  process.env.STORAGE = "local";
  process.env.DATA_DIR = tmpDir;
  store = createStore();
  router = makeRouter({ store });
});

afterEach(async () => {
  await rm(tmpDir, { recursive: true, force: true });
  delete process.env.STORAGE;
  delete process.env.DATA_DIR;
});

describe("router", () => {
  it("health returns ok and check count", async () => {
    const res = await router.handle({ method: "GET", path: "/api/health" });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ ok: true, checks: registry.length, storage: "local" });
  });

  it("creates a scan; hardcoded key makes secrets-in-repo fail", async () => {
    const res = await router.handle({
      method: "POST",
      path: "/api/scans",
      body: { name: "tiny", files: tinyRepo.files },
    });
    expect(res.status).toBe(201);
    const { id, report } = res.body as { id: string; report: ScanReport };
    expect(typeof id).toBe("string");
    const sec = report.results.find((r: CheckResult) => r.checkId === "secrets-in-repo");
    expect(sec).toBeDefined();
    expect(sec!.passed).toBe(false);
    expect(sec!.severity).toBe("critical");
  });

  it("400 on path containing ..", async () => {
    const res = await router.handle({
      method: "POST",
      path: "/api/scans",
      body: { name: "x", files: [{ path: "../secret.js", content: "a" }] },
    });
    expect(res.status).toBe(400);
    expect(res.body).toMatchObject({ error: expect.any(String) });
  });

  it("400 on more than 500 files", async () => {
    const files = Array.from({ length: 501 }, (_, i) => ({ path: `f${i}.js`, content: "x" }));
    const res = await router.handle({ method: "POST", path: "/api/scans", body: { name: "x", files } });
    expect(res.status).toBe(400);
  });

  it("404 for unknown scan id", async () => {
    const res = await router.handle({
      method: "GET",
      path: "/api/scans/00000000-0000-0000-0000-000000000000",
    });
    expect(res.status).toBe(404);
  });

  it("patches apply, improve score, and every recorded guard is ok", async () => {
    const createRes = await router.handle({
      method: "POST",
      path: "/api/scans",
      body: { name: "tiny", files: tinyRepo.files },
    });
    expect(createRes.status).toBe(201);
    const id = (createRes.body as { id: string }).id;

    const patchRes = await router.handle({ method: "POST", path: `/api/scans/${id}/patches` });
    expect(patchRes.status).toBe(200);
    const body = patchRes.body as {
      scoreBefore: number;
      scoreAfter: number;
      status: string;
      patches: Array<{ guard: { ok: boolean } }>;
    };
    expect(body.scoreAfter).toBeGreaterThan(body.scoreBefore);
    for (const p of body.patches) expect(p.guard.ok).toBe(true);
  });

  it("download returns only approved files", async () => {
    const createRes = await router.handle({
      method: "POST",
      path: "/api/scans",
      body: { name: "tiny", files: tinyRepo.files },
    });
    const id = (createRes.body as { id: string }).id;

    const patchRes = await router.handle({ method: "POST", path: `/api/scans/${id}/patches` });
    const patchId = (patchRes.body as { patches: Array<{ patch: { id: string } }> }).patches[0].patch.id;

    let dl = await router.handle({ method: "GET", path: `/api/scans/${id}/download` });
    expect((dl.body as { files: unknown[] }).files).toEqual([]);

    const ap = await router.handle({
      method: "POST",
      path: `/api/scans/${id}/patches/${patchId}/approve`,
    });
    expect((ap.body as { approved: string[] }).approved).toContain(patchId);
    expect((ap.body as { failing: string[] }).failing).not.toContain("secrets-in-repo");

    const stored = await router.handle({ method: "GET", path: `/api/scans/${id}` });
    expect(stored.body).toMatchObject({ demo: false, approvedSummary: { failing: expect.any(Array) } });

    dl = await router.handle({ method: "GET", path: `/api/scans/${id}/download` });
    const paths = (dl.body as { files: Array<{ path: string }> }).files.map((f) => f.path);
    expect(paths).toContain("server.js");
    expect(paths).toContain(".env.example");
    expect(paths).toContain(`.siidekick/${patchId}.patch`);
    expect(paths).toContain("SIIDEKICK_LOG.md");
    const log = (dl.body as { files: Array<{ path: string; content: string }> }).files.find((f) => f.path === "SIIDEKICK_LOG.md")!;
    expect(log.content).toContain(`git apply -R .siidekick/${patchId}.patch`);
  });

  it("download leaves out edits from patches that were not approved", async () => {
    const expressServer =
      "const express = require('express');\nconst app = express();\napp.use(express.json());\n" +
      `const STRIPE_API_KEY = '${KEY}';\n` +
      "app.post('/login', (req, res) => res.json({ ok: true }));\napp.listen(3000);\n";
    const createRes = await router.handle({
      method: "POST",
      path: "/api/scans",
      body: { name: "express", files: [{ path: "server.js", content: expressServer }] },
    });
    const id = (createRes.body as { id: string }).id;
    const patchRes = await router.handle({ method: "POST", path: `/api/scans/${id}/patches` });
    type Edit = { kind: string; path: string; after?: string };
    const patches = (patchRes.body as { patches: Array<{ patch: { id: string; edits: Edit[] } }> }).patches;
    const touchingServer = patches.filter((p) => p.patch.edits.some((e) => e.path === "server.js"));
    expect(touchingServer.length).toBeGreaterThan(1);

    // The first patch was generated against the original repo, so its server.js `after` is exactly
    // what approving it alone must produce.
    const first = touchingServer[0];
    const ap = await router.handle({ method: "POST", path: `/api/scans/${id}/patches/${first.patch.id}/approve` });
    expect(ap.status).toBe(200);
    expect(typeof (ap.body as { score: number }).score).toBe("number");

    const dl = await router.handle({ method: "GET", path: `/api/scans/${id}/download` });
    const server = (dl.body as { files: Array<{ path: string; content: string }> }).files.find((f) => f.path === "server.js");
    expect(server?.content).toBe(first.patch.edits.find((e) => e.path === "server.js")!.after);
  });
  describe("tamper check", () => {
    type Edit = { kind: "create"; path: string; content: string } | { kind: "modify"; path: string; before: string; after: string };
    type Entry = { patch: { id: string; edits: Edit[] }; guard: { ok: boolean } };

    async function patchedScan() {
      const files = [{ path: "server.js", content: `const STRIPE_API_KEY = '${KEY}';\napp.listen(3000);\n` }];
      const created = await router.handle({ method: "POST", path: "/api/scans", body: { name: "tiny", files } });
      const id = (created.body as { id: string }).id;
      const res = await router.handle({ method: "POST", path: `/api/scans/${id}/patches` });
      const entries = (res.body as { patches: Entry[] }).patches;
      const target = entries.find((e) => e.patch.edits.some((x) => x.kind === "modify" && x.path === "server.js"));
      if (!target) throw new Error("expected a patch that modifies server.js");
      return { id, target };
    }

    it("passes the stored edits unchanged", async () => {
      const { id, target } = await patchedScan();
      const res = await router.handle({
        method: "POST",
        path: `/api/scans/${id}/patches/${target.patch.id}/check`,
        body: { edits: target.patch.edits },
      });
      expect(res.status).toBe(200);
      expect((res.body as { guard: { ok: boolean } }).guard.ok).toBe(true);
    });

    it("blocks an edit that deletes an owner line and names the line", async () => {
      const { id, target } = await patchedScan();
      const edits = target.patch.edits.map((e) =>
        e.kind === "modify" && e.path === "server.js"
          ? { ...e, after: e.after.split("\n").filter((l) => !l.includes("app.listen")).join("\n") }
          : e,
      );
      const res = await router.handle({ method: "POST", path: `/api/scans/${id}/patches/${target.patch.id}/check`, body: { edits } });
      expect(res.status).toBe(200);
      const guard = (res.body as { guard: { ok: boolean; violations: Array<{ reason: string; line?: string }> } }).guard;
      expect(guard.ok).toBe(false);
      expect(guard.violations.some((v) => v.line?.includes("app.listen(3000)"))).toBe(true);
    });

    it("rejects a bad body, an unsafe path and an unknown patch", async () => {
      const { id, target } = await patchedScan();
      const url = `/api/scans/${id}/patches/${target.patch.id}/check`;
      expect((await router.handle({ method: "POST", path: url, body: { edits: [] } })).status).toBe(400);
      const unsafe = [{ kind: "create", path: "../x.js", content: "" }];
      expect((await router.handle({ method: "POST", path: url, body: { edits: unsafe } })).status).toBe(400);
      const huge = Array.from({ length: 3000 }, (_, i) => `l${i}`).join("\n");
      const tooBig = [{ kind: "modify", path: "server.js", before: huge, after: huge + "\nx" }];
      expect((await router.handle({ method: "POST", path: url, body: { edits: tooBig } })).status).toBe(400);
      const missing = `/api/scans/${id}/patches/no-such-patch/check`;
      expect((await router.handle({ method: "POST", path: missing, body: { edits: target.patch.edits } })).status).toBe(404);
    });
  });
  describe("prove (attack replay)", () => {
    type Receipt = { id: string; verdict: string };
    type Path = { id: string; openAfter: boolean };

    it("refuses records that are not the demo shop", async () => {
      const created = await router.handle({ method: "POST", path: "/api/scans", body: tinyRepo });
      const { id } = created.body as { id: string };
      const res = await router.handle({ method: "POST", path: `/api/scans/${id}/prove` });
      expect(res.status).toBe(409);
    });

    it("rejects a bad id and a missing record", async () => {
      expect((await router.handle({ method: "POST", path: "/api/scans/not-a-uuid/prove" })).status).toBe(400);
      expect((await router.handle({ method: "POST", path: `/api/scans/${crypto.randomUUID()}/prove` })).status).toBe(404);
    });

    it("replays attacks on the demo: unapproved stays open, approved fixes block", async () => {
      // No network in tests: the dependency audit fails soft without OSV.
      router = makeRouter({ store, fetch: (async () => { throw new Error("offline"); }) as typeof fetch });
      const created = await router.handle({ method: "POST", path: "/api/scans/demo" });
      const { id } = created.body as { id: string };

      const none = await router.handle({ method: "POST", path: `/api/scans/${id}/prove` });
      expect(none.status).toBe(200);
      const noneBody = none.body as { available: boolean; attacks: Receipt[] };
      expect(noneBody.available).toBe(true);
      expect(noneBody.attacks.every((a) => a.verdict === "still-open")).toBe(true);

      const patchRes = await router.handle({ method: "POST", path: `/api/scans/${id}/patches` });
      const entries = (patchRes.body as { patches: Array<{ patch: { id: string }; guard: { ok: boolean } }> }).patches;
      for (const e of entries.filter((p) => p.guard.ok)) {
        const ap = await router.handle({ method: "POST", path: `/api/scans/${id}/patches/${e.patch.id}/approve` });
        expect(ap.status).toBe(200);
      }
      const res = await router.handle({ method: "POST", path: `/api/scans/${id}/prove` });
      const body = res.body as { available: boolean; attacks: Receipt[]; paths: Path[] };
      const verdict = Object.fromEntries(body.attacks.map((a) => [a.id, a.verdict]));
      expect(verdict["admin-open"]).toBe("blocked");
      expect(verdict["brute-force"]).toBe("blocked");
      expect(verdict["sqli-dump"]).toBe("still-open");
      expect(JSON.stringify(body)).not.toMatch(/password123|welcome2024|fest2025|pk_demo_/);
    }, 30_000);
  });
});

describe("cachedScanFetch", () => {
  const BATCH = "https://api.osv.dev/v1/querybatch";
  function counting(status = 200) {
    const calls: string[] = [];
    const inner = (async (input: RequestInfo | URL) => {
      calls.push(String(input));
      return new Response(JSON.stringify({ n: calls.length }), { status, headers: { "content-type": "application/json" } });
    }) as typeof fetch;
    return { calls, inner };
  }

  it("answers a repeated OSV query from the cache, with a readable body each time", async () => {
    const { calls, inner } = counting();
    const f = cachedScanFetch(inner);
    const a = await f(BATCH, { method: "POST", body: '{"queries":[1]}' });
    const b = await f(BATCH, { method: "POST", body: '{"queries":[1]}' });
    expect(await a.json()).toEqual({ n: 1 });
    expect(await b.json()).toEqual({ n: 1 });
    expect(calls).toHaveLength(1);
  });

  it("keys on the request body, expires entries, and never caches failures or other hosts", async () => {
    let t = 0;
    const { calls, inner } = counting();
    const f = cachedScanFetch(inner, () => t);
    await f(BATCH, { method: "POST", body: "a" });
    await f(BATCH, { method: "POST", body: "b" });
    expect(calls).toHaveLength(2);
    t = 11 * 60_000;
    await f(BATCH, { method: "POST", body: "a" });
    expect(calls).toHaveLength(3);
    await f("https://api.github.com/x");
    await f("https://api.github.com/x");
    expect(calls).toHaveLength(5);

    const failing = counting(503);
    const g = cachedScanFetch(failing.inner);
    await g(BATCH, { method: "POST", body: "a" });
    await g(BATCH, { method: "POST", body: "a" });
    expect(failing.calls).toHaveLength(2);
  });

  it("caches a registry 404 as an answer, but not an OSV 404", async () => {
    const missing = counting(404);
    const f = cachedScanFetch(missing.inner);
    const npm = "https://registry.npmjs.org/no-such-pkg";
    expect((await f(npm, { method: "HEAD" })).status).toBe(404);
    expect((await f(npm, { method: "HEAD" })).status).toBe(404);
    expect(missing.calls).toHaveLength(1);
    await f(BATCH, { method: "POST", body: "a" });
    await f(BATCH, { method: "POST", body: "a" });
    expect(missing.calls).toHaveLength(3);
  });
});

describe("source code only", () => {
  it("has no website scanning route", async () => {
    const res = await router.handle({ method: "POST", path: "/api/sites", body: { url: "https://www.youtube.com" } });
    expect(res.status).toBe(404);
    const checks = await router.handle({ method: "GET", path: "/api/checks" });
    expect(Object.keys(checks.body as object)).toEqual(["repo"]);
  });
});
