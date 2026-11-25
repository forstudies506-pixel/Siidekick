import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { registry, type ScanReport, type CheckResult, type RepoSnapshot } from "@siidekick/engine";
import { makeRouter } from "../src/router.js";
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
    expect(res.body).toMatchObject({ ok: true, checks: registry.length });
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
});
