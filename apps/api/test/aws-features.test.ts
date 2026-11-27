import { describe, expect, it, beforeEach, afterEach } from "vitest";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inflateRawSync } from "node:zlib";
import type { Finding } from "@siidekick/engine";
import { makeRouter } from "../src/router.js";
import { createStore } from "../src/store.js";
import { evidenceFor, explainFinding, groundingCheck, type ConverseFn } from "../src/ai.js";
import { buildSourceZip, evaluate, evaluateJob, type BuildResult, type JobMeta, type SideResult, type VerifyBackend } from "../src/verify.js";
import { prBody } from "../src/pullRequest.js";

const lodashFinding: Finding = {
  checkId: "dependency-audit",
  title: "Vulnerable dependency: qs",
  severity: "high",
  file: "package-lock.json",
  evidence: "qs@6.7.0 → fixed in 6.10.3 (GHSA-hrpp-h998-j3pp / CVE-2022-24999) — transitive via express → qs",
  explanation: "Prototype pollution in qs.",
  chain: ["express", "qs"],
  advisories: [{ id: "GHSA-hrpp-h998-j3pp", aliases: ["CVE-2022-24999"], summary: "qs prototype pollution", severity: "HIGH", fixed: "6.10.3" }],
};

describe("AI grounding", () => {
  it("accepts ids and versions that are in the evidence", () => {
    const ev = evidenceFor(lodashFinding);
    expect(ev).toContain("DEPENDENCY PATH (app first): your app -> express -> qs");
    expect(groundingCheck("Upgrade qs from 6.7.0 to 6.10.3 to close CVE-2022-24999 (GHSA-hrpp-h998-j3pp).", ev)).toEqual([]);
  });

  it("flags an invented CVE or version", () => {
    const ev = evidenceFor(lodashFinding);
    expect(groundingCheck("This is CVE-2023-99999; upgrade to 7.0.1.", ev)).toEqual(["CVE-2023-99999", "7.0.1"]);
  });

  it("retries once when the model invents a fact, then accepts a grounded answer", async () => {
    const answers = [
      JSON.stringify({ summary: "Bad: CVE-2021-1111", impact: "x", fix: "upgrade to 9.9.9", options: [], unknowns: "" }),
      JSON.stringify({ summary: "qs 6.7.0 है", impact: "डेटा", fix: "express अपडेट करें", options: [{ option: "a", tradeoff: "b" }], unknowns: "पहुँच अज्ञात" }),
    ];
    const prompts: string[] = [];
    const converse: ConverseFn = async (r) => {
      prompts.push(r.user + "\n" + r.system);
      return answers.shift()!;
    };
    const out = await explainFinding({ converse, modelId: "m", finding: lodashFinding, lang: "hi" });
    expect(out.ungrounded).toEqual([]);
    expect(out.explanation.summary).toContain("qs");
    expect(prompts[0]).toContain("Hindi");
    expect(prompts[1]).toContain("CVE-2021-1111");
  });

  it("returns ungrounded tokens when the model keeps inventing", async () => {
    const converse: ConverseFn = async () => JSON.stringify({ summary: "CVE-2020-0001", fix: "x", impact: "", options: [], unknowns: "" });
    const out = await explainFinding({ converse, modelId: "m", finding: lodashFinding, lang: "en" });
    expect(out.ungrounded).toEqual(["CVE-2020-0001"]);
  });
});

const side = (over: Partial<SideResult> = {}): SideResult => ({
  install: { ok: true, code: 0, tail: "" },
  tests: { ran: true, code: 0, passed: true, tail: "" },
  audit: { ok: true, packages: {} },
  ...over,
});
const meta: JobMeta = { jobId: "j", scanId: "s", repo: "r", targets: ["qs", "lodash"], approved: ["p"], startedAt: "t" };
const vuln = { severity: "high", isDirect: false, via: [], fixAvailable: true };

describe("trust rule", () => {
  it("verified only when tests pass and every target is clean in npm audit", () => {
    const r: BuildResult = { before: side({ audit: { ok: true, packages: { qs: vuln, lodash: vuln } } }), after: side(), lockfileRefreshed: true };
    const v = evaluate(meta, r);
    expect(v.status).toBe("verified");
    expect(v.targets.every((t) => t.fixed)).toBe(true);
  });

  it("not verified when a target is still vulnerable", () => {
    const r: BuildResult = { before: side(), after: side({ audit: { ok: true, packages: { qs: vuln } } }), lockfileRefreshed: true };
    expect(evaluate(meta, r).status).toBe("not-verified");
  });

  it("catches a regression: tests passed before and fail after", () => {
    const r: BuildResult = { before: side(), after: side({ tests: { ran: true, code: 1, passed: false, tail: "boom" } }), lockfileRefreshed: true };
    expect(evaluate(meta, r).status).toBe("regression");
  });

  it("inconclusive without tests, even when the audit is clean", () => {
    const r: BuildResult = { before: side({ tests: { ran: false } }), after: side({ tests: { ran: false } }), lockfileRefreshed: true };
    expect(evaluate(meta, r).status).toBe("inconclusive");
  });

  it("not verified when npm audit gave no report", () => {
    const r: BuildResult = { before: side(), after: side({ audit: { ok: false, packages: {} } }), lockfileRefreshed: true };
    expect(evaluate(meta, r).status).toBe("not-verified");
  });

  it("error when the build produced nothing", () => {
    expect(evaluate(meta, null, "States.Timeout").status).toBe("error");
  });
});

describe("source zip", () => {
  it("puts our scripts outside the repo folders and refuses traversal paths", () => {
    const zip = buildSourceZip(
      { name: "a", files: [{ path: "package.json", content: "{}" }, { path: "../evil.sh", content: "x" }] },
      { name: "a", files: [{ path: "package.json", content: '{"x":1}' }] },
    );
    const names: string[] = [];
    let at = 0;
    while (zip.readUInt32LE(at) === 0x04034b50) {
      const csize = zip.readUInt32LE(at + 18);
      const nlen = zip.readUInt16LE(at + 26);
      const name = zip.subarray(at + 30, at + 30 + nlen).toString("utf8");
      names.push(name);
      if (name === "after/package.json") expect(inflateRawSync(zip.subarray(at + 30 + nlen, at + 30 + nlen + csize)).toString()).toBe('{"x":1}');
      at += 30 + nlen + csize;
    }
    expect(names).toEqual(["siidekick/verify.sh", "siidekick/collect.cjs", "before/package.json", "after/package.json"]);
  });
});

describe("PR body", () => {
  it("includes fixes, verdict evidence and limits", () => {
    const v = evaluate(meta, { before: side({ audit: { ok: true, packages: { qs: vuln } } }), after: side(), lockfileRefreshed: true });
    const body = prBody({ scanId: "abc", scoreBefore: 40, scoreAfter: 81, fixes: [{ title: "Bump qs", reason: "a | b", added: 1, removed: 1 }], verdict: v });
    expect(body).toContain("40 → 81");
    expect(body).toContain("a \\| b");
    expect(body).toContain("AWS CodeBuild): ✅ verified");
    expect(body).toContain("| qs | high | clean |");
    expect(body).toContain("does not make the app secure");
  });
});

// ---- router integration with fake AWS backends ----

let tmpDir: string;
beforeEach(async () => {
  tmpDir = await mkdtemp(join(tmpdir(), "siidekick-aws-test-"));
  process.env.STORAGE = "local";
  process.env.DATA_DIR = tmpDir;
});
afterEach(async () => {
  await rm(tmpDir, { recursive: true, force: true });
  delete process.env.STORAGE;
  delete process.env.DATA_DIR;
});

function fakeBackend(): VerifyBackend & { objects: Map<string, string | Buffer>; started: string[] } {
  const objects = new Map<string, string | Buffer>();
  const started: string[] = [];
  return {
    bucket: "b",
    objects,
    started,
    async put(key, body) {
      objects.set(key, body);
    },
    async get(key) {
      const v = objects.get(key);
      return v === undefined ? null : v.toString();
    },
    async start(jobId) {
      started.push(jobId);
      return `arn:${jobId}`;
    },
    async describe() {
      return { status: "RUNNING" };
    },
  };
}

const KEY = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc";
const repoFiles = [
  { path: "package.json", content: JSON.stringify({ name: "x", scripts: { test: "node --test" } }, null, 2) },
  { path: "server.js", content: `const STRIPE_API_KEY = '${KEY}';\n` },
];
const offline = (async () => {
  throw new Error("offline");
}) as typeof fetch;

describe("router: AWS features", () => {
  it("reports features in health", async () => {
    const router = makeRouter({ store: createStore(), fetch: offline });
    const res = await router.handle({ method: "GET", path: "/api/health" });
    expect(res.body).toMatchObject({ features: { ai: null, verify: false, pullRequests: true } });
  });

  it("explain: 503 without Bedrock, cached grounded answer with it", async () => {
    const store = createStore();
    let calls = 0;
    const converse: ConverseFn = async () => {
      calls++;
      return JSON.stringify({ summary: "A secret is in your code.", impact: "Anyone can use it.", fix: "Move it to an env var.", options: [], unknowns: "" });
    };
    const off = makeRouter({ store, fetch: offline });
    const created = await off.handle({ method: "POST", path: "/api/scans", body: { name: "x", files: repoFiles } });
    const id = (created.body as { id: string }).id;
    expect((await off.handle({ method: "POST", path: `/api/scans/${id}/explain`, body: { checkId: "secrets-in-repo" } })).status).toBe(503);

    const on = makeRouter({ store, fetch: offline, ai: { modelId: "apac.amazon.nova-lite-v1:0", converse: async () => converse } });
    const bad = await on.handle({ method: "POST", path: `/api/scans/${id}/explain`, body: { checkId: "secrets-in-repo", lang: "xx" } });
    expect(bad.status).toBe(400);
    const r1 = await on.handle({ method: "POST", path: `/api/scans/${id}/explain`, body: { checkId: "secrets-in-repo", lang: "ta" } });
    expect(r1.status).toBe(200);
    expect(r1.body).toMatchObject({ lang: "ta", ungrounded: [] });
    const r2 = await on.handle({ method: "POST", path: `/api/scans/${id}/explain`, body: { checkId: "secrets-in-repo", lang: "ta" } });
    expect(r2.body).toMatchObject({ cached: true });
    expect(calls).toBe(1);
  });

  it("verify: needs an approved fix, uploads before/after, starts the workflow, then serves the verdict", async () => {
    const store = createStore();
    const backend = fakeBackend();
    const router = makeRouter({ store, fetch: offline, verify: async () => backend });
    const created = await router.handle({ method: "POST", path: "/api/scans", body: { name: "x", files: repoFiles } });
    const id = (created.body as { id: string }).id;
    expect((await router.handle({ method: "POST", path: `/api/scans/${id}/verify` })).status).toBe(409);

    const patches = await router.handle({ method: "POST", path: `/api/scans/${id}/patches` });
    const first = (patches.body as { patches: Array<{ patch: { id: string }; guard: { ok: boolean } }> }).patches.find((p) => p.guard.ok)!;
    await router.handle({ method: "POST", path: `/api/scans/${id}/patches/${first.patch.id}/approve` });

    const start = await router.handle({ method: "POST", path: `/api/scans/${id}/verify` });
    expect(start.status).toBe(202);
    const { jobId } = start.body as { jobId: string };
    expect(backend.started).toEqual([jobId]);
    expect(backend.objects.has(`jobs/${jobId}/source.zip`)).toBe(true);

    const again = await router.handle({ method: "POST", path: `/api/scans/${id}/verify` });
    expect(again.body).toMatchObject({ jobId, reused: true });

    const running = await router.handle({ method: "GET", path: `/api/scans/${id}/verify/${jobId}` });
    expect(running.body).toMatchObject({ state: "running" });

    backend.objects.set(`jobs/${jobId}/out/result.json`, JSON.stringify({ before: side(), after: side(), lockfileRefreshed: true }));
    const verdict = await evaluateJob(backend, { jobId });
    expect(verdict.status).toBe("verified"); // no dependency targets in this repo: tests pass, nothing flagged

    const done = await router.handle({ method: "GET", path: `/api/scans/${id}/verify/${jobId}` });
    expect(done.body).toMatchObject({ state: "done", verdict: { status: "verified" } });

    const other = await router.handle({ method: "GET", path: `/api/scans/${crypto.randomUUID()}/verify/${jobId}` });
    expect(other.status).toBe(404);
  });

  it("pull request: only for GitHub scans, token validated, never echoed", async () => {
    const store = createStore();
    const router = makeRouter({ store, fetch: offline });
    const created = await router.handle({ method: "POST", path: "/api/scans", body: { name: "x", files: repoFiles } });
    const id = (created.body as { id: string }).id;
    const short = await router.handle({ method: "POST", path: `/api/scans/${id}/pr`, body: { token: "abc" } });
    expect(short.status).toBe(400);
    const token = "github_pat_" + "A".repeat(30);
    const res = await router.handle({ method: "POST", path: `/api/scans/${id}/pr`, body: { token } });
    expect(res.status).toBe(409);
    expect(JSON.stringify(res.body)).not.toContain(token);
  });
});

describe("openPullRequest", () => {
  it("creates tree, commit, branch and PR against the default branch; token only in the auth header", async () => {
    const { openPullRequest } = await import("../src/pullRequest.js");
    const calls: Array<{ method: string; url: string; body?: string; auth?: string }> = [];
    const fake = (async (url: string, init?: RequestInit) => {
      const method = init?.method ?? "GET";
      const h = init?.headers as Record<string, string>;
      calls.push({ method, url, body: init?.body as string | undefined, auth: h.authorization });
      const u = new URL(url).pathname;
      const json = (o: unknown, status = 200) => new Response(JSON.stringify(o), { status, headers: { "content-type": "application/json" } });
      if (u === "/repos/me/shop") return json({ default_branch: "main" });
      if (u === "/repos/me/shop/git/ref/heads/main") return json({ object: { sha: "base1" } });
      if (u === "/repos/me/shop/git/commits/base1") return json({ tree: { sha: "tree0" } });
      if (u === "/repos/me/shop/git/trees") return json({ sha: "tree1" }, 201);
      if (u === "/repos/me/shop/git/commits") return json({ sha: "c1" }, 201);
      if (u === "/repos/me/shop/git/refs") return json({ ref: "x" }, 201);
      if (u === "/repos/me/shop/pulls") return json({ html_url: "https://github.com/me/shop/pull/7", number: 7 }, 201);
      return json({ message: "Not Found" }, 404);
    }) as typeof fetch;
    const token = "github_pat_" + "B".repeat(30);
    const pr = await openPullRequest({
      token, owner: "me", repo: "shop", ref: "HEAD", scanId: "12345678-aaaa", fetch: fake,
      files: [{ path: "package.json", content: "{}" }], title: "Siidekick: 1 security fix", body: "b",
    });
    expect(pr).toMatchObject({ url: "https://github.com/me/shop/pull/7", number: 7 });
    expect(pr.branch).toMatch(/^siidekick\/fixes-12345678-/);
    const tree = JSON.parse(calls.find((c) => c.url.endsWith("/git/trees"))!.body!);
    expect(tree).toMatchObject({ base_tree: "tree0", tree: [{ path: "package.json", content: "{}" }] });
    const pull = JSON.parse(calls.find((c) => c.url.endsWith("/pulls"))!.body!);
    expect(pull).toMatchObject({ base: "main", head: pr.branch });
    expect(calls.every((c) => c.auth === `Bearer ${token}` && !(c.body ?? "").includes(token))).toBe(true);
  });

  it("explains a permission problem in plain words", async () => {
    const { openPullRequest } = await import("../src/pullRequest.js");
    const fake = (async () => new Response(JSON.stringify({ message: "Resource not accessible by personal access token" }), { status: 403 })) as typeof fetch;
    await expect(
      openPullRequest({ token: "t".repeat(30), owner: "me", repo: "shop", ref: "HEAD", scanId: "s", fetch: fake, files: [{ path: "a", content: "b" }], title: "t", body: "b" }),
    ).rejects.toThrow(/Contents and Pull requests/);
  });
});

describe("openPullRequest permission hint", () => {
  it("names the Workflows permission and the failing step when a fix adds a GitHub Actions file", async () => {
    const { openPullRequest } = await import("../src/pullRequest.js");
    const fake = (async (url: string) => {
      const u = new URL(url).pathname;
      const ok = (o: unknown) => new Response(JSON.stringify(o), { status: 200 });
      if (u === "/repos/me/shop") return ok({ default_branch: "main" });
      if (u === "/repos/me/shop/git/ref/heads/main") return ok({ object: { sha: "b" } });
      if (u === "/repos/me/shop/git/commits/b") return ok({ tree: { sha: "t" } });
      return new Response(JSON.stringify({ message: "Resource not accessible by personal access token" }), { status: 403 });
    }) as typeof fetch;
    const files = [{ path: ".github/workflows/siidekick.yml", content: "on: push" }];
    await expect(
      openPullRequest({ token: "t".repeat(30), owner: "me", repo: "shop", ref: "HEAD", scanId: "s", fetch: fake, files, title: "t", body: "b" }),
    ).rejects.toThrow(/uploading the changed files.*Workflows/s);
  });
});
