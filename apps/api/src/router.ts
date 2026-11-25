import {
  runScan,
  registry,
  guardPatch,
  renderDiff,
  applyPatch,
  patchArtifacts,
  replayDemo,
  type RepoSnapshot,
  type ScanReport,
  type Patch,
  type GuardResult,
  type DiffLine,
  type Check,
  type FileEdit,
  runSiteScan,
  type SiteSnapshot,
} from "@siidekick/engine";
import * as z from "zod";
import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { createStore, RecordTooLargeError, type Store, type ScanRecord } from "./store.js";
import { fetchGithubRepo, GithubError } from "./github.js";
import { fetchSite, SiteError, takeScanSlot } from "./site.js";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const MAX_FILES = 500;
const MAX_BYTES = 2 * 1024 * 1024;

const scanBodySchema = z.object({
  name: z.string().min(1),
  files: z.array(z.object({ path: z.string(), content: z.string() })).max(MAX_FILES),
});

const githubBodySchema = z.object({ url: z.string().max(300) });
const siteBodySchema = z.object({ url: z.string().min(1).max(2048) });

function validatePath(p: string): string | null {
  if (p.includes("\0")) return "path must not contain NUL";
  if (p.startsWith("/")) return "path must be relative, no leading /";
  for (const seg of p.split("/")) {
    if (seg === "..") return "path must not contain ..";
  }
  return null;
}

function validateScanBody(body: unknown): { ok: true; repo: RepoSnapshot } | { ok: false; error: string } {
  const parsed = scanBodySchema.safeParse(body);
  if (!parsed.success) return { ok: false, error: "invalid request body" };
  const { name, files } = parsed.data;
  let total = 0;
  for (const f of files) {
    const err = validatePath(f.path);
    if (err) return { ok: false, error: err };
    total += Buffer.byteLength(f.content, "utf8");
  }
  if (total > MAX_BYTES) return { ok: false, error: "total content exceeds 2 MB" };
  return { ok: true, repo: { name, files } };
}

// The tamper check diffs whatever the client sends; cap each edit's line product so the O(n·m) diff stays cheap.
const MAX_CHECK_EDITS = 20;
const MAX_DIFF_CELLS = 4_000_000;

const editSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("create"), path: z.string(), content: z.string() }),
  z.object({ kind: z.literal("modify"), path: z.string(), before: z.string(), after: z.string() }),
]);
const checkBodySchema = z.object({ edits: z.array(editSchema).min(1).max(MAX_CHECK_EDITS) });

function editDiff(edits: FileEdit[]): Array<{ path: string; lines: DiffLine[] }> {
  return edits.map((e) =>
    e.kind === "create" ? { path: e.path, lines: renderDiff("", e.content) } : { path: e.path, lines: renderDiff(e.before, e.after) },
  );
}

type Handler = (params: Record<string, string>, body: unknown) => Promise<{ status: number; body: unknown }>;

interface RouteDef {
  method: string;
  path: string;
  handler: Handler;
}

function matchPath(pattern: string, pathname: string): Record<string, string> | null {
  const pSegs = pattern.split("/");
  const sSegs = pathname.split("/");
  if (pSegs.length !== sSegs.length) return null;
  const params: Record<string, string> = {};
  for (let i = 0; i < pSegs.length; i++) {
    const p = pSegs[i];
    const s = sSegs[i];
    if (p.startsWith(":")) {
      params[p.slice(1)] = s;
    } else if (p !== s) {
      return null;
    }
  }
  return params;
}

// Every approve rescans the whole repo. OSV advisories and registry existence do not change within minutes.
const CACHED_HOSTS = new Set(["api.osv.dev", "registry.npmjs.org", "pypi.org"]);
// A registry 404 is an answer ("not published"), so it is cached too. OSV 404s are errors and are not.
const CACHE_404_HOSTS = new Set(["registry.npmjs.org", "pypi.org"]);
const CACHE_TTL_MS = 10 * 60_000;
const CACHE_MAX_ENTRIES = 2000;

/** Wraps fetch so identical OSV.dev and package-registry requests reuse a recent answer. Other hosts pass straight through. */
export function cachedScanFetch(inner: typeof fetch, now: () => number = Date.now): typeof fetch {
  const cache = new Map<string, { at: number; status: number; type: string; body: string }>();
  const replay = (e: { status: number; type: string; body: string }) =>
    new Response(e.body || null, { status: e.status, headers: { "content-type": e.type } });
  return async (input, init) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const reqBody = init?.body ?? "";
    const host = new URL(url).host;
    if (!CACHED_HOSTS.has(host) || typeof reqBody !== "string") return inner(input, init);
    const key = createHash("sha256").update(`${init?.method ?? "GET"} ${url}\n${reqBody}`).digest("hex");
    const hit = cache.get(key);
    if (hit && now() - hit.at < CACHE_TTL_MS) return replay(hit);
    const res = await inner(input, init);
    if (!res.ok && !(res.status === 404 && CACHE_404_HOSTS.has(host))) return res;
    const entry = { at: now(), status: res.status, type: res.headers.get("content-type") ?? "application/json", body: await res.text() };
    cache.delete(key);
    if (cache.size >= CACHE_MAX_ENTRIES) cache.delete(cache.keys().next().value as string);
    cache.set(key, entry);
    return replay(entry);
  };
}

const DEMO_URL = new URL("./demoRepo.generated.json", import.meta.url);

async function readDemoRepo(): Promise<RepoSnapshot> {
  return JSON.parse(await readFile(DEMO_URL, "utf8"));
}

/** node_modules with express and lodash for the replay child: dist/runtime in Lambda, the workspace root in dev. */
function defaultReplayRuntime(): string | null {
  const candidates = [new URL("./runtime/node_modules", import.meta.url), new URL("../../../node_modules", import.meta.url)];
  for (const u of candidates) {
    const dir = fileURLToPath(u);
    if (existsSync(`${dir}/express`) && existsSync(`${dir}/lodash`)) return dir;
  }
  return null;
}

export function makeRouter(deps: {
  store: Store;
  fetch?: typeof fetch;
  replayRuntime?: string;
  fetchSite?: (url: string) => Promise<SiteSnapshot>;
}) {
  const store = deps.store;
  const scanFetch = cachedScanFetch(deps.fetch ?? fetch);

  async function healthHandler(): Promise<{ status: number; body: unknown }> {
    return { status: 200, body: { ok: true, checks: registry.length } };
  }

  async function saveScan(repo: RepoSnapshot, demo = false, omitted = 0): Promise<{ status: number; body: unknown }> {
    const report: ScanReport = await runScan({ repo, fetch: scanFetch }, registry);
    const id = crypto.randomUUID();
    const record: ScanRecord = {
      id,
      createdAt: new Date().toISOString(),
      repo,
      report,
      ...(demo ? { demo: true as const } : {}),
      ...(omitted > 0 ? { omitted } : {}),
    };
    await store.put(id, record);
    return { status: 201, body: { id, report, ...(omitted > 0 ? { omitted } : {}) } };
  }

  async function createScanHandler(_params: Record<string, string>, body: unknown): Promise<{ status: number; body: unknown }> {
    const v = validateScanBody(body);
    if (!v.ok) return { status: 400, body: { error: v.error } };
    return saveScan(v.repo);
  }

  async function demoScanHandler(): Promise<{ status: number; body: unknown }> {
    return saveScan(await readDemoRepo(), true);
  }

  async function githubScanHandler(_params: Record<string, string>, body: unknown): Promise<{ status: number; body: unknown }> {
    const parsed = githubBodySchema.safeParse(body);
    if (!parsed.success) return { status: 400, body: { error: "invalid request body" } };
    try {
      const { omitted, ...repo } = await fetchGithubRepo(parsed.data.url, { fetch: deps.fetch });
      return await saveScan(repo, false, omitted);
    } catch (err) {
      if (err instanceof GithubError) return { status: 400, body: { error: err.message } };
      throw err;
    }
  }

  async function siteScanHandler(_params: Record<string, string>, body: unknown): Promise<{ status: number; body: unknown }> {
    const parsed = siteBodySchema.safeParse(body);
    if (!parsed.success) return { status: 400, body: { error: "invalid request body" } };
    if (!takeScanSlot()) return { status: 429, body: { error: "too many website scans right now; try again in a minute" } };
    let snap: SiteSnapshot;
    try {
      snap = await (deps.fetchSite ?? fetchSite)(parsed.data.url);
    } catch (err) {
      if (err instanceof SiteError) return { status: err.status, body: { error: err.message } };
      throw err;
    }
    const report = runSiteScan(snap);
    const id = crypto.randomUUID();
    const site = { url: snap.requested, finalUrl: snap.url, fetchedAt: snap.fetchedAt };
    // The page itself is not stored: it can be large and it is the site's content, not ours.
    await store.put(id, {
      id,
      createdAt: new Date().toISOString(),
      repo: { name: new URL(snap.url).host, files: [] },
      report,
      kind: "site",
      site,
    });
    return { status: 201, body: { id, report, kind: "site", site } };
  }

  async function getScanHandler(params: Record<string, string>): Promise<{ status: number; body: unknown }> {
    if (!UUID_RE.test(params.id)) return { status: 400, body: { error: "invalid id" } };
    const record = await store.get(params.id);
    if (!record) return { status: 404, body: { error: "not found" } };
    const anyApproved = (record.patches ?? []).some((p) => p.approved);
    return {
      status: 200,
      body: {
        id: record.id,
        report: record.report,
        patches: record.patches,
        after: record.after,
        omitted: record.omitted,
        demo: record.demo === true,
        ...(record.kind ? { kind: record.kind, site: record.site } : {}),
        ...(anyApproved ? { approvedSummary: await approvedSummary(record) } : {}),
      },
    };
  }

  async function patchesHandler(params: Record<string, string>): Promise<{ status: number; body: unknown }> {
    if (!UUID_RE.test(params.id)) return { status: 400, body: { error: "invalid id" } };
    const record = await store.get(params.id);
    if (!record) return { status: 404, body: { error: "not found" } };
    if (record.kind === "site") return { status: 400, body: { error: "website scans report fixes; there is no code to patch" } };

    let current: RepoSnapshot = { name: record.repo.name, files: [...record.repo.files] };
    const beforeReport: ScanReport = record.report;
    const entries: Array<{
      patchId: string;
      patch: Patch;
      guard: GuardResult;
      diff: Array<{ path: string; lines: DiffLine[] }>;
      approved: boolean;
    }> = [];

    for (const check of registry) {
      const result = beforeReport.results.find((r) => r.checkId === check.id);
      if (!result || result.passed || !check.fix) continue;
      let patch: Patch | null;
      try {
        patch = await check.fix({ repo: current, fetch: scanFetch }, result.findings);
      } catch (err) {
        // A crashing fixer is that check's problem; skip it and keep applying the rest.
        console.error(`check ${check.id} fix threw:`, err);
        continue;
      }
      if (!patch) continue;

      const guard: GuardResult = guardPatch(current, patch);
      const diff = editDiff(patch.edits);

      entries.push({ patchId: patch.id, patch, guard, diff, approved: false });
      if (guard.ok) {
        current = applyPatch(current, patch);
      }
    }

    const afterReport: ScanReport = await runScan({ repo: current, fetch: scanFetch }, registry);
    const status: "rescan-clean" | "partial" = afterReport.passed === afterReport.total ? "rescan-clean" : "partial";

    const updated: ScanRecord = {
      ...record,
      patches: entries,
      after: afterReport,
      // snapshotAfter is stored internally so /download can serve file contents.
      snapshotAfter: current,
    };
    await store.put(params.id, updated);

    return {
      status: 200,
      body: {
        patches: entries.map((e) => ({ patch: e.patch, guard: e.guard, diff: e.diff })),
        scoreBefore: beforeReport.score,
        scoreAfter: afterReport.score,
        status,
      },
    };
  }

  /**
   * The owner's repo with only the approved patches applied. Stored patches are chained (each one was
   * generated against the repo with every earlier patch applied), so replaying a subset would hit
   * before-mismatches. Fixers are deterministic, so approved ones are re-run against the original repo.
   */
  async function approvedSnapshot(record: ScanRecord, base: RepoSnapshot = record.repo): Promise<{ snapshot: RepoSnapshot; applied: Patch[] }> {
    const approved = new Set((record.patches ?? []).filter((p) => p.approved).map((p) => p.patchId));
    let current: RepoSnapshot = { name: base.name, files: [...base.files] };
    const applied: Patch[] = [];
    for (const check of registry) {
      const result = record.report.results.find((r) => r.checkId === check.id);
      if (!result || result.passed || !check.fix) continue;
      let patch: Patch | null;
      try {
        patch = await check.fix({ repo: current, fetch: scanFetch }, result.findings);
      } catch {
        continue;
      }
      if (!patch || !approved.has(patch.id) || !guardPatch(current, patch).ok) continue;
      current = applyPatch(current, patch);
      applied.push(patch);
    }
    return { snapshot: current, applied };
  }

  /** Rescan of the repo with only the approved patches applied: what the owner would ship. */
  async function approvedSummary(record: ScanRecord): Promise<{ score: number; passed: number; total: number; failing: string[] }> {
    const rescan = await runScan({ repo: (await approvedSnapshot(record)).snapshot, fetch: scanFetch }, registry);
    const failing = rescan.results.filter((r) => !r.passed && !r.skipped).map((r) => r.checkId);
    return { score: rescan.score, passed: rescan.passed, total: rescan.total, failing };
  }

  async function approveHandler(params: Record<string, string>): Promise<{ status: number; body: unknown }> {
    if (!UUID_RE.test(params.id)) return { status: 400, body: { error: "invalid id" } };
    // patchId is the check-defined patch id (e.g. "secrets-in-repo-1"), not a UUID.
    const record = await store.get(params.id);
    if (!record) return { status: 404, body: { error: "not found" } };
    const patches = record.patches ?? [];
    const patch = patches.find((p) => p.patchId === params.patchId);
    if (!patch) return { status: 404, body: { error: "patch not found" } };
    if (!patch.guard.ok) return { status: 409, body: { error: "the diff guard blocked this patch" } };
    patch.approved = true;
    const approved = patches.filter((p) => p.approved).map((p) => p.patchId);
    await store.put(params.id, record);
    return { status: 200, body: { approved, ...(await approvedSummary(record)) } };
  }

  /**
   * Runs the real diff guard on an edited copy of a stored patch, so the owner can watch it block a change
   * that deletes their code. Only the edits come from the client; class and allowedRemovals stay the stored
   * ones, so a tampered request cannot widen what the guard allows. Nothing is saved.
   */
  async function checkHandler(params: Record<string, string>, body: unknown): Promise<{ status: number; body: unknown }> {
    if (!UUID_RE.test(params.id)) return { status: 400, body: { error: "invalid id" } };
    const parsed = checkBodySchema.safeParse(body);
    if (!parsed.success) return { status: 400, body: { error: "invalid request body" } };
    const edits: FileEdit[] = parsed.data.edits;
    let bytes = 0;
    for (const e of edits) {
      const err = validatePath(e.path);
      if (err) return { status: 400, body: { error: err } };
      const text = e.kind === "create" ? e.content : e.before + e.after;
      bytes += Buffer.byteLength(text, "utf8");
      if (e.kind === "modify" && e.before.split("\n").length * e.after.split("\n").length > MAX_DIFF_CELLS) {
        return { status: 400, body: { error: "too many lines to diff" } };
      }
    }
    if (bytes > MAX_BYTES) return { status: 400, body: { error: "total content exceeds 2 MB" } };

    const record = await store.get(params.id);
    if (!record) return { status: 404, body: { error: "not found" } };
    const patches = record.patches ?? [];
    const index = patches.findIndex((p) => p.patchId === params.patchId);
    if (index === -1) return { status: 404, body: { error: "patch not found" } };

    // Rebuild the snapshot this patch was generated against: every earlier patch the guard let through.
    let base: RepoSnapshot = { name: record.repo.name, files: [...record.repo.files] };
    for (const p of patches.slice(0, index)) {
      if (p.guard.ok) base = applyPatch(base, p.patch);
    }
    const tampered: Patch = { ...patches[index].patch, edits };
    return { status: 200, body: { guard: guardPatch(base, tampered), diff: editDiff(edits) } };
  }

  async function downloadHandler(params: Record<string, string>): Promise<{ status: number; body: unknown }> {
    if (!UUID_RE.test(params.id)) return { status: 400, body: { error: "invalid id" } };
    const record = await store.get(params.id);
    if (!record) return { status: 404, body: { error: "not found" } };

    const { snapshot, applied } = await approvedSnapshot(record);
    const approvedPaths = new Set(applied.flatMap((p) => p.edits.map((e) => e.path)));
    const files = snapshot.files.filter((f) => approvedPaths.has(f.path)).map((f) => ({ path: f.path, content: f.content }));
    // The patch files and log let the owner see and undo each fix with plain git.
    files.push(...patchArtifacts(record.repo, applied));
    return { status: 200, body: { files } };
  }

  /**
   * Proof of fix: boots the demo shop before and after the approved patches and fires the same attacks at both.
   * Only the bundled demo is ever executed, never code a visitor sent, so `before` is read from disk, not the record.
   */
  async function proveHandler(params: Record<string, string>): Promise<{ status: number; body: unknown }> {
    if (!UUID_RE.test(params.id)) return { status: 400, body: { error: "invalid id" } };
    const record = await store.get(params.id);
    if (!record) return { status: 404, body: { error: "not found" } };
    if (!record.demo) return { status: 409, body: { error: "attack replay runs on the demo shop only" } };
    const runtimeDir = deps.replayRuntime ?? defaultReplayRuntime();
    if (!runtimeDir) return { status: 200, body: { available: false, reason: "replay unavailable here: runtime not bundled", attacks: [], paths: [], ms: 0 } };
    const before = await readDemoRepo();
    const { snapshot: after } = await approvedSnapshot(record, before);
    return { status: 200, body: await replayDemo({ before, after, runtimeDir }) };
  }

  const routes: RouteDef[] = [
    { method: "GET", path: "api/health", handler: healthHandler },
    { method: "POST", path: "api/scans", handler: createScanHandler },
    { method: "POST", path: "api/scans/demo", handler: demoScanHandler },
    { method: "POST", path: "api/scans/github", handler: githubScanHandler },
    { method: "POST", path: "api/sites", handler: siteScanHandler },
    { method: "GET", path: "api/scans/:id", handler: getScanHandler },
    { method: "POST", path: "api/scans/:id/patches", handler: patchesHandler },
    { method: "POST", path: "api/scans/:id/patches/:patchId/approve", handler: approveHandler },
    { method: "POST", path: "api/scans/:id/patches/:patchId/check", handler: checkHandler },
    { method: "GET", path: "api/scans/:id/download", handler: downloadHandler },
    { method: "POST", path: "api/scans/:id/prove", handler: proveHandler },
  ];

  async function handle(req: {
    method: string;
    path: string;
    body?: unknown;
  }): Promise<{ status: number; body: unknown }> {
    const pathname = req.path.replace(/\/+$/, "").replace(/^\//, "");
    const method = (req.method || "GET").toUpperCase();

    let pathMatched = false;
    let matched: { route: RouteDef; params: Record<string, string> } | null = null;
    for (const r of routes) {
      const params = matchPath(r.path, pathname);
      if (!params) continue;
      pathMatched = true;
      if (r.method === method) {
        matched = { route: r, params };
        break;
      }
    }
    if (!pathMatched) return { status: 404, body: { error: "not found" } };
    if (!matched) return { status: 405, body: { error: "method not allowed" } };

    try {
      return await matched.route.handler(matched.params, req.body);
    } catch (err) {
      if (err instanceof RecordTooLargeError) return { status: 413, body: { error: err.message } };
      console.error(err);
      return { status: 500, body: { error: "internal" } };
    }
  }

  return { handle };
}
