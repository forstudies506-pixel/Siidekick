import {
  runScan,
  registry,
  guardPatch,
  renderDiff,
  applyPatch,
  type RepoSnapshot,
  type ScanReport,
  type Patch,
  type GuardResult,
  type DiffLine,
  type Check,
} from "@siidekick/engine";
import * as z from "zod";
import { readFile } from "node:fs/promises";
import { createStore, type Store, type ScanRecord } from "./store.js";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const MAX_FILES = 500;
const MAX_BYTES = 2 * 1024 * 1024;

const scanBodySchema = z.object({
  name: z.string().min(1),
  files: z.array(z.object({ path: z.string(), content: z.string() })).max(MAX_FILES),
});

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

export function makeRouter(deps: { store: Store }) {
  const store = deps.store;

  async function healthHandler(): Promise<{ status: number; body: unknown }> {
    return { status: 200, body: { ok: true, checks: registry.length } };
  }

  async function createScanHandler(_params: Record<string, string>, body: unknown): Promise<{ status: number; body: unknown }> {
    const v = validateScanBody(body);
    if (!v.ok) return { status: 400, body: { error: v.error } };
    const repo: RepoSnapshot = v.repo;
    const report: ScanReport = await runScan({ repo, fetch }, registry);
    const id = crypto.randomUUID();
    const record: ScanRecord = { id, createdAt: new Date().toISOString(), repo, report };
    await store.put(id, record);
    return { status: 201, body: { id, report } };
  }

  async function demoScanHandler(): Promise<{ status: number; body: unknown }> {
    const demoUrl = new URL("./demoRepo.generated.json", import.meta.url);
    const repo: RepoSnapshot = JSON.parse(await readFile(demoUrl, "utf8"));
    const report: ScanReport = await runScan({ repo, fetch }, registry);
    const id = crypto.randomUUID();
    const record: ScanRecord = { id, createdAt: new Date().toISOString(), repo, report };
    await store.put(id, record);
    return { status: 201, body: { id, report } };
  }

  async function getScanHandler(params: Record<string, string>): Promise<{ status: number; body: unknown }> {
    if (!UUID_RE.test(params.id)) return { status: 400, body: { error: "invalid id" } };
    const record = await store.get(params.id);
    if (!record) return { status: 404, body: { error: "not found" } };
    return {
      status: 200,
      body: { id: record.id, report: record.report, patches: record.patches, after: record.after },
    };
  }

  async function patchesHandler(params: Record<string, string>): Promise<{ status: number; body: unknown }> {
    if (!UUID_RE.test(params.id)) return { status: 400, body: { error: "invalid id" } };
    const record = await store.get(params.id);
    if (!record) return { status: 404, body: { error: "not found" } };

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
        patch = await check.fix({ repo: current }, result.findings);
      } catch (err) {
        // A crashing fixer is that check's problem; skip it and keep applying the rest.
        console.error(`check ${check.id} fix threw:`, err);
        continue;
      }
      if (!patch) continue;

      const guard: GuardResult = guardPatch(current, patch);
      const diff = patch.edits.map((e) =>
        e.kind === "create" ? { path: e.path, lines: renderDiff("", e.content) } : { path: e.path, lines: renderDiff(e.before, e.after) },
      );

      entries.push({ patchId: patch.id, patch, guard, diff, approved: false });
      if (guard.ok) {
        current = applyPatch(current, patch);
      }
    }

    const afterReport: ScanReport = await runScan({ repo: current }, registry);
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
  async function approvedSnapshot(record: ScanRecord): Promise<RepoSnapshot> {
    const approved = new Set((record.patches ?? []).filter((p) => p.approved).map((p) => p.patchId));
    let current: RepoSnapshot = { name: record.repo.name, files: [...record.repo.files] };
    for (const check of registry) {
      const result = record.report.results.find((r) => r.checkId === check.id);
      if (!result || result.passed || !check.fix) continue;
      let patch: Patch | null;
      try {
        patch = await check.fix({ repo: current }, result.findings);
      } catch {
        continue;
      }
      if (!patch || !approved.has(patch.id) || !guardPatch(current, patch).ok) continue;
      current = applyPatch(current, patch);
    }
    return current;
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
    const rescan = await runScan({ repo: await approvedSnapshot(record) }, registry);
    return { status: 200, body: { approved, score: rescan.score, passed: rescan.passed, total: rescan.total } };
  }

  async function downloadHandler(params: Record<string, string>): Promise<{ status: number; body: unknown }> {
    if (!UUID_RE.test(params.id)) return { status: 400, body: { error: "invalid id" } };
    const record = await store.get(params.id);
    if (!record) return { status: 404, body: { error: "not found" } };

    const patches = record.patches ?? [];
    const approvedPaths = new Set<string>();
    for (const p of patches) {
      if (p.approved) {
        for (const d of p.diff) approvedPaths.add(d.path);
      }
    }

    const snapshot = await approvedSnapshot(record);
    const files = snapshot.files.filter((f) => approvedPaths.has(f.path)).map((f) => ({ path: f.path, content: f.content }));
    return { status: 200, body: { files } };
  }

  const routes: RouteDef[] = [
    { method: "GET", path: "api/health", handler: healthHandler },
    { method: "POST", path: "api/scans", handler: createScanHandler },
    { method: "POST", path: "api/scans/demo", handler: demoScanHandler },
    { method: "GET", path: "api/scans/:id", handler: getScanHandler },
    { method: "POST", path: "api/scans/:id/patches", handler: patchesHandler },
    { method: "POST", path: "api/scans/:id/patches/:patchId/approve", handler: approveHandler },
    { method: "GET", path: "api/scans/:id/download", handler: downloadHandler },
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
      console.error(err);
      return { status: 500, body: { error: "internal" } };
    }
  }

  return { handle };
}
