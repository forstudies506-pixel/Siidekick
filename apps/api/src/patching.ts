import { applyPatch, guardPatch, registry, renderDiff, runScan, type DiffLine, type FileEdit, type Patch, type RepoSnapshot, type ScanReport } from "@siidekick/engine";
import type { PatchEntry } from "./store.js";

export function editDiff(edits: FileEdit[]): Array<{ path: string; lines: DiffLine[] }> {
  return edits.map((e) =>
    e.kind === "create" ? { path: e.path, lines: renderDiff("", e.content) } : { path: e.path, lines: renderDiff(e.before, e.after) },
  );
}

/**
 * Every fix the registry proposes for a scanned repo, in registry order, each generated against the
 * repo with the earlier guard-accepted fixes applied. Used by the API and by the AWS pipeline, so both
 * propose exactly the same patches. Nothing is approved here.
 */
export async function proposePatches(
  repo: RepoSnapshot,
  report: ScanReport,
  fetchFn: typeof fetch,
): Promise<{ entries: PatchEntry[]; patched: RepoSnapshot; after: ScanReport }> {
  let current: RepoSnapshot = { name: repo.name, files: [...repo.files] };
  const entries: PatchEntry[] = [];
  for (const check of registry) {
    const result = report.results.find((r) => r.checkId === check.id);
    if (!result || result.passed || !check.fix) continue;
    let patch: Patch | null;
    try {
      patch = await check.fix({ repo: current, fetch: fetchFn }, result.findings);
    } catch (err) {
      // A crashing fixer is that check's problem; skip it and keep applying the rest.
      console.error(`check ${check.id} fix threw:`, err);
      continue;
    }
    if (!patch) continue;
    const guard = guardPatch(current, patch);
    entries.push({ patchId: patch.id, patch, guard, diff: editDiff(patch.edits), approved: false });
    if (guard.ok) current = applyPatch(current, patch);
  }
  const after = await runScan({ repo: current, fetch: fetchFn }, registry);
  return { entries, patched: current, after };
}
