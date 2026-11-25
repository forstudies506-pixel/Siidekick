import { guardPatch, type GuardLimits } from "./diffGuard.js";
import type { GuardResult, Patch, RepoSnapshot } from "./types.js";

export class GuardRejected extends Error {
  constructor(public result: GuardResult) {
    super(`diff guard rejected patch: ${result.violations.map((v) => `${v.path}:${v.reason}`).join(", ")}`);
  }
}

/** Applies a patch to an in-memory snapshot. Throws GuardRejected if the diff guard says no. */
export function applyPatch(repo: RepoSnapshot, patch: Patch, limits?: Partial<GuardLimits>): RepoSnapshot {
  const result = guardPatch(repo, patch, limits);
  if (!result.ok) throw new GuardRejected(result);
  const files = new Map(repo.files.map((f) => [f.path, f.content]));
  for (const e of patch.edits) files.set(e.path, e.kind === "create" ? e.content : e.after);
  return { name: repo.name, files: [...files].map(([path, content]) => ({ path, content })).sort((a, b) => a.path.localeCompare(b.path)) };
}
