import type { GuardResult, GuardViolation, Patch, RepoSnapshot } from "./types.js";

export interface GuardLimits {
  maxAdded: number;
  maxRemoved: number;
}

const DEFAULT_LIMITS: GuardLimits = { maxAdded: 400, maxRemoved: 5 };

function splitLines(s: string): string[] {
  if (s === "") return [];
  const lines = s.split(/\r?\n/);
  if (lines[lines.length - 1] === "") lines.pop();
  return lines;
}

export type DiffLine = { type: "same" | "add" | "del"; text: string };

/** LCS line diff in order, for rendering. renderDiff("a\nb", "a\nc") -> same a, del b, add c. */
export function renderDiff(before: string, after: string): DiffLine[] {
  return diffLines(splitLines(before), splitLines(after));
}

/** LCS diff over already-split lines. */
export function diffLines(a: string[], b: string[]): DiffLine[] {
  // Patches add a few lines to a long file; trimming the shared ends keeps the O(n·m) table small.
  let start = 0;
  while (start < a.length && start < b.length && a[start] === b[start]) start++;
  let endA = a.length;
  let endB = b.length;
  while (endA > start && endB > start && a[endA - 1] === b[endB - 1]) {
    endA--;
    endB--;
  }
  const same = (text: string): DiffLine => ({ type: "same", text });
  return [...a.slice(0, start).map(same), ...lcsDiff(a.slice(start, endA), b.slice(start, endB)), ...a.slice(endA).map(same)];
}

function lcsDiff(a: string[], b: string[]): DiffLine[] {
  const n = a.length;
  const m = b.length;
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      out.push({ type: "same", text: a[i++] });
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      out.push({ type: "del", text: a[i++] });
    } else {
      out.push({ type: "add", text: b[j++] });
    }
  }
  while (i < n) out.push({ type: "del", text: a[i++] });
  while (j < m) out.push({ type: "add", text: b[j++] });
  return out;
}

/** Lines only in `before` (removed) and only in `after` (added). */
export function lineDiff(before: string, after: string): { added: string[]; removed: string[] } {
  const d = renderDiff(before, after);
  return { added: d.filter((l) => l.type === "add").map((l) => l.text), removed: d.filter((l) => l.type === "del").map((l) => l.text) };
}

/**
 * The "we never replace your code" promise, enforced in code (ROADMAP §9).
 * Pure function: checks the patch against the repo snapshot, applies nothing.
 */
export function guardPatch(repo: RepoSnapshot, patch: Patch, limits: Partial<GuardLimits> = {}): GuardResult {
  const lim = { ...DEFAULT_LIMITS, ...limits };
  const files = new Map(repo.files.map((f) => [f.path, f.content]));
  const allowed = new Set((patch.allowedRemovals ?? []).map((l) => l.trim()));
  const violations: GuardViolation[] = [];
  let added = 0;
  let removed = 0;

  for (const edit of patch.edits) {
    if (edit.kind === "create") {
      if (files.has(edit.path)) {
        violations.push({ path: edit.path, reason: "overwrites-existing-file" });
        continue;
      }
      added += splitLines(edit.content).length;
      continue;
    }

    const current = files.get(edit.path);
    if (current === undefined) {
      violations.push({ path: edit.path, reason: "modify-missing-file" });
      continue;
    }
    if (current !== edit.before) {
      violations.push({ path: edit.path, reason: "before-mismatch" });
      continue;
    }

    const d = lineDiff(edit.before, edit.after);
    added += d.added.length;
    removed += d.removed.length;
    for (const line of d.removed) {
      if (patch.class === "additive") {
        violations.push({ path: edit.path, reason: "removal-in-additive-patch", line });
      } else if (!allowed.has(line.trim())) {
        violations.push({ path: edit.path, reason: "removed-line-not-allowed", line });
      }
    }
  }

  if (added > lim.maxAdded || removed > lim.maxRemoved) {
    violations.push({ path: "*", reason: "patch-too-large" });
  }

  return { ok: violations.length === 0, added, removed, violations };
}
