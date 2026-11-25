import { execFile } from "node:child_process";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { applyPatch, GuardRejected } from "./apply.js";
import type { Patch, RepoSnapshot } from "./types.js";

export type TestRun = { ok: boolean; output: string };
/** Runs the owner's tests in `dir`. null means the project has no test script. */
export type TestRunner = (dir: string) => Promise<TestRun | null>;
export type Verdict = { patch: Patch; kept: boolean; note: string };
/** Rebuilds a patch against `repo` when the patch no longer fits because an earlier one was undone. */
export type Regenerate = (repo: RepoSnapshot, stale: Patch) => Promise<Patch | null>;

const TEST_TIMEOUT_MS = 120_000;

/** `npm test` in `dir`, only when package.json defines a test script. Local CLI only, never server-side. */
export const runOwnerTests: TestRunner = async (dir) => {
  let pkg: { scripts?: Record<string, string> };
  try {
    pkg = JSON.parse(await readFile(join(dir, "package.json"), "utf8"));
  } catch {
    return null;
  }
  if (!pkg.scripts?.test) return null;
  return new Promise((done) => {
    execFile("npm", ["test"], { cwd: dir, timeout: TEST_TIMEOUT_MS, env: { ...process.env, CI: "1" }, maxBuffer: 8 * 1024 * 1024 }, (err, stdout, stderr) => {
      done({ ok: !err, output: (stdout + stderr).split("\n").slice(-20).join("\n") });
    });
  });
};

export async function writeRepo(repo: RepoSnapshot, out: string): Promise<void> {
  for (const f of repo.files) {
    const p = join(out, f.path);
    await mkdir(dirname(p), { recursive: true });
    await writeFile(p, f.content);
  }
}

async function writeEdits(out: string, patch: Patch, direction: "apply" | "undo"): Promise<void> {
  for (const e of patch.edits) {
    const p = join(out, e.path);
    if (e.kind === "create" && direction === "undo") {
      await rm(p);
      continue;
    }
    await mkdir(dirname(p), { recursive: true });
    await writeFile(p, e.kind === "create" ? e.content : direction === "apply" ? e.after : e.before);
  }
}

/**
 * Test-and-rollback: writes `original` to `out`, runs the tests, then applies each patch on disk and reruns them.
 * A patch after which the tests fail is undone. Patches are chained, so one built on an undone patch is rebuilt
 * with `regenerate` when given, and skipped otherwise.
 */
export async function verifyPatches(
  out: string,
  original: RepoSnapshot,
  patches: Patch[],
  run: TestRunner = runOwnerTests,
  regenerate?: Regenerate,
): Promise<{ baseline: TestRun | null; verdicts: Verdict[]; repo: RepoSnapshot }> {
  await writeRepo(original, out);
  const baseline = await run(out);
  let current = original;

  if (!baseline || !baseline.ok) {
    const note = baseline ? "tests already fail before any patch, so not verified" : "no test script, so not verified";
    for (const p of patches) current = applyPatch(current, p);
    await writeRepo(current, out);
    return { baseline, verdicts: patches.map((patch) => ({ patch, kept: true, note })), repo: current };
  }

  const verdicts: Verdict[] = [];
  for (const stale of patches) {
    let patch = stale;
    let next: RepoSnapshot;
    try {
      next = applyPatch(current, patch);
    } catch (e) {
      if (!(e instanceof GuardRejected)) throw e;
      const fresh = regenerate ? await regenerate(current, stale) : null;
      if (!fresh) {
        verdicts.push({ patch, kept: false, note: "built on a patch that was rolled back" });
        continue;
      }
      // A rebuilt patch that still does not fit is a bug in its check, so let applyPatch throw.
      patch = fresh;
      next = applyPatch(current, patch);
    }
    await writeEdits(out, patch, "apply");
    const r = await run(out);
    if (r?.ok) {
      current = next;
      verdicts.push({ patch, kept: true, note: "tests pass" });
    } else {
      await writeEdits(out, patch, "undo");
      verdicts.push({ patch, kept: false, note: "tests failed after this patch, rolled back" });
    }
  }
  return { baseline, verdicts, repo: current };
}
