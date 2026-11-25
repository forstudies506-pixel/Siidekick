import { describe, expect, it } from "vitest";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runOwnerTests, verifyPatches } from "../src/verify.js";
import type { Patch, RepoSnapshot } from "../src/types.js";

// The project's own test fails when flag.txt says "bad", so a patch that writes "bad" must be rolled back.
const pkg = JSON.stringify({ name: "t", scripts: { test: "node -e \"process.exit(require('fs').readFileSync('flag.txt','utf8').includes('bad')?1:0)\"" } });
const original: RepoSnapshot = {
  name: "t",
  files: [
    { path: "package.json", content: pkg },
    { path: "flag.txt", content: "ok\n" },
  ],
};
const good: Patch = {
  id: "good-1",
  checkId: "good",
  title: "Add a helper",
  class: "additive",
  reason: "r",
  edits: [{ kind: "create", path: "lib/helper.js", content: "module.exports = 1;\n" }],
};
const bad: Patch = {
  id: "bad-1",
  checkId: "bad",
  title: "Break the tests",
  class: "additive",
  reason: "r",
  edits: [
    { kind: "modify", path: "flag.txt", before: "ok\n", after: "ok\nbad\n" },
    { kind: "create", path: "lib/extra.js", content: "x\n" },
  ],
};
const onBad: Patch = {
  id: "after-bad-1",
  checkId: "after",
  title: "Built on the bad patch",
  class: "additive",
  reason: "r",
  edits: [{ kind: "modify", path: "flag.txt", before: "ok\nbad\n", after: "ok\nbad\nmore\n" }],
};

function tmp() {
  return mkdtempSync(join(tmpdir(), "siidekick-verify-"));
}

describe("verifyPatches", () => {
  it("keeps a passing patch, rolls back a failing one, and skips one built on it", async () => {
    const out = tmp();
    try {
      const { baseline, verdicts, repo } = await verifyPatches(out, original, [good, bad, onBad]);
      expect(baseline?.ok).toBe(true);
      expect(verdicts.map((v) => [v.patch.id, v.kept])).toEqual([
        ["good-1", true],
        ["bad-1", false],
        ["after-bad-1", false],
      ]);
      expect(verdicts[2].note).toContain("rolled back");
      expect(readFileSync(join(out, "flag.txt"), "utf8")).toBe("ok\n");
      expect(existsSync(join(out, "lib/helper.js"))).toBe(true);
      expect(existsSync(join(out, "lib/extra.js"))).toBe(false);
      expect(repo.files.map((f) => f.path)).toEqual(["flag.txt", "lib/helper.js", "package.json"]);
    } finally {
      rmSync(out, { recursive: true, force: true });
    }
  }, 30_000); // spawns four real `npm test` runs; slow when every test file runs in parallel

  it("keeps every patch but marks them unverified when tests already fail", async () => {
    const out = tmp();
    try {
      const broken = { ...original, files: [original.files[0], { path: "flag.txt", content: "bad\n" }] };
      const { baseline, verdicts } = await verifyPatches(out, broken, [good]);
      expect(baseline?.ok).toBe(false);
      expect(verdicts[0].kept).toBe(true);
      expect(verdicts[0].note).toContain("not verified");
      expect(existsSync(join(out, "lib/helper.js"))).toBe(true);
    } finally {
      rmSync(out, { recursive: true, force: true });
    }
  });

  it("returns null baseline when there is no test script", async () => {
    const out = tmp();
    try {
      expect(await runOwnerTests(out)).toBeNull();
    } finally {
      rmSync(out, { recursive: true, force: true });
    }
  });

  it("rebuilds a patch built on an undone one when given regenerate", async () => {
    const out = tmp();
    try {
      const rebuilt: Patch = { ...onBad, edits: [{ kind: "modify", path: "flag.txt", before: "ok\n", after: "ok\nmore\n" }] };
      const { verdicts } = await verifyPatches(out, original, [bad, onBad], undefined, async (repo, stale) => {
        expect(stale.id).toBe("after-bad-1");
        expect(repo.files.find((f) => f.path === "flag.txt")!.content).toBe("ok\n");
        return rebuilt;
      });
      expect(verdicts.map((v) => v.kept)).toEqual([false, true]);
      expect(verdicts[1].patch).toBe(rebuilt);
      expect(readFileSync(join(out, "flag.txt"), "utf8")).toBe("ok\nmore\n");
    } finally {
      rmSync(out, { recursive: true, force: true });
    }
  });
});
