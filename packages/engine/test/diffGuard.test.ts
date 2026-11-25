import { describe, expect, it } from "vitest";
import { guardPatch, lineDiff } from "../src/diffGuard";
import type { Patch, RepoSnapshot } from "../src/types";

const repo: RepoSnapshot = {
  name: "demo",
  files: [{ path: "server.js", content: "const app = express();\napp.get('/', h);\napp.listen(3000);\n" }],
};

const base = { id: "p1", checkId: "x", title: "t", reason: "r" } as const;

describe("lineDiff", () => {
  it("counts pure insertions", () => {
    const d = lineDiff("a\nb\n", "a\nx\nb\n");
    expect(d.added).toEqual(["x"]);
    expect(d.removed).toEqual([]);
  });
  it("detects a changed line as remove + add", () => {
    const d = lineDiff("a\nb\n", "a\nc\n");
    expect(d.removed).toEqual(["b"]);
    expect(d.added).toEqual(["c"]);
  });
  it("diffs one inserted line in a 50k-line file without building the full table", () => {
    const big = Array.from({ length: 50_000 }, (_, i) => `line ${i}`);
    const after = [...big.slice(0, 25_000), "inserted", ...big.slice(25_000)];
    const d = lineDiff(big.join("\n"), after.join("\n"));
    expect(d.added).toEqual(["inserted"]);
    expect(d.removed).toEqual([]);
  });
});

describe("guardPatch", () => {
  it("accepts an additive patch that inserts one line and creates a file", () => {
    const p: Patch = {
      ...base,
      class: "additive",
      edits: [
        { kind: "create", path: "security.js", content: "module.exports = () => {};\n" },
        {
          kind: "modify",
          path: "server.js",
          before: repo.files[0].content,
          after: "const app = express();\nrequire('./security')(app);\napp.get('/', h);\napp.listen(3000);\n",
        },
      ],
    };
    const r = guardPatch(repo, p);
    expect(r.ok).toBe(true);
    expect(r.removed).toBe(0);
    expect(r.added).toBe(2);
  });

  it("rejects an additive patch that deletes a user line", () => {
    const p: Patch = {
      ...base,
      class: "additive",
      edits: [{ kind: "modify", path: "server.js", before: repo.files[0].content, after: "const app = express();\napp.listen(3000);\n" }],
    };
    const r = guardPatch(repo, p);
    expect(r.ok).toBe(false);
    expect(r.violations[0]).toMatchObject({ reason: "removal-in-additive-patch", line: "app.get('/', h);" });
  });

  it("allows a minimal edit only for declared removals", () => {
    const after = "const app = express();\napp.get('/', auth, h);\napp.listen(3000);\n";
    const ok = guardPatch(repo, {
      ...base,
      class: "minimal-edit",
      allowedRemovals: ["app.get('/', h);"],
      edits: [{ kind: "modify", path: "server.js", before: repo.files[0].content, after }],
    });
    expect(ok.ok).toBe(true);

    const bad = guardPatch(repo, {
      ...base,
      class: "minimal-edit",
      allowedRemovals: ["something else"],
      edits: [{ kind: "modify", path: "server.js", before: repo.files[0].content, after }],
    });
    expect(bad.ok).toBe(false);
    expect(bad.violations[0].reason).toBe("removed-line-not-allowed");
  });

  it("rejects creating a file that already exists", () => {
    const r = guardPatch(repo, { ...base, class: "additive", edits: [{ kind: "create", path: "server.js", content: "x" }] });
    expect(r.violations[0].reason).toBe("overwrites-existing-file");
  });

  it("rejects a modify whose before does not match the repo", () => {
    const r = guardPatch(repo, { ...base, class: "additive", edits: [{ kind: "modify", path: "server.js", before: "stale", after: "stale\nx" }] });
    expect(r.violations[0].reason).toBe("before-mismatch");
  });

  it("rejects a modify on a missing file", () => {
    const r = guardPatch(repo, { ...base, class: "additive", edits: [{ kind: "modify", path: "nope.js", before: "", after: "x" }] });
    expect(r.violations[0].reason).toBe("modify-missing-file");
  });

  it("rejects patches above the size cap", () => {
    const big = Array.from({ length: 5 }, (_, i) => `line${i}`).join("\n");
    const r = guardPatch(repo, { ...base, class: "additive", edits: [{ kind: "create", path: "big.js", content: big }] }, { maxAdded: 3 });
    expect(r.violations[0].reason).toBe("patch-too-large");
  });

  it("caps removals in a minimal edit", () => {
    const before = "a\nb\nc\nd\n";
    const r = guardPatch(
      { name: "x", files: [{ path: "f.js", content: before }] },
      { ...base, class: "minimal-edit", allowedRemovals: ["a", "b", "c", "d"], edits: [{ kind: "modify", path: "f.js", before, after: "" }] },
      { maxRemoved: 3 },
    );
    expect(r.ok).toBe(false);
    expect(r.violations.some((v) => v.reason === "patch-too-large")).toBe(true);
  });
});
