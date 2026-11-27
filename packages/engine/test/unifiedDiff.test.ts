import { describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { unifiedFileDiff, patchArtifacts } from "../src/unifiedDiff.js";
import type { Patch, RepoSnapshot } from "../src/types.js";

/** git confined to `dir`: no parent repo is found and line endings stay as written (Windows checkouts default to CRLF). */
function git(dir: string, args: string[]): void {
  execFileSync("git", ["-c", "core.autocrlf=false", ...args], { cwd: dir, env: { ...process.env, GIT_CEILING_DIRECTORIES: dirname(dir) } });
}

function writeTree(dir: string, files: Record<string, string>) {
  for (const [p, c] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, p)), { recursive: true });
    writeFileSync(join(dir, p), c);
  }
}

/** Applies `diff` with real `git apply`, checks the result, then reverts it with `-R` and checks again. */
function roundTrip(before: Record<string, string>, after: Record<string, string>, diff: string) {
  const dir = mkdtempSync(join(tmpdir(), "siidekick-ud-"));
  try {
    writeTree(dir, before);
    writeFileSync(join(dir, "x.patch"), diff);
    git(dir, ["apply", "--check", "x.patch"]);
    git(dir, ["apply", "x.patch"]);
    for (const [p, c] of Object.entries(after)) expect(readFileSync(join(dir, p), "utf8")).toBe(c);
    git(dir, ["apply", "-R", "x.patch"]);
    for (const [p, c] of Object.entries(before)) expect(readFileSync(join(dir, p), "utf8")).toBe(c);
    for (const p of Object.keys(after)) if (!(p in before)) expect(existsSync(join(dir, p))).toBe(false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const lines = (n: number) => Array.from({ length: n }, (_, i) => `line ${i + 1}`).join("\n") + "\n";

describe("unifiedFileDiff", () => {
  it("returns empty string when nothing changed", () => {
    expect(unifiedFileDiff("a.js", "x\n", "x\n")).toBe("");
  });

  it("modifies a middle line with context", () => {
    const before = lines(10);
    const after = before.replace("line 5\n", "line 5\nadded\n");
    const d = unifiedFileDiff("src/a.js", before, after);
    expect(d).toContain("--- a/src/a.js\n+++ b/src/a.js\n");
    expect(d).toContain("@@ -3,6 +3,7 @@");
    roundTrip({ "src/a.js": before }, { "src/a.js": after }, d);
  });

  it("creates a new file", () => {
    const d = unifiedFileDiff("middleware/validate.js", null, "a\nb\n");
    expect(d).toContain("new file mode 100644\n--- /dev/null\n+++ b/middleware/validate.js\n@@ -0,0 +1,2 @@\n+a\n+b\n");
    roundTrip({}, { "middleware/validate.js": "a\nb\n" }, d);
  });

  it("handles a file with no trailing newline", () => {
    const before = "a\nb";
    const after = "a\nb\nc\n";
    const d = unifiedFileDiff("f.js", before, after);
    expect(d).toContain("\\ No newline at end of file");
    roundTrip({ "f.js": before }, { "f.js": after }, d);
  });

  it("keeps CRLF line endings", () => {
    const before = "a\r\nb\r\nc\r\n";
    const after = "a\r\nb\r\nnew\r\nc\r\n";
    roundTrip({ "w.js": before }, { "w.js": after }, unifiedFileDiff("w.js", before, after));
  });

  it("splits far-apart changes into separate hunks", () => {
    const before = lines(40);
    const after = before.replace("line 2\n", "line 2\nfirst\n").replace("line 35\n", "line 35\nsecond\n");
    const d = unifiedFileDiff("big.js", before, after);
    expect(d.match(/^@@ /gm)?.length).toBe(2);
    roundTrip({ "big.js": before }, { "big.js": after }, d);
  });

  it("merges close changes into one hunk", () => {
    const before = lines(20);
    const after = before.replace("line 5\n", "line 5\nx\n").replace("line 9\n", "line 9\ny\n");
    const d = unifiedFileDiff("c.js", before, after);
    expect(d.match(/^@@ /gm)?.length).toBe(1);
    roundTrip({ "c.js": before }, { "c.js": after }, d);
  });

  it("handles an insert at the very top", () => {
    const before = lines(5);
    const after = "top\n" + before;
    roundTrip({ "t.js": before }, { "t.js": after }, unifiedFileDiff("t.js", before, after));
  });
});

describe("patchArtifacts", () => {
  const original: RepoSnapshot = {
    name: "demo",
    files: [{ path: "server.js", content: "const app = express();\napp.listen(3000);\n" }],
  };
  const mid = "const app = express();\napp.use(require('./middleware/headers.js'));\napp.listen(3000);\n";
  const end = "const app = express();\napp.use(require('./middleware/headers.js'));\napp.get('/health', (q, r) => r.send('ok'));\napp.listen(3000);\n";
  const p1 = {
    id: "security-headers-1",
    checkId: "security-headers",
    title: "Add security headers",
    class: "additive",
    reason: "Sets standard headers.",
    edits: [
      { kind: "create", path: "middleware/headers.js", content: "module.exports = 1;\n" },
      { kind: "modify", path: "server.js", before: original.files[0].content, after: mid },
    ],
  } as Patch;
  const p2 = {
    id: "health-endpoint-1",
    checkId: "health-endpoint",
    title: "Add /health",
    class: "additive",
    reason: "Lets uptime monitors check the site.",
    edits: [{ kind: "modify", path: "server.js", before: mid, after: end }],
  } as Patch;

  it("emits one patch file per patch plus a log", () => {
    const files = patchArtifacts(original, [p1, p2]);
    expect(files.map((f) => f.path)).toEqual([
      ".siidekick/security-headers-1.patch",
      ".siidekick/health-endpoint-1.patch",
      "SIIDEKICK_LOG.md",
    ]);
    const log = files.find((f) => f.path === "SIIDEKICK_LOG.md")!.content;
    expect(log).toContain("security-headers-1");
    expect(log).toContain("Sets standard headers.");
    expect(log).toContain("git apply -R .siidekick/health-endpoint-1.patch");
    expect(log).toContain("additive");
    expect(log).toContain("middleware/headers.js");
  });

  it("chained patch files apply in order with real git apply and revert newest first", () => {
    const files = patchArtifacts(original, [p1, p2]);
    const dir = mkdtempSync(join(tmpdir(), "siidekick-pa-"));
    try {
      writeTree(dir, { "server.js": original.files[0].content });
      writeTree(dir, Object.fromEntries(files.map((f) => [f.path, f.content])));
      git(dir, ["apply", ".siidekick/security-headers-1.patch"]);
      git(dir, ["apply", ".siidekick/health-endpoint-1.patch"]);
      expect(readFileSync(join(dir, "server.js"), "utf8")).toBe(end);
      git(dir, ["apply", "-R", ".siidekick/health-endpoint-1.patch"]);
      git(dir, ["apply", "-R", ".siidekick/security-headers-1.patch"]);
      expect(readFileSync(join(dir, "server.js"), "utf8")).toBe(original.files[0].content);
      expect(existsSync(join(dir, "middleware/headers.js"))).toBe(false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("returns nothing for no patches", () => {
    expect(patchArtifacts(original, [])).toEqual([]);
  });

  it("masks the removed secret in the patch file and says to rotate it", () => {
    const key = "abcd1234efgh5678wxyz";
    const before = `const API_KEY = '${key}';\napp.listen(3000);\n`;
    const after = "const API_KEY = process.env.API_KEY;\napp.listen(3000);\n";
    const files = patchArtifacts({ name: "s", files: [{ path: "server.js", content: before }] }, [
      { id: "secrets-in-repo-1", checkId: "secrets-in-repo", title: "Move secret", class: "minimal-edit", reason: "r", allowedRemovals: [`const API_KEY = '${key}';`],
        edits: [{ kind: "modify", path: "server.js", before, after }] } as Patch,
    ]);
    for (const f of files) expect(f.content).not.toContain(key);
    expect(files[0].content).toContain("abcd…wxyz (20 chars)");
    expect(files.find((f) => f.path === "SIIDEKICK_LOG.md")!.content).toContain("rotate it");
  });

  it("makes unsafe patch ids into safe file names", () => {
    const files = patchArtifacts(original, [{ ...p1, id: "../evil id" } as Patch]);
    expect(files[0].path).toBe(".siidekick/---evil-id.patch");
    expect(files[0].path.split("/")).toHaveLength(2);
  });
});
