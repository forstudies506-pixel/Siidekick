import { describe, expect, it } from "vitest";
import { execFile } from "node:child_process";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { loadRepo } from "../src/loadRepo.js";
import { sameFiles } from "../src/replay.js";

const run = promisify(execFile);
const root = fileURLToPath(new URL("../../../", import.meta.url));
const engine = fileURLToPath(new URL("../", import.meta.url));

describe("sameFiles", () => {
  it("matches the demo against itself and rejects a one-byte change", async () => {
    const demo = await loadRepo(root + "demo/vulnerable-app");
    expect(sameFiles(demo, { ...demo, name: "other" })).toBe(true);
    const edited = { ...demo, files: demo.files.map((f, i) => (i === 0 ? { ...f, content: f.content + " " } : f)) };
    expect(sameFiles(demo, edited)).toBe(false);
    expect(sameFiles(demo, { ...demo, files: demo.files.slice(1) })).toBe(false);
  });
});

describe("siidekick fix --prove", () => {
  it("refuses any folder that is not the bundled demo, before scanning or booting it", async () => {
    const dir = await mkdtemp(join(tmpdir(), "siidekick-prove-"));
    try {
      await writeFile(join(dir, "package.json"), JSON.stringify({ name: "x", scripts: { start: "node server.js" } }));
      await writeFile(join(dir, "server.js"), "require('fs').writeFileSync(__dirname + '/RAN', 'yes');\n");
      const err = await run("npx", ["tsx", "src/cli.ts", "fix", dir, "--prove"], { cwd: engine }).catch((e) => e);
      expect(err.code).toBe(2);
      expect(String(err.stderr)).toMatch(/only runs on the bundled demo shop/);
      expect(String(err.stdout)).not.toMatch(/Score/);
      const after = await loadRepo(dir);
      expect(after.files.some((f) => f.path === "RAN")).toBe(false);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  }, 30_000);
});
