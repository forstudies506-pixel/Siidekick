import { describe, expect, it } from "vitest";
import { readme } from "../src/checks/readme";
import { applyPatch } from "../src/apply";
import type { RepoSnapshot } from "../src/types";

const base = [
  { path: "package.json", content: JSON.stringify({ name: "demo-app", description: "A demo app used to test Siidekick's readme check.", scripts: { start: "node server.js", test: "node:test test/" } }) },
  { path: ".env.example", content: "API_KEY=\nDATABASE_URL=\nPORT=3000\n" },
  { path: "server.js", content: "const app = require('./app');\n" },
];

function repo(files: typeof base): RepoSnapshot { return { name: "demo", files }; }

describe("readme", () => {
  it("fails when README.md is missing", async () => {
    const f = await readme.detect({ repo: repo(base) });
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "low", file: "README.md", checkId: "readme" });
  });

  it("fails when README.md is under 200 chars", async () => {
    const f = await readme.detect({ repo: repo([...base, { path: "README.md", content: "too short" }]) });
    expect(f).toHaveLength(1);
  });

  it("passes when README.md is long enough", async () => {
    const f = await readme.detect({ repo: repo([...base, { path: "README.md", content: "x".repeat(250) }]) });
    expect(f).toEqual([]);
  });

  it("fix creates README from package.json and .env.example, applies cleanly, re-detect is clean", async () => {
    const ctx = { repo: repo(base) };
    const patch = await readme.fix!(ctx, await readme.detect(ctx));
    expect(patch?.class).toBe("additive");
    const fixed = applyPatch(repo(base), patch!);
    const file = fixed.files.find((x) => x.path === "README.md")!;
    expect(file.content).toContain("demo-app");
    expect(file.content).toContain("A demo app");
    expect(file.content).toContain("npm run start");
    expect(file.content).toContain("API_KEY=");
    expect(file.content).toContain("DATABASE_URL=");
    expect(await readme.detect({ repo: fixed })).toEqual([]);
  });
});
