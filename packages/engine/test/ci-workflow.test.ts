import { describe, expect, it } from "vitest";
import { ciWorkflow } from "../src/checks/ci-workflow";
import { applyPatch } from "../src/apply";
import type { RepoSnapshot } from "../src/types";

const files = [
  { path: "package.json", content: JSON.stringify({ name: "demo" }) },
  { path: "server.js", content: "const app = require('./app');\n" },
];

function repo(files: typeof files): RepoSnapshot { return { name: "demo", files }; }

describe("ci-workflow", () => {
  it("fails when no .github/workflows/*.yml exists", async () => {
    const f = await ciWorkflow.detect({ repo: repo(files) });
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "medium", checkId: "ci-workflow" });
  });

  it("passes when a workflow yml exists", async () => {
    const f = await ciWorkflow.detect({ repo: repo([...files, { path: ".github/workflows/ci.yml", content: "name: ci\n" }]) });
    expect(f).toEqual([]);
  });

  it("fix creates siidekick.yml, applies via guard, re-detect is clean", async () => {
    const ctx = { repo: repo(files) };
    const patch = await ciWorkflow.fix!(ctx, await ciWorkflow.detect(ctx));
    expect(patch?.class).toBe("additive");
    const fixed = applyPatch(repo(files), patch!);
    const wf = fixed.files.find((x) => x.path === ".github/workflows/siidekick.yml")!;
    expect(wf.content).toContain("node-version: 20");
    expect(wf.content).toContain("npm ci");
    expect(wf.content).toContain("npm test --if-present");
    expect(wf.content).toContain("npm audit --audit-level=high || true");
    expect(await ciWorkflow.detect({ repo: fixed })).toEqual([]);
  });
});
