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
    expect(wf.content).toContain("node-version: 22");
    expect(wf.content).toContain("permissions:\n  contents: read");
    expect(wf.content).toContain("npm install --ignore-scripts"); // no lockfile in this repo
    expect(wf.content).toContain("npm test --if-present");
    expect(wf.content).toContain("npm audit --audit-level=high || true");
    expect(wf.content).toMatch(/uses: forstudies506-pixel\/Siidekick\/action@[0-9a-f]{40}\n/); // pinned, so ci-security stays clean
    expect(await ciWorkflow.detect({ repo: fixed })).toEqual([]);
  });

  it("uses the project's Node pin and npm ci when a lockfile exists", async () => {
    const pinned = [
      { path: "package.json", content: JSON.stringify({ name: "demo", engines: { node: ">=22.5" } }) },
      { path: "package-lock.json", content: "{}" },
    ];
    const patch = await ciWorkflow.fix!({ repo: repo(pinned) }, []);
    const wf = patch!.edits[0].kind === "create" ? patch!.edits[0].content : "";
    expect(wf).toContain('node-version: ">=22.5"');
    expect(wf).toContain("npm ci --ignore-scripts");
    const nvm = await ciWorkflow.fix!({ repo: repo([...pinned, { path: ".nvmrc", content: "22\n" }]) }, []);
    expect(nvm!.edits[0].kind === "create" && nvm!.edits[0].content).toContain("node-version-file: .nvmrc");
  });

  it("the workflow it adds passes Siidekick's own CI security check", async () => {
    const { registry } = await import("../src/registry");
    const ciSecurity = registry.find((c) => c.id === "ci-security")!;
    const patch = await ciWorkflow.fix!({ repo: repo(files) }, []);
    const fixed = applyPatch(repo(files), patch!);
    expect(await ciSecurity.detect({ repo: fixed })).toEqual([]);
  });
});
