import { describe, expect, it } from "vitest";
import { secretsInRepo } from "../src/checks/secrets";
import { applyPatch } from "../src/apply";
import type { RepoSnapshot } from "../src/types";

const KEY = "sk_live_" + "4eC39HqLyjWDarjtT1zdp7dc"; // split so this file itself is not a literal hit
const repo: RepoSnapshot = {
  name: "demo",
  files: [
    { path: "server.js", content: `const express = require('express');\nconst STRIPE_API_KEY = '${KEY}';\nconst port = 3000;\n` },
    { path: "config.js", content: "module.exports = { dbPassword: process.env.DB_PASSWORD };\n" },
    { path: ".env.example", content: "API_KEY=your_key_here\n" },
  ],
};

describe("secrets-in-repo", () => {
  it("finds a hardcoded key and redacts the evidence", async () => {
    const f = await secretsInRepo.detect({ repo });
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ file: "server.js", line: 2, severity: "critical" });
    expect(f[0].evidence).not.toContain(KEY);
  });

  it("ignores env reads and placeholder examples", async () => {
    const f = await secretsInRepo.detect({ repo: { name: "x", files: repo.files.slice(1) } });
    expect(f).toEqual([]);
  });

  it("fix moves the key to an env var, passes the guard, and the re-scan is clean", async () => {
    const ctx = { repo };
    const patch = await secretsInRepo.fix!(ctx, await secretsInRepo.detect(ctx));
    expect(patch?.class).toBe("minimal-edit");
    const fixed = applyPatch(repo, patch!);
    const server = fixed.files.find((x) => x.path === "server.js")!.content;
    expect(server).toContain("const STRIPE_API_KEY = process.env.STRIPE_API_KEY;");
    expect(server).not.toContain(KEY);
    expect(fixed.files.find((x) => x.path === ".env.example")!.content).toContain("STRIPE_API_KEY=");
    expect(fixed.files.find((x) => x.path === ".gitignore")!.content).toMatch(/^\.env$/m);
    expect(await secretsInRepo.detect({ repo: fixed })).toEqual([]);
  });

  it("ignores made-up passwords in test files but still reports a vendor key there, without rewriting the test", async () => {
    const tests: RepoSnapshot = {
      name: "t",
      files: [
        { path: "test/app.test.js", content: "const password = 'password123';\nlogin({ password: 'wrong-password' });\n" },
        { path: "src/api.spec.ts", content: `const key = '${KEY}';\n` },
      ],
    };
    const f = await secretsInRepo.detect({ repo: tests });
    expect(f.map((x) => x.file)).toEqual(["src/api.spec.ts"]);
    expect(await secretsInRepo.fix!({ repo: tests }, f)).toBeNull();
  });
});

describe("scan skips Siidekick's own artifacts", () => {
  it("does not fail secrets for a key quoted in .siidekick/", async () => {
    const { runScan } = await import("../src/registry.js");
    const report = await runScan({ repo: { name: "a", files: [
      { path: ".siidekick/secrets-in-repo-1.patch", content: "-const API_KEY = 'abcd1234efgh5678wxyz';\n" },
      { path: "server.js", content: "const API_KEY = process.env.API_KEY;\n" },
    ] } });
    expect(report.results.find((r) => r.checkId === "secrets-in-repo")!.passed).toBe(true);
  });
});
