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
});
