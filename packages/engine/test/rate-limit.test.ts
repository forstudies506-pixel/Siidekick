import { describe, expect, it } from "vitest";
import { rateLimitCheck } from "../src/checks/rate-limit";
import { applyPatch } from "../src/apply";
import type { RepoSnapshot } from "../src/types";

const LOGIN_APP = `const express = require('express');
const app = express();
app.post('/login', (req, res) => res.json({ ok: true }));
app.post('/reset', (req, res) => res.json({ ok: true }));
app.listen(3000);
`;

const vuln: RepoSnapshot = { name: "vuln", files: [{ path: "server.js", content: LOGIN_APP }] };

describe("rate-limit", () => {
  it("flags auth routes with no limiter", async () => {
    const f = await rateLimitCheck.detect({ repo: vuln });
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ checkId: "rate-limit", severity: "high", file: "server.js", line: 2 });
    expect(f[0].evidence).toContain("/login");
    expect(f[0].evidence).toContain("/reset");
  });

  it("passes when a limiter is present, and when no auth routes exist", async () => {
    const limited: RepoSnapshot = {
      name: "limited",
      files: [
        {
          path: "server.js",
          content: `const express = require('express');\nconst { rateLimit } = require('express-rate-limit');\nconst app = express();\napp.use(rateLimit({ windowMs: 900000 }));\napp.post('/login', (req, res) => res.json({ ok: true }));\n`,
        },
      ],
    };
    expect(await rateLimitCheck.detect({ repo: limited })).toEqual([]);

    const noAuth: RepoSnapshot = {
      name: "no-auth",
      files: [
        {
          path: "server.js",
          content: `const express = require('express');\nconst app = express();\napp.get('/health', (req, res) => res.json({ ok: true }));\n`,
        },
      ],
    };
    expect(await rateLimitCheck.detect({ repo: noAuth })).toEqual([]);
  });

  it("fix adds the limiter helper and wiring, passes the guard, and the re-scan is clean", async () => {
    const ctx = { repo: vuln };
    const patch = await rateLimitCheck.fix!(ctx, await rateLimitCheck.detect(ctx));
    expect(patch?.class).toBe("additive");
    const fixed = applyPatch(vuln, patch!);

    const server = fixed.files.find((x) => x.path === "server.js")!.content.split("\n");
    expect(server[2]).toBe(`app.use(['/login', '/signup', '/register', '/reset'], require('./rateLimit')());`);
    const helper = fixed.files.find((x) => x.path === "rateLimit.js")!;
    expect(helper.content).toContain("15 * 60 * 1000");
    expect(helper.content).toContain("RATE_LIMIT_MAX");
    expect(helper.content).toContain("res.status(429).json(");
    expect(await rateLimitCheck.detect({ repo: fixed })).toEqual([]);
  });

  it("fix uses the ESM import form for an ESM app", async () => {
    const esm: RepoSnapshot = {
      name: "esm",
      files: [
        { path: "package.json", content: '{ "name": "app", "type": "module" }' },
        {
          path: "src/app.js",
          content: `import express from 'express';\nconst app = express();\napp.post('/login', (req, res) => res.json({ ok: true }));\n`,
        },
      ],
    };
    const ctx = { repo: esm };
    const patch = await rateLimitCheck.fix!(ctx, await rateLimitCheck.detect(ctx));
    const fixed = applyPatch(esm, patch!);

    const appFile = fixed.files.find((x) => x.path === "src/app.js")!.content;
    expect(appFile).toContain("import rateLimit from './rateLimit.js';");
    expect(appFile).not.toContain("require(");
    expect(fixed.files.find((x) => x.path === "src/rateLimit.js")?.content).toContain("export default");
    expect(await rateLimitCheck.detect({ repo: fixed })).toEqual([]);
  });
});
