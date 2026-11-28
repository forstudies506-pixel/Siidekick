import { describe, expect, it } from "vitest";
import { healthEndpoint } from "../src/checks/health-endpoint";
import { applyPatch } from "../src/apply";
import type { RepoSnapshot } from "../src/types";

const withoutHealth = `const express = require('express');
const app = express();

app.get('/', (req, res) => res.send('ok'));

module.exports = app;
`;

const withHealthz = `const express = require('express');
const app = express();
app.get('/healthz', (req, res) => res.json({ ok: true }));

app.get('/', (req, res) => res.send('ok'));
module.exports = app;
`;

function repo(content: string): RepoSnapshot { return { name: "demo", files: [{ path: "server.js", content }] }; }

describe("health-endpoint", () => {
  it("fails when the Express app has no /health or /healthz route", async () => {
    const f = await healthEndpoint.detect({ repo: repo(withoutHealth) });
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "low", checkId: "health-endpoint" });
  });

  it("passes when /healthz exists", async () => {
    const f = await healthEndpoint.detect({ repo: repo(withHealthz) });
    expect(f).toEqual([]);
  });

  it("passes when a route table lists api/health", async () => {
    const repo: RepoSnapshot = {
      name: "x",
      files: [
        { path: "src/server.js", content: "const express = require('express');\nconst app = express();\napp.listen(3000);\n" },
        { path: "src/router.ts", content: 'const routes = [{ method: "GET", path: "api/health", handler: health }];\n' },
      ],
    };
    expect(await healthEndpoint.detect({ repo })).toEqual([]);
  });

  it("passes when /health exists", async () => {
    const f = await healthEndpoint.detect({ repo: repo("const express = require('express');\nconst app = express();\napp.get('/health', (req, res) => res.json({ ok: true }));\nmodule.exports = app;\n") });
    expect(f).toEqual([]);
  });

  it("fix inserts /health after the app line, applies via guard, re-detect is clean", async () => {
    const ctx = { repo: repo(withoutHealth) };
    const patch = await healthEndpoint.fix!(ctx, await healthEndpoint.detect(ctx));
    expect(patch?.class).toBe("additive");
    const fixed = applyPatch(repo(withoutHealth), patch!);
    const server = fixed.files.find((x) => x.path === "server.js")!.content;
    const lines = server.split("\n");
    const appLine = lines.findIndex((l) => /=\s*express\(\)/.test(l));
    expect(lines[appLine + 1]).toBe("app.get('/health', (req, res) => res.json({ ok: true }));");
    expect(await healthEndpoint.detect({ repo: fixed })).toEqual([]);
  });
});
