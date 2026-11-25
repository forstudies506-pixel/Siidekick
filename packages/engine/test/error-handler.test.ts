import { describe, expect, it } from "vitest";
import { errorHandler } from "../src/checks/error-handler";
import { applyPatch } from "../src/apply";
import type { RepoSnapshot } from "../src/types";

const without = `const express = require('express');
const app = express();

app.get('/', (req, res) => res.send('ok'));

module.exports = app;

if (require.main === module) {
  app.listen(process.env.PORT || 3000);
}
`;

const withHandler = `const express = require('express');
const app = express();

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong' });
});

module.exports = app;
`;

function repo(content: string): RepoSnapshot { return { name: "demo", files: [{ path: "server.js", content }] }; }

describe("error-handler", () => {
  it("fails when no (err, req, res, next) middleware exists", async () => {
    const f = await errorHandler.detect({ repo: repo(without) });
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "medium", checkId: "error-handler" });
  });

  it("passes when a four-argument error handler exists", async () => {
    const f = await errorHandler.detect({ repo: repo(withHandler) });
    expect(f).toEqual([]);
  });

  it("fix creates errorHandler.js, wires it before module.exports = app, applies via guard, re-detect is clean", async () => {
    const ctx = { repo: repo(without) };
    const patch = await errorHandler.fix!(ctx, await errorHandler.detect(ctx));
    expect(patch?.class).toBe("additive");
    const fixed = applyPatch(repo(without), patch!);
    const handler = fixed.files.find((x) => x.path === "errorHandler.js")!;
    expect(handler.content).toContain("console.error(err.stack)");
    expect(handler.content).toContain("{ error: 'Something went wrong' }");
    expect(handler.content).not.toContain("res.status(500).json({ error: err.stack })");
    const server = fixed.files.find((x) => x.path === "server.js")!.content;
    const lines = server.split("\n");
    const exportIdx = lines.findIndex((l) => /module\.exports\s*=\s*app/.test(l));
    expect(lines[exportIdx - 1]).toBe("app.use(require('./errorHandler'));");
    expect(await errorHandler.detect({ repo: fixed })).toEqual([]);
  });
});
