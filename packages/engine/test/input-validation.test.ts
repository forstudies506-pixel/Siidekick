import { describe, expect, it } from "vitest";
import { inputValidation } from "../src/checks/input-validation";
import { applyPatch } from "../src/apply";
import { guardPatch } from "../src/diffGuard";
import type { RepoSnapshot } from "../src/types";

const vulnerable = `const express = require('express');
const app = express();

app.post('/login', (req, res) => {
  const email = req.body.email;
  res.send(email);
});

module.exports = app;
`;

const validated = `const express = require('express');
const app = express();

app.post('/login', (req, res) => {
  const result = schema.safeParse(req.body);
  res.send(result);
});

module.exports = app;
`;

function repo(files: { path: string; content: string }[]): RepoSnapshot { return { name: "demo", files }; }

describe("input-validation", () => {
  it("fails when a route reads req.body without validation", async () => {
    const f = await inputValidation.detect({ repo: repo([{ path: "routes.js", content: vulnerable }]) });
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ checkId: "input-validation", severity: "high", file: "routes.js", line: 5 });
  });

  it("passes when the file calls a validation helper (.safeParse)", async () => {
    const f = await inputValidation.detect({ repo: repo([{ path: "routes.js", content: validated }]) });
    expect(f).toEqual([]);
  });

  it("ignores files under test/", async () => {
    const f = await inputValidation.detect({ repo: repo([{ path: "test/routes.js", content: vulnerable }]) });
    expect(f).toEqual([]);
  });

  it("ignores non-code files", async () => {
    const f = await inputValidation.detect({ repo: repo([{ path: "README.md", content: "req.body" }]) });
    expect(f).toEqual([]);
  });

  it("still fails when middleware/validate.js exists but the route does not call it", async () => {
    const f = await inputValidation.detect({ repo: repo([{ path: "routes.js", content: vulnerable }, { path: "middleware/validate.js", content: "module.exports = {};" }]) });
    expect(f).toHaveLength(1);
  });

  it("passes once the route calls validate()", async () => {
    const wired = vulnerable.replace("app.post('/login', (req", "app.post('/login', validate({ email: 'email' }), (req");
    expect(wired).not.toBe(vulnerable);
    const f = await inputValidation.detect({ repo: repo([{ path: "routes.js", content: wired }]) });
    expect(f).toEqual([]);
  });

  it("fix creates middleware/validate.js and the route stays flagged until the owner wires it", async () => {
    const ctx = { repo: repo([{ path: "routes.js", content: vulnerable }]) };
    const patch = await inputValidation.fix!(ctx, await inputValidation.detect(ctx));
    expect(patch).not.toBeNull();
    expect(patch!.class).toBe("additive");
    expect(guardPatch(ctx.repo, patch!).ok).toBe(true);
    const fixed = applyPatch(ctx.repo, patch!);
    const mw = fixed.files.find((x) => x.path === "middleware/validate.js")!;
    expect(mw.content).toContain("function validate");
    expect(await inputValidation.detect({ repo: fixed })).toHaveLength(1);
    expect(await inputValidation.fix!({ repo: fixed }, [])).toBeNull();
  });
});
