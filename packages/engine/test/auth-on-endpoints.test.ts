import { describe, expect, it } from "vitest";
import { authOnEndpoints } from "../src/checks/auth-on-endpoints";
import { applyPatch } from "../src/apply";
import { guardPatch } from "../src/diffGuard";
import type { RepoSnapshot } from "../src/types";

const VULN = `const express = require('express');
const app = express();
app.use(express.json());
app.get('/admin/users', (req, res) => res.json({ users: [] }));
app.post('/api/admin/settings', updateSettings);
app.get('/public/status', (req, res) => res.json({ ok: true }));
app.listen(3000);
`;

const CLEAN = `const express = require('express');
const app = express();
app.use('/admin', require('./adminAuth'));
app.use('/api/admin', verifyAdmin);
app.get('/admin/users', listUsers);
app.post('/api/admin/settings', updateSettings);
app.get('/administrator', (req, res) => res.json({})); // not an admin route
app.get('/public', (req, res) => res.json({ ok: true }));
app.listen(3000);
`;

const vuln: RepoSnapshot = { name: "vuln", files: [{ path: "server.js", content: VULN }] };
const clean: RepoSnapshot = { name: "clean", files: [{ path: "server.js", content: CLEAN }] };

describe("auth-on-endpoints", () => {
  it("flags admin routes with no named guard and no prior admin mount", async () => {
    const f = await authOnEndpoints.detect({ repo: vuln });
    expect(f).toHaveLength(2); // /admin/users and /api/admin/settings; /public/status is fine
    expect(f.map((x) => x.line)).toEqual([4, 5]);
    expect(f[0]).toMatchObject({ checkId: "auth-on-endpoints", severity: "critical", file: "server.js" });
    expect(f[0].evidence).toContain("/admin/users");
    expect(f[0].explanation).toContain("Cognito");
  });

  it("passes when a prior mount or a named handler protects the route", async () => {
    expect(await authOnEndpoints.detect({ repo: clean })).toEqual([]);
  });

  it("fix adds auth.js and the admin mounts, passes the guard, and the re-scan is clean", async () => {
    const ctx = { repo: vuln };
    const patch = await authOnEndpoints.fix!(ctx, await authOnEndpoints.detect(ctx));
    expect(patch?.class).toBe("additive");
    expect(guardPatch(vuln, patch!).ok).toBe(true);
    const fixed = applyPatch(vuln, patch!); // throws GuardRejected if the guard says no

    const server = fixed.files.find((x) => x.path === "server.js")!.content.split("\n");
    expect(server[2]).toBe(`app.use('/admin', require('./auth').requireAdmin);`); // right after the app line
    expect(server[3]).toBe(`app.use('/api/admin', require('./auth').requireAdmin);`);

    const auth = fixed.files.find((x) => x.path === "auth.js")!;
    expect(auth.content).toContain("Authorization");
    expect(auth.content).toContain("ADMIN_TOKEN");
    expect(auth.content).toContain("401");
    expect(auth.content).toContain("Cognito");
    expect(await authOnEndpoints.detect({ repo: fixed })).toEqual([]);
  });

  it("uses the ESM import form for an ESM app", async () => {
    const esm: RepoSnapshot = {
      name: "esm",
      files: [
        { path: "package.json", content: '{ "name": "app", "type": "module" }' },
        { path: "src/app.js", content: `import express from 'express';\nconst app = express();\napp.get('/admin/x', (req, res) => res.end());\napp.listen(3000);\n` },
      ],
    };
    const ctx = { repo: esm };
    const patch = await authOnEndpoints.fix!(ctx, await authOnEndpoints.detect(ctx));
    const fixed = applyPatch(esm, patch!);

    const appFile = fixed.files.find((x) => x.path === "src/app.js")!.content;
    expect(appFile).toContain(`import { requireAdmin } from './auth.js';`);
    expect(appFile).toContain(`app.use('/admin', requireAdmin);`);
    expect(appFile).not.toContain("require(");
    expect(fixed.files.find((x) => x.path === "src/auth.js")?.content).toContain("export { requireAdmin };");
    expect(await authOnEndpoints.detect({ repo: fixed })).toEqual([]);
  });

  it("does not count the endpoint handler itself or a bare 'admin' name as a guard", async () => {
    const content = `const app = require('express')();\napp.get('/admin/users', adminController.list);\napp.get('/admin/stats', getAdminStats);\napp.get('/admin/ok', requireAdmin, listUsers);\napp.get('/admin/pp', passport.authenticate('jwt'), listUsers);\n`;
    const f = await authOnEndpoints.detect({ repo: { name: "r", files: [{ path: "server.js", content }] } });
    expect(f.map((x) => x.line)).toEqual([2, 3]);
  });

  it("does not count a mount of an unguarded admin router as protection", async () => {
    const open = `const app = require('express')();\napp.use('/admin', adminRouter);\napp.get('/admin/x', (req, res) => res.end());\n`;
    const f = await authOnEndpoints.detect({ repo: { name: "r", files: [{ path: "server.js", content: open }] } });
    expect(f.map((x) => x.line)).toEqual([3]);
    const guarded = open.replace("adminRouter", "authenticate, adminRouter");
    expect(await authOnEndpoints.detect({ repo: { name: "r", files: [{ path: "server.js", content: guarded }] } })).toEqual([]);
  });
});
