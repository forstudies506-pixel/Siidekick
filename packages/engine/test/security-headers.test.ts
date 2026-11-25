import { describe, expect, it } from "vitest";
import { securityHeaders } from "../src/checks/security-headers";
import { applyPatch } from "../src/apply";
import type { RepoSnapshot } from "../src/types";

const CJS_APP = `const express = require('express');
const app = express();
app.use(express.json());
app.listen(3000);
`;

const vuln: RepoSnapshot = { name: "vuln", files: [{ path: "server.js", content: CJS_APP }] };

describe("security-headers", () => {
  it("flags an Express app with no helmet and no header code", async () => {
    const f = await securityHeaders.detect({ repo: vuln });
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ checkId: "security-headers", severity: "high", file: "server.js", line: 2 });
    expect(f[0].explanation).toContain("reduces");
  });

  it("passes when helmet is used, or when headers are set explicitly", async () => {
    const helmetRepo: RepoSnapshot = {
      name: "helmet",
      files: [
        {
          path: "server.js",
          content: `const express = require('express');\nconst helmet = require('helmet');\nconst app = express();\napp.use(helmet());\n`,
        },
      ],
    };
    expect(await securityHeaders.detect({ repo: helmetRepo })).toEqual([]);

    const headerRepo: RepoSnapshot = {
      name: "headers",
      files: [
        {
          path: "server.js",
          content: `const app = require('express')();\napp.use((req, res, next) => {\n  res.setHeader('X-Frame-Options', 'DENY');\n  next();\n});\n`,
        },
      ],
    };
    expect(await securityHeaders.detect({ repo: headerRepo })).toEqual([]);
  });

  it("fix adds the helper and wiring, passes the guard, and the re-scan is clean", async () => {
    const ctx = { repo: vuln };
    const patch = await securityHeaders.fix!(ctx, await securityHeaders.detect(ctx));
    expect(patch?.class).toBe("additive");
    const fixed = applyPatch(vuln, patch!);

    const server = fixed.files.find((x) => x.path === "server.js")!.content.split("\n");
    expect(server[2]).toBe("require('./security')(app);"); // right after the app line
    const helper = fixed.files.find((x) => x.path === "security.js")!;
    expect(helper.content).toContain(`res.setHeader("Content-Security-Policy", "default-src 'self'")`);
    expect(helper.content).toContain(`res.setHeader("X-Frame-Options", "DENY")`);
    expect(helper.content).toContain("res.removeHeader(\"X-Powered-By\")");
    expect(await securityHeaders.detect({ repo: fixed })).toEqual([]);
  });

  it("fix uses ESM import form and a sibling helper for an ESM app in a subdirectory", async () => {
    const esm: RepoSnapshot = {
      name: "esm",
      files: [
        { path: "package.json", content: '{ "name": "app", "type": "module" }' },
        {
          path: "src/app.js",
          content: `import express from 'express';\nconst app = express();\napp.listen(3000);\n`,
        },
      ],
    };
    const ctx = { repo: esm };
    const patch = await securityHeaders.fix!(ctx, await securityHeaders.detect(ctx));
    const fixed = applyPatch(esm, patch!);

    const appFile = fixed.files.find((x) => x.path === "src/app.js")!.content;
    expect(appFile).toContain("import security from './security.js';");
    expect(appFile).not.toContain("require(");
    expect(fixed.files.find((x) => x.path === "src/security.js")?.content).toContain("export default");
    expect(await securityHeaders.detect({ repo: fixed })).toEqual([]);
  });

  it("does not count headers mentioned only in docs", async () => {
    const f = await securityHeaders.detect({ repo: { ...vuln, files: [...vuln.files, { path: "README.md", content: "We should add helmet and Content-Security-Policy." }] } });
    expect(f.length).toBeGreaterThan(0);
  });

  describe("Python and serverless apps", () => {
    const scan = (files: { path: string; content: string }[]) => securityHeaders.detect({ repo: { name: "r", files } });

    it("passes a Django project with the clickjacking middleware, and Flask with Talisman", async () => {
      const settings = `MIDDLEWARE = [\n    "django.middleware.security.SecurityMiddleware",\n    "django.middleware.clickjacking.XFrameOptionsMiddleware",\n]\n`;
      expect(await scan([{ path: "mysite/settings.py", content: settings }, { path: "manage.py", content: "import django" }])).toEqual([]);
      const flask = `from flask import Flask\nfrom flask_talisman import Talisman\napp = Flask(__name__)\nTalisman(app)\n`;
      expect(await scan([{ path: "app.py", content: flask }])).toEqual([]);
    });

    it("flags a bare Flask app at its server line, with Python advice and no Express patch", async () => {
      const files = [{ path: "app.py", content: `from flask import Flask\napp = Flask(__name__)\n` }];
      const [f] = await scan(files);
      expect(f).toMatchObject({ file: "app.py", line: 2 });
      expect(f.evidence).toMatch(/Talisman/);
      expect(f.evidence).not.toMatch(/helmet/);
      expect(securityHeaders.fix!({ repo: { name: "r", files } }, [])).toBeNull();
    });

    it("flags serverless functions with host-config advice, and passes when vercel.json sets headers", async () => {
      const fn = { path: "api/users.ts", content: "export default function handler() {}" };
      const [f] = await scan([fn]);
      expect(f.evidence).toMatch(/vercel\.json/);
      const vercel = { path: "vercel.json", content: JSON.stringify({ headers: [{ source: "/(.*)", headers: [{ key: "X-Frame-Options", value: "DENY" }] }] }) };
      expect(await scan([fn, vercel])).toEqual([]);
    });
  });
});
