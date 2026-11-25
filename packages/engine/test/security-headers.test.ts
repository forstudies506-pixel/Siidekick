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
});
