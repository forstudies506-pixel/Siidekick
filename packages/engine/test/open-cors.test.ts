import { describe, expect, it } from "vitest";
import { openCors } from "../src/checks/open-cors";
import { applyPatch } from "../src/apply";
import type { RepoSnapshot } from "../src/types";

const CORS_APP = `const express = require('express');
const cors = require('cors');
const app = express();
app.use(cors());
app.use(cors({ origin: '*' }));
app.get('/data', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
});
app.listen(3000);
`;

const vuln: RepoSnapshot = { name: "vuln", files: [{ path: "server.js", content: CORS_APP }] };

describe("open-cors", () => {
  it("flags every wildcard origin form", async () => {
    const f = await openCors.detect({ repo: vuln });
    expect(f).toHaveLength(3); // bare cors(), origin: '*', header with '*'
    expect(f.map((x) => x.line)).toEqual([4, 5, 7]);
    expect(f[0]).toMatchObject({ checkId: "open-cors", severity: "medium", file: "server.js" });
  });

  it("passes when origins are explicitly restricted", async () => {
    const clean: RepoSnapshot = {
      name: "clean",
      files: [
        {
          path: "server.js",
          content: `const express = require('express');\nconst cors = require('cors');\nconst app = express();\napp.use(cors({ origin: process.env.ALLOWED_ORIGIN }));\napp.get('/data', (req, res) => {\n  res.setHeader('Access-Control-Allow-Origin', 'https://app.example.com');\n});\n`,
        },
      ],
    };
    expect(await openCors.detect({ repo: clean })).toEqual([]);
  });

  it("fix replaces each wildcard, passes the guard, and the re-scan is clean", async () => {
    const ctx = { repo: vuln };
    const patch = await openCors.fix!(ctx, await openCors.detect(ctx));
    expect(patch?.class).toBe("minimal-edit");
    expect(patch?.allowedRemovals).toHaveLength(3);
    expect(patch!.allowedRemovals).toContain(`app.use(cors());`);
    const fixed = applyPatch(vuln, patch!); // throws GuardRejected if the guard says no

    const server = fixed.files.find((x) => x.path === "server.js")!.content;
    expect(server).toContain(`app.use(cors({ origin: process.env.ALLOWED_ORIGIN || 'http://localhost:3000' }));`);
    expect(server).toContain(`res.setHeader('Access-Control-Allow-Origin', process.env.ALLOWED_ORIGIN || 'http://localhost:3000');`);
    expect(server).not.toContain(`'*'`);
    expect(await openCors.detect({ repo: fixed })).toEqual([]);
  });
});
