import { describe, expect, it } from "vitest";
import { securityChecks } from "../src/checks/security";
import { applyPatch } from "../src/apply";
import { guardPatch } from "../src/diffGuard";
import type { RepoSnapshot } from "../src/types";

const APP = `const express = require('express');
const cors = require('cors');
const app = express();
app.use(cors());
app.post('/login', (req, res) => res.json({ ok: true }));
app.get('/admin/users', (req, res) => res.json({ users: [] }));
app.listen(3000);
`;

const PKG = `{
  "name": "all-fixers",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.2",
    "lodash": "^4.17.20"
  }
}
`;

const LOCK = `{
  "name": "all-fixers",
  "lockfileVersion": 3,
  "packages": {
    "": { "name": "all-fixers", "version": "1.0.0" },
    "node_modules/express": { "version": "4.18.2" },
    "node_modules/lodash": { "version": "4.17.20" }
  }
}
`;

/** Minimal OSV.dev stand-in so dependency-audit can run offline inside the sequence. */
const osvFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = String(input);
  if (url.endsWith("/v1/querybatch")) {
    const body = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version: string }> };
    const results = body.queries.map((q) =>
      q.package.name === "lodash" && q.version === "4.17.20" ? { vulns: [{ id: "GHSA-mock-lodash-0001" }] } : {},
    );
    return new Response(JSON.stringify({ results }), { status: 200 });
  }
  const id = decodeURIComponent(url.slice(url.lastIndexOf("/") + 1));
  return new Response(
    JSON.stringify({
      id,
      aliases: [],
      summary: "Mock advisory",
      affected: [{ package: { name: "lodash", ecosystem: "npm" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "4.17.21" }] }] }],
    }),
    { status: 200 },
  );
}) as typeof fetch;

/** Stand-in for `npm install` regenerating the lock after the package.json bump (tests may not run npm). */
function refreshLock(repo: RepoSnapshot): RepoSnapshot {
  return {
    name: repo.name,
    files: repo.files.map((f) =>
      f.path === "package-lock.json" ? { ...f, content: f.content.replace('"version": "4.17.20"', '"version": "4.17.21"') } : f,
    ),
  };
}

// The original seven fixable security checks; the data-flow and config families have their own tests.
const core = securityChecks.slice(0, 7);

describe("security checks barrel", () => {
  it("registers the security checks with their declared severities and modes", () => {
    expect(core.map((c) => ({ id: c.id, severity: c.severity, mode: c.mode }))).toEqual([
      { id: "secrets-in-repo", severity: "critical", mode: "auto" },
      { id: "security-headers", severity: "high", mode: "auto" },
      { id: "rate-limit", severity: "high", mode: "auto" },
      { id: "open-cors", severity: "medium", mode: "auto" },
      { id: "auth-on-endpoints", severity: "critical", mode: "auto" },
      { id: "sql-string-concat", severity: "critical", mode: "report" },
      { id: "dependency-audit", severity: "high", mode: "auto" },
    ]);
  });

  it("applies every security fixer in sequence and the guard accepts each patch", async () => {
    // One fixture drives fixers 1-4 and 6: an Express app (headers, rate limit, CORS, admin auth)
    // plus a lockfile with a vulnerable direct dep. sql-string-concat is report-only, so it is
    // skipped by mode and the fixture contains no string-built SQL.
    let repo: RepoSnapshot = {
      name: "all",
      files: [
        { path: "server.js", content: APP },
        { path: "package.json", content: PKG },
        { path: "package-lock.json", content: LOCK },
      ],
    };
    const ctx = () => ({ repo, fetch: osvFetch });

    const before = Object.fromEntries(
      await Promise.all(core.map(async (c) => [c.id, (await c.detect(ctx())).length])),
    );
    expect(before).toEqual({
      "secrets-in-repo": 0,
      "security-headers": 1,
      "rate-limit": 1,
      "open-cors": 1,
      "auth-on-endpoints": 1,
      "sql-string-concat": 0,
      "dependency-audit": 1,
    });

    for (const check of core) {
      const findings = await check.detect(ctx());
      if (findings.length === 0 || check.mode === "report") continue;
      const patch = await check.fix!(ctx(), findings);
      expect(patch, `${check.id} produced no patch`).not.toBeNull();
      expect(guardPatch(repo, patch!).ok, `${check.id} patch rejected by guard`).toBe(true);
      repo = applyPatch(repo, patch!); // also throws GuardRejected if the guard says no
      if (check.id === "dependency-audit") repo = refreshLock(repo);
    }

    const after = await Promise.all(core.map((c) => c.detect(ctx())));
    after.forEach((findings, i) => expect(findings, `${core[i].id} still failing`).toEqual([]));
  });
});
