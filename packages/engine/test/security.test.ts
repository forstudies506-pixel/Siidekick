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
app.listen(3000);
`;

describe("security checks barrel", () => {
  it("registers the Phase A checks with their declared severities and modes", () => {
    expect(securityChecks.map((c) => ({ id: c.id, severity: c.severity, mode: c.mode }))).toEqual([
      { id: "secrets-in-repo", severity: "critical", mode: "auto" },
      { id: "security-headers", severity: "high", mode: "auto" },
      { id: "rate-limit", severity: "high", mode: "auto" },
      { id: "open-cors", severity: "medium", mode: "auto" },
    ]);
  });

  it("applies every security fixer in sequence and the guard accepts each patch", async () => {
    let repo: RepoSnapshot = { name: "all", files: [{ path: "server.js", content: APP }] };

    const before = Object.fromEntries(
      await Promise.all(securityChecks.map(async (c) => [c.id, (await c.detect({ repo })).length])),
    );
    expect(before).toEqual({ "secrets-in-repo": 0, "security-headers": 1, "rate-limit": 1, "open-cors": 1 });

    for (const check of securityChecks) {
      const findings = await check.detect({ repo });
      if (findings.length === 0) continue;
      const patch = await check.fix!({ repo }, findings);
      expect(patch, `${check.id} produced no patch`).not.toBeNull();
      expect(guardPatch(repo, patch!).ok, `${check.id} patch rejected by guard`).toBe(true);
      repo = applyPatch(repo, patch!); // also throws GuardRejected if the guard says no
    }

    const after = await Promise.all(securityChecks.map((c) => c.detect({ repo })));
    after.forEach((findings, i) => expect(findings, `${securityChecks[i].id} still failing`).toEqual([]));
  });
});
