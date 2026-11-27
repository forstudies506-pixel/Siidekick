import { describe, expect, it } from "vitest";
import { runScan } from "../src/registry.js";
import { securityHeaders } from "../src/checks/security-headers.js";
import { secretsInRepo } from "../src/checks/secrets.js";
import { guardPatch } from "../src/diffGuard.js";
import { applyPatch } from "../src/apply.js";
import { buildChangeReport, changeReportHtml, changeReportMarkdown } from "../src/report.js";
import type { Patch, RepoSnapshot } from "../src/types.js";

const KEY = "sk_live_" + "9fA3kLm2Qx7Rt5Vw1Yz8Bc4D";
const original: RepoSnapshot = {
  name: "shop",
  files: [{ path: "server.js", content: `const express = require('express');\nconst app = express();\nconst STRIPE_KEY = '${KEY}';\napp.get('/', (req, res) => res.send('<b>hi</b>'));\napp.listen(3000);\n` }],
};

describe("change report", () => {
  it("shows each applied change with its diff, closed findings and labelled evidence, and redacts secrets", async () => {
    const checks = [securityHeaders, secretsInRepo];
    const before = await runScan({ repo: original }, checks);
    expect(before.risk).toBe("critical");
    let repo = original;
    const patches: { patch: Patch; guard: ReturnType<typeof guardPatch>; approved: boolean }[] = [];
    for (const c of checks) {
      const p = await c.fix!({ repo }, (await c.detect({ repo })) as never);
      const guard = guardPatch(repo, p!);
      patches.push({ patch: p!, guard, approved: c.id === "security-headers" });
      if (c.id === "security-headers") repo = applyPatch(repo, p!);
    }
    const after = await runScan({ repo }, checks);
    const report = buildChangeReport({ repo: "shop", original, before, after, patches, verification: { where: "AWS CodeBuild (isolated)", tests: { ok: true, passed: 4, failed: 0 } } });

    expect(report.changes).toHaveLength(1);
    expect(report.changes[0]).toMatchObject({ checkId: "security-headers", class: "additive" });
    expect(report.changes[0].closed).toHaveLength(1);
    expect(report.changes[0].evidence.map((e) => [e.kind, e.ok])).toEqual([["rescan", true], ["tests", true]]);
    expect(report.skipped.map((s) => s.why)).toEqual(["not approved"]);
    expect(report.checks.fixed).toEqual(["security-headers"]);
    expect(report.risk).toEqual({ before: "critical", after: "critical" });

    const md = changeReportMarkdown(report);
    expect(md).toContain("```diff");
    expect(md).toContain("AWS CodeBuild (isolated): the project's tests passed (4 passed, 0 failed)");
    expect(md).not.toContain(KEY);
    const html = changeReportHtml(report);
    expect(html).toContain("&lt;b&gt;hi&lt;/b&gt;"); // diff text is escaped
    expect(html).not.toContain(KEY);
  });
});
