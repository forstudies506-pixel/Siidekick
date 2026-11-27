import { describe, expect, it, beforeEach } from "vitest";
import { cycloneDx, lockGraph } from "../src/deps/graph.js";
import { resetIntelCache } from "../src/deps/intel.js";
import { dependencyAudit } from "../src/checks/dependency-audit.js";
import type { RepoSnapshot } from "../src/types.js";

// express → body-parser → qs, all hoisted to the top level as npm does; jest is dev-only.
const LOCK = JSON.stringify({
  name: "shop",
  version: "1.0.0",
  lockfileVersion: 3,
  packages: {
    "": { name: "shop", version: "1.0.0", dependencies: { express: "^4.17.1" }, devDependencies: { jest: "^29.0.0" } },
    "node_modules/express": { version: "4.17.1", dependencies: { "body-parser": "1.19.0" }, integrity: "sha512-AAAA", resolved: "https://registry.npmjs.org/express/-/express-4.17.1.tgz" },
    "node_modules/body-parser": { version: "1.19.0", dependencies: { qs: "6.7.0" } },
    "node_modules/qs": { version: "6.7.0" },
    "node_modules/jest": { version: "29.0.0", dev: true },
  },
});
const PKG = `{\n  "name": "shop",\n  "dependencies": {\n    "express": "^4.17.1"\n  },\n  "devDependencies": {\n    "jest": "^29.0.0"\n  }\n}\n`;
const repo: RepoSnapshot = {
  name: "shop",
  files: [
    { path: "package.json", content: PKG },
    { path: "package-lock.json", content: LOCK },
    { path: "server.js", content: `const express = require("express");\n` },
  ],
};

/** OSV + KEV + EPSS in one fake: qs has a KEV-listed CVE, jest a moderate one. */
const feeds = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = String(input);
  const json = (b: unknown) => new Response(JSON.stringify(b), { status: 200 });
  if (url.endsWith("/querybatch")) {
    const q = JSON.parse(String(init!.body)).queries as { package: { name: string } }[];
    return json({ results: q.map((x) => ({ vulns: x.package.name === "qs" ? [{ id: "GHSA-qs" }] : x.package.name === "jest" ? [{ id: "GHSA-jest" }] : [] })) });
  }
  if (url.includes("/vulns/GHSA-qs")) return json({ id: "GHSA-qs", aliases: ["CVE-2022-24999"], summary: "qs prototype poisoning", database_specific: { severity: "HIGH" }, affected: [{ package: { name: "qs" }, ranges: [{ events: [{ introduced: "6.7.0" }, { fixed: "6.7.3" }] }] }] });
  if (url.includes("/vulns/GHSA-jest")) return json({ id: "GHSA-jest", aliases: ["CVE-2099-0001"], database_specific: { severity: "MODERATE" }, affected: [{ package: { name: "jest" }, ranges: [{ events: [{ introduced: "0" }, { fixed: "29.0.1" }] }] }] });
  if (url.includes("known_exploited")) return json({ vulnerabilities: [{ cveID: "CVE-2022-24999", dateAdded: "2024-01-02" }] });
  if (url.includes("api.first.org")) return json({ data: [{ cve: "CVE-2022-24999", epss: "0.12", percentile: "0.95" }] });
  return new Response("not found", { status: 404 });
}) as typeof fetch;

describe("dependency graph, exploit priority and SBOM", () => {
  beforeEach(() => resetIntelCache());

  it("gives hoisted packages their real chain and marks dev-only ones", () => {
    const g = lockGraph(LOCK)!;
    expect(g.nodes.get("node_modules/qs")!.chain).toEqual(["express", "body-parser", "qs"]);
    expect(g.nodes.get("node_modules/jest")!.dev).toBe(true);
  });

  it("puts the exploited transitive package first, as critical, and pins it with an override", async () => {
    const f = await dependencyAudit.detect({ repo, fetch: feeds });
    expect(f.map((x) => [x.title, x.severity])).toEqual([
      ["Actively exploited dependency: qs", "critical"],
      ["Vulnerable dependency: jest", "low"], // moderate, lowered one step: dev-only
    ]);
    expect(f[0].evidence).toContain("transitive via express → body-parser → qs");
    expect(f[0].explanation).toMatch(/Known Exploited Vulnerabilities.*EPSS gives CVE-2022-24999 a 12\.0% chance.*loads express in server\.js/s);
    const patch = await dependencyAudit.fix!({ repo, fetch: feeds }, f);
    expect(patch!.edits[0].kind === "modify" && JSON.parse(patch!.edits[0].after).overrides).toEqual({ qs: "^6.7.3" });
  });

  it("writes a CycloneDX SBOM with purls, scopes, hashes and the dependency graph", () => {
    const bom = cycloneDx(repo) as { components: { purl: string; scope: string; hashes?: unknown[] }[]; dependencies: { ref: string; dependsOn: string[] }[] };
    expect(bom.components.map((c) => `${c.purl} ${c.scope}`)).toEqual([
      "pkg:npm/express@4.17.1 required",
      "pkg:npm/body-parser@1.19.0 required",
      "pkg:npm/qs@6.7.0 required",
      "pkg:npm/jest@29.0.0 excluded",
    ]);
    expect(bom.components[0].hashes).toHaveLength(1);
    expect(bom.dependencies.find((d) => d.ref === "pkg:npm/shop@1.0.0")!.dependsOn).toEqual(["pkg:npm/express@4.17.1", "pkg:npm/jest@29.0.0"]);
  });
});
