import { describe, expect, it } from "vitest";
import { dependencyAudit } from "../src/checks/dependency-audit";
import { applyPatch } from "../src/apply";
import { guardPatch } from "../src/diffGuard";
import { runScan } from "../src/registry";
import type { RepoSnapshot } from "../src/types";

const PKG = `{
  "name": "demo",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.2",
    "lodash": "^4.17.20"
  }
}
`;

const LOCK = `{
  "name": "demo",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": { "name": "demo", "version": "1.0.0" },
    "node_modules/express": { "version": "4.18.2" },
    "node_modules/lodash": { "version": "4.17.20" },
    "node_modules/express/node_modules/ms": { "version": "2.0.0" }
  }
}
`;

interface MockVuln {
  name: string;
  version: string;
  id: string;
  aliases?: string[];
  summary?: string;
  fixed?: string[];
  /** Full OSV range events; overrides `fixed` when set. */
  events?: Array<Record<string, string>>;
}

/** OSV.dev stand-in: routes querybatch + vuln detail by URL. No network in tests. */
function osvMock(entries: MockVuln[]): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    if (url.endsWith("/v1/querybatch")) {
      const body = JSON.parse(String(init?.body)) as { queries: Array<{ package: { name: string }; version: string }> };
      const results = body.queries.map((q) => {
        const hit = entries.find((e) => e.name === q.package.name && e.version === q.version);
        return hit ? { vulns: [{ id: hit.id }] } : {};
      });
      return new Response(JSON.stringify({ results }), { status: 200 });
    }
    const id = decodeURIComponent(url.slice(url.lastIndexOf("/") + 1));
    const hit = entries.find((e) => e.id === id);
    if (!hit) return new Response("not found", { status: 404 });
    return new Response(
      JSON.stringify({
        id: hit.id,
        aliases: hit.aliases ?? [],
        summary: hit.summary ?? "",
        severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H" }],
        affected: [
          {
            package: { name: hit.name, ecosystem: "npm" },
            ranges: [{ type: "SEMVER", events: hit.events ?? [{ introduced: "0" }, ...(hit.fixed ?? []).map((f) => ({ fixed: f }))] }],
          },
        ],
      }),
      { status: 200 },
    );
  }) as typeof fetch;
}

const VULNS: MockVuln[] = [
  {
    name: "lodash",
    version: "4.17.20",
    id: "GHSA-p6mc-m468-83gg",
    aliases: ["CVE-2021-23337"],
    summary: "Command injection in lodash template compile",
    fixed: ["4.17.21"],
  },
  {
    name: "ms",
    version: "2.0.0",
    id: "GHSA-q7qp-9w3m-4v2c",
    summary: "ReDoS in ms",
    fixed: ["2.0.1"],
  },
];

const vuln: RepoSnapshot = {
  name: "vuln",
  files: [
    { path: "package.json", content: PKG },
    { path: "package-lock.json", content: LOCK },
  ],
};

/** Stand-in for `npm install` regenerating the lock after the package.json bump (tests may not run npm). */
function refreshLock(repo: RepoSnapshot): RepoSnapshot {
  return {
    name: repo.name,
    files: repo.files.map((f) =>
      f.path === "package-lock.json"
        ? { ...f, content: f.content.replace('"version": "4.17.20"', '"version": "4.17.21"').replace('"version": "2.0.0"', '"version": "2.0.1"') }
        : f,
    ),
  };
}

/** The fixer pins the vulnerable transitive ms@2.0.0 with an npm override; strip that block to compare the rest. */
const MS_OVERRIDE = /,(\r?\n)  "overrides": \{\r?\n    "ms": "\^2\.0\.1"\r?\n  \}/;
const withoutOverride = (s: string) => s.replace(MS_OVERRIDE, "");

describe("dependency-audit", () => {
  it("flags vulnerable direct and transitive packages with fixed versions and chains", async () => {
    const f = await dependencyAudit.detect({ repo: vuln, fetch: osvMock(VULNS) });
    expect(f).toHaveLength(2);

    const lodash = f.find((x) => x.evidence!.includes("lodash@"))!;
    expect(lodash.evidence).toBe("lodash@4.17.20 → fixed in 4.17.21 (GHSA-p6mc-m468-83gg / CVE-2021-23337) — direct dependency");
    expect(lodash).toMatchObject({ checkId: "dependency-audit", severity: "high", file: "package-lock.json" });
    expect(lodash.explanation).toContain("direct dependency");
    expect(lodash.explanation).toContain("Command injection");

    const ms = f.find((x) => x.evidence!.includes("ms@"))!;
    expect(ms.evidence).toBe("ms@2.0.0 → fixed in 2.0.1 (GHSA-q7qp-9w3m-4v2c) — transitive via express → ms");
    expect(ms.explanation).toContain("transitively");
  });

  it("passes when the lockfile has no vulnerable packages", async () => {
    expect(await dependencyAudit.detect({ repo: vuln, fetch: osvMock([]) })).toEqual([]);
  });

  it("without a package-lock.json audits the lowest version package.json allows, and the bump clears it", async () => {
    // No lockfile used to mean "nothing reported", which showed a false pass for a planted lodash pin.
    const noLock: RepoSnapshot = { name: "nolock", files: [{ path: "package.json", content: PKG }] };
    const ctx = { repo: noLock, fetch: osvMock(VULNS) };
    const f = await dependencyAudit.detect(ctx);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ file: "package.json", evidence: "lodash@4.17.20 → fixed in 4.17.21 (GHSA-p6mc-m468-83gg / CVE-2021-23337) — direct dependency" });
    expect(f[0].explanation).toContain("No package-lock.json");

    const patch = await dependencyAudit.fix!(ctx, f);
    const fixed = applyPatch(noLock, patch!);
    expect(await dependencyAudit.detect({ repo: fixed, fetch: osvMock(VULNS) })).toEqual([]);
  });

  it("never calls fetch when there is no lockfile and no versioned dependency", async () => {
    const pkg = `{ "name": "x", "dependencies": { "local": "file:../local", "any": "*" } }`;
    let called = false;
    const spy = (async () => {
      called = true;
      return new Response("{}", { status: 500 });
    }) as typeof fetch;
    expect(await dependencyAudit.detect({ repo: { name: "x", files: [{ path: "package.json", content: pkg }] }, fetch: spy })).toEqual([]);
    expect(await dependencyAudit.detect({ repo: { name: "y", files: [] }, fetch: spy })).toEqual([]);
    expect(called).toBe(false);
  });

  it("throws when OSV is unreachable, so the check errors instead of passing", async () => {
    const down = (async () => {
      throw new Error("ECONNREFUSED");
    }) as typeof fetch;
    await expect(dependencyAudit.detect({ repo: vuln, fetch: down })).rejects.toThrow(/OSV\.dev unreachable/);

    const report = await runScan({ repo: vuln, fetch: down }, [dependencyAudit]);
    expect(report.results[0].passed).toBe(false);
    expect(report.results[0].error).toContain("OSV.dev unreachable");
  });

  it("throws on a non-2xx OSV response", async () => {
    const broken = (async () => new Response("nope", { status: 503 })) as typeof fetch;
    await expect(dependencyAudit.detect({ repo: vuln, fetch: broken })).rejects.toThrow(/HTTP 503/);
  });

  it("fix bumps direct deps, pins transitive ones with an override, passes the guard, and the re-scan is clean after install", async () => {
    const ctx = { repo: vuln, fetch: osvMock(VULNS) };
    const patch = await dependencyAudit.fix!(ctx, await dependencyAudit.detect(ctx));
    expect(patch?.class).toBe("minimal-edit");
    // lodash is bumped in place; the last line before the new overrides block gains a comma.
    expect(patch?.allowedRemovals).toEqual([`"lodash": "^4.17.20"`, "}"]);
    expect(patch!.reason).toContain("verified only after npm install + tests pass");
    expect(guardPatch(vuln, patch!).ok).toBe(true);

    const fixed = applyPatch(vuln, patch!); // throws GuardRejected if the guard says no
    const pkg = fixed.files.find((x) => x.path === "package.json")!.content;
    expect(pkg).toContain(`"lodash": "^4.17.21"\n`);
    expect(pkg).toMatch(MS_OVERRIDE);
    expect(pkg).toContain(`"express": "^4.18.2",`); // untouched
    expect(await dependencyAudit.detect({ repo: refreshLock(fixed), fetch: osvMock(VULNS) })).toEqual([]);
  });

  it("keeps CRLF line endings when it bumps a dependency", async () => {
    const crlf: RepoSnapshot = {
      name: "crlf",
      files: [
        { path: "package.json", content: PKG.replace(/\n/g, "\r\n") },
        { path: "package-lock.json", content: LOCK.replace(/\n/g, "\r\n") },
      ],
    };
    const ctx = { repo: crlf, fetch: osvMock(VULNS) };
    const patch = await dependencyAudit.fix!(ctx, await dependencyAudit.detect(ctx));
    expect(patch).not.toBeNull();
    expect(guardPatch(crlf, patch!).ok).toBe(true);
    const after = applyPatch(crlf, patch!).files.find((f) => f.path === "package.json")!.content;
    expect(withoutOverride(after)).toBe(PKG.replace('"lodash": "^4.17.20"', '"lodash": "^4.17.21"').replace(/\n/g, "\r\n"));
    expect(after).not.toMatch(/[^\r]\n/);
  });

  it("picks the fix from the range that contains the installed version", async () => {
    const multi: MockVuln[] = [
      { name: "lodash", version: "4.17.20", id: "GHSA-multi", events: [{ introduced: "0" }, { fixed: "3.1.2" }, { introduced: "4.0.0" }, { fixed: "4.17.21" }] },
    ];
    const ctx = { repo: vuln, fetch: osvMock(multi) };
    const f = await dependencyAudit.detect(ctx);
    expect(f[0].evidence).toContain("fixed in 4.17.21");
    const patch = await dependencyAudit.fix!(ctx, f);
    expect(applyPatch(vuln, patch!).files.find((x) => x.path === "package.json")!.content).toContain('"lodash": "^4.17.21"');
  });

  it("bumps only the dependencies section, not a peerDependencies line above it", async () => {
    const pkg = `{
  "name": "demo",
  "peerDependencies": {
    "lodash": "^4.0.0"
  },
  "dependencies": {
    "express": "^4.18.2",
    "lodash": "^4.17.20"
  }
}
`;
    const repo: RepoSnapshot = { name: "peer", files: [{ path: "package.json", content: pkg }, { path: "package-lock.json", content: LOCK }] };
    const ctx = { repo, fetch: osvMock(VULNS) };
    const patch = await dependencyAudit.fix!(ctx, await dependencyAudit.detect(ctx));
    const after = applyPatch(repo, patch!).files.find((x) => x.path === "package.json")!.content;
    expect(withoutOverride(after)).toBe(pkg.replace('"lodash": "^4.17.20"', '"lodash": "^4.17.21"'));
  });

  it("skips past a fix version that a later advisory affects", async () => {
    // Real case: lodash 4.18.0 fixes the 4.17.x advisories but sits inside a newer range fixed in 4.18.1.
    const later: MockVuln = {
      name: "lodash",
      version: "4.17.21",
      id: "GHSA-later-0000-0000",
      events: [{ introduced: "4.17.21" }, { fixed: "4.17.22" }],
    };
    const repo: RepoSnapshot = { name: "chain", files: [{ path: "package.json", content: PKG }, { path: "package-lock.json", content: LOCK }] };
    const ctx = { repo, fetch: osvMock([...VULNS, later]) };
    const findings = await dependencyAudit.detect(ctx);
    expect(findings.find((f) => f.evidence.includes("lodash"))!.evidence).toContain("fixed in 4.17.22");
    const patch = await dependencyAudit.fix!(ctx, findings);
    const after = applyPatch(repo, patch!).files.find((x) => x.path === "package.json")!.content;
    expect(after).toContain('"lodash": "^4.17.22"');
  });

  it("bumps a dependency declared in a one-line dependencies object", async () => {
    const pkg = `{
  "name": "demo",
  "dependencies": { "express": "^4.18.2", "lodash": "4.17.20" }
}
`;
    const repo: RepoSnapshot = { name: "inline", files: [{ path: "package.json", content: pkg }, { path: "package-lock.json", content: LOCK }] };
    const ctx = { repo, fetch: osvMock(VULNS) };
    const patch = await dependencyAudit.fix!(ctx, await dependencyAudit.detect(ctx));
    expect(patch).not.toBeNull();
    expect(guardPatch(repo, patch!).ok).toBe(true);
    const after = applyPatch(repo, patch!).files.find((x) => x.path === "package.json")!.content;
    expect(withoutOverride(after)).toBe(pkg.replace('"lodash": "4.17.20"', '"lodash": "^4.17.21"'));
  });

  it("splits a large lockfile into querybatch requests of at most 1000", async () => {
    const pkgs: Record<string, { version: string }> = { "": { version: "1.0.0" } as { version: string } };
    for (let i = 0; i < 1500; i++) pkgs[`node_modules/p${i}`] = { version: "1.0.0" };
    pkgs["node_modules/lodash"] = { version: "4.17.20" };
    const lock = JSON.stringify({ name: "big", lockfileVersion: 3, packages: pkgs });
    const repo: RepoSnapshot = { name: "big", files: [{ path: "package.json", content: PKG }, { path: "package-lock.json", content: lock }] };
    const sizes: number[] = [];
    const base = osvMock(VULNS);
    const spy = (async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith("/v1/querybatch")) sizes.push((JSON.parse(String(init?.body)) as { queries: unknown[] }).queries.length);
      return base(input, init);
    }) as typeof fetch;
    const f = await dependencyAudit.detect({ repo, fetch: spy });
    // Two chunks for the 1501 installed packages, then one query re-checking lodash's bump target.
    expect(sizes).toEqual([1000, 501, 1]);
    expect(f.map((x) => x.title)).toEqual(["Vulnerable dependency: lodash"]);
  });
});
