import { describe, expect, it } from "vitest";
import { hallucinatedPackage } from "../src/checks/hallucinated-package";
import type { RepoFile } from "../src/types";

/** Registry stub: names in `missing` answer 404, everything else 200. Records every URL asked. */
function registry(missing: string[], status?: number) {
  const asked: string[] = [];
  const fetchFn = (async (input: string | URL | Request) => {
    const url = String(input);
    asked.push(url);
    if (status) return new Response(null, { status });
    const hit = missing.some((m) => url.endsWith(m.replace("/", "%2f")) || url.endsWith(`/${m}/json`));
    return new Response(null, { status: hit ? 404 : 200 });
  }) as typeof fetch;
  return { fetchFn, asked };
}

const pkg = (deps: Record<string, string>, name = "app"): string =>
  JSON.stringify({ name, version: "1.0.0", dependencies: deps }, null, 2);

const run = (files: RepoFile[], fetchFn: typeof fetch) =>
  hallucinatedPackage.detect({ repo: { name: "t", files }, fetch: fetchFn });

describe("hallucinated-package", () => {
  it("flags an unpublished npm name as critical, on its line", async () => {
    const { fetchFn } = registry(["expressjs-auth-helper"]);
    const content = pkg({ express: "^4.21.2", "expressjs-auth-helper": "^1.0.0" });
    const f = await run([{ path: "package.json", content }], fetchFn);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "critical", file: "package.json", line: 6 });
    expect(f[0].title).toContain("does not exist on npm");
  });

  it("passes when every dependency is published", async () => {
    const { fetchFn } = registry([]);
    expect(await run([{ path: "package.json", content: pkg({ express: "^4.21.2", lodash: "4.17.21" }) }], fetchFn)).toEqual([]);
  });

  it("skips workspace, file, git and alias specs, and the repo's own packages", async () => {
    const { fetchFn, asked } = registry([]);
    const files = [
      { path: "package.json", content: pkg({ "@me/engine": "*", a: "file:../a", b: "workspace:*", c: "github:x/y", d: "npm:lodash@4", e: "x/y" }) },
      { path: "packages/engine/package.json", content: pkg({}, "@me/engine") },
    ];
    expect(await run(files, fetchFn)).toEqual([]);
    expect(asked).toEqual([]);
  });

  it("looks each name up once across manifests, and ignores node_modules", async () => {
    const { fetchFn, asked } = registry([]);
    const files = [
      { path: "a/package.json", content: pkg({ express: "^4" }, "a") },
      { path: "b/package.json", content: pkg({ express: "^4" }, "b") },
      { path: "node_modules/x/package.json", content: pkg({ ghost: "1" }, "x") },
    ];
    await run(files, fetchFn);
    expect(asked).toEqual(["https://registry.npmjs.org/express"]);
  });

  it("words a missing scoped package as not on public npm, and trusts a private registry in .npmrc", async () => {
    const { fetchFn } = registry(["@acme/internal"]);
    const files = [{ path: "package.json", content: pkg({ "@acme/internal": "^1" }) }];
    const f = await run(files, fetchFn);
    expect(f[0]).toMatchObject({ severity: "medium", title: "@acme/internal is not on public npm" });
    const withRc = [...files, { path: ".npmrc", content: "@acme:registry=https://npm.acme.example/\n" }];
    expect(await run(withRc, fetchFn)).toEqual([]);
  });

  it("flags a published near miss of a popular name, but not the popular name itself", async () => {
    const { fetchFn } = registry([]);
    const f = await run([{ path: "package.json", content: pkg({ lodahs: "1", expres: "1", react: "18", preact: "10", color: "4" }) }], fetchFn);
    expect(f.map((x) => x.title).sort()).toEqual([
      "expres looks like a misspelling of express",
      "lodahs looks like a misspelling of lodash",
    ]);
    expect(f.every((x) => x.severity === "high")).toBe(true);
  });

  it("checks requirements.txt against PyPI with normalised names", async () => {
    const { fetchFn, asked } = registry(["fastapi-secure-auth"]);
    const content = "# deps\nFastAPI==0.110\nfastapi_secure_auth>=1.0\n-r other.txt\ngit+https://x/y.git\n";
    const f = await run([{ path: "requirements.txt", content }], fetchFn);
    expect(asked.sort()).toEqual(["https://pypi.org/pypi/fastapi-secure-auth/json", "https://pypi.org/pypi/fastapi/json"]);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ line: 3, title: "fastapi-secure-auth does not exist on PyPI" });
  });

  it("throws instead of passing when the registry cannot answer", async () => {
    const { fetchFn } = registry([], 429);
    await expect(run([{ path: "package.json", content: pkg({ express: "^4" }) }], fetchFn)).rejects.toThrow(/429/);
  });
});
