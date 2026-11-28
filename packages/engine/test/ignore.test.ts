import { describe, expect, it } from "vitest";
import { isIgnored, parseIgnore } from "../src/ignore";
import { runScan } from "../src/registry";
import type { Check } from "../src/types";

const rules = (t: string) => parseIgnore(t);

describe(".siidekickignore patterns", () => {
  it("matches directories at any depth, or at the root when anchored", () => {
    const r = rules("demo/\n/docs/samples/");
    expect(isIgnored("demo/app.js", r)).toBe(true);
    expect(isIgnored("tools/py/demo/shop/server.js", r)).toBe(true);
    expect(isIgnored("docs/samples/a.md", r)).toBe(true);
    expect(isIgnored("x/docs/samples/a.md", r)).toBe(false);
    expect(isIgnored("demolition.js", r)).toBe(false);
  });

  it("supports globs, ** and negation, with comments and blank lines skipped", () => {
    const r = rules("# fixtures\n\n*.min.js\ntest/**/fixtures/\npackages/engine/src/checks/\n!packages/engine/src/checks/keep.ts");
    expect(isIgnored("public/app.min.js", r)).toBe(true);
    expect(isIgnored("test/fixtures/a.js", r)).toBe(true);
    expect(isIgnored("test/unit/deep/fixtures/a.js", r)).toBe(true);
    expect(isIgnored("packages/engine/src/checks/secrets.ts", r)).toBe(true);
    expect(isIgnored("packages/engine/src/checks/keep.ts", r)).toBe(false);
    expect(isIgnored("src/app.js", r)).toBe(false);
  });
});

describe("runScan honours .siidekickignore", () => {
  const flagsBad: Check = {
    id: "flags-bad",
    group: "C-security",
    title: "No BAD",
    severity: "high",
    mode: "report",
    detect: (ctx) => ctx.repo.files.filter((f) => f.content.includes("BAD")).map((f) => ({ file: f.path, title: "bad", explanation: "bad" })),
  } as unknown as Check;

  it("skips ignored files and reports how many and which patterns", async () => {
    const report = await runScan(
      {
        repo: {
          name: "x",
          files: [
            { path: ".siidekickignore", content: "# demos\ndemo/\n" },
            { path: "demo/shop.js", content: "BAD" },
            { path: "src/app.js", content: "fine" },
          ],
        },
      },
      [flagsBad],
    );
    expect(report.results[0].passed).toBe(true);
    expect(report.ignored).toEqual({ files: 1, patterns: ["demo/"] });
  });

  it("leaves the report unchanged when there is no ignore file", async () => {
    const report = await runScan({ repo: { name: "x", files: [{ path: "demo/shop.js", content: "BAD" }] } }, [flagsBad]);
    expect(report.results[0].passed).toBe(false);
    expect(report.ignored).toBeUndefined();
  });
});
