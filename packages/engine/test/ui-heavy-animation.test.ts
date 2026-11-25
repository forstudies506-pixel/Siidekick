import { describe, expect, it } from "vitest";
import { uiHeavyAnimation } from "../src/checks/ui-heavy-animation";
import type { RepoSnapshot } from "../src/types";

const cssWithKeyframes = `.box { position: absolute; }
@keyframes drift {
  0% { left: 0; top: 0; }
  100% { left: 100px; top: 100px; }
}
`;

const cssClean = `.box { position: absolute; }
@keyframes fade {
  0% { opacity: 0; transform: translateX(0); }
  100% { opacity: 1; transform: translateX(10px); }
}
`;

const inlineScriptLines = Array.from({ length: 250 }, (_, i) => `var step${i} = ${i};`).join("\n");
const htmlWithInlineScript = `<!DOCTYPE html>
<html>
<head><style>@keyframes drift { 0% { width: 10px; } 100% { width: 20px; } }</style></head>
<body>
<script>
${inlineScriptLines}
</script>
</body>
</html>
`;

const htmlClean = `<!DOCTYPE html>
<html>
<head><script src="/app.js"></script></head>
<body>
<script>
var a = 1;
var b = 2;
</script>
</body>
</html>
`;

function repo(files: { path: string; content: string }[]): RepoSnapshot { return { name: "demo", files }; }

describe("ui-heavy-animation", () => {
  it("flags keyframes animating layout properties and inline scripts over 200 lines", async () => {
    const f = await uiHeavyAnimation.detect({ repo: repo([{ path: "style.css", content: cssWithKeyframes }, { path: "index.html", content: htmlWithInlineScript }]) });
    expect(f.some((x) => x.file === "style.css" && x.title.includes("drift"))).toBe(true);
    expect(f.some((x) => x.file === "index.html" && x.title.includes("drift"))).toBe(true);
    expect(f.some((x) => x.title === "Inline script over 200 lines")).toBe(true);
    expect(f.every((x) => x.severity === "low" && x.checkId === "ui-heavy-animation")).toBe(true);
  });

  it("passes on keyframes using only transform/opacity", async () => {
    const f = await uiHeavyAnimation.detect({ repo: repo([{ path: "style.css", content: cssClean }]) });
    expect(f).toEqual([]);
  });

  it("passes on clean html with external script and small inline script", async () => {
    const f = await uiHeavyAnimation.detect({ repo: repo([{ path: "index.html", content: htmlClean }]) });
    expect(f).toEqual([]);
  });

  it("ignores script tags with src", async () => {
    const big = "x".repeat(5000);
    const f = await uiHeavyAnimation.detect({ repo: repo([{ path: "index.html", content: `<html><script src="/big.js">\n${big}\n</script></html>` }]) });
    expect(f).toEqual([]);
  });

  it("only inspects css and html files", async () => {
    const f = await uiHeavyAnimation.detect({ repo: repo([{ path: "app.js", content: `@keyframes x { 0% { left: 0; } 100% { left: 1px; } }` }]) });
    expect(f).toEqual([]);
  });
});
