import { describe, expect, it } from "vitest";
import { dependencyChains } from "../src/checks/dependency-audit.js";

describe("dependencyChains", () => {
  it("follows declared dependencies through hoisted entries", () => {
    const pkgs = {
      "": { dependencies: { express: "4.17.1" }, devDependencies: { vitest: "1" } },
      "node_modules/express": { version: "4.17.1", dependencies: { "body-parser": "1.19.0", qs: "6.7.0" } },
      "node_modules/body-parser": { version: "1.19.0", dependencies: { qs: "6.7.0" } },
      "node_modules/qs": { version: "6.7.0" },
      "node_modules/vitest": { version: "1.0.0" },
    };
    const chains = dependencyChains(pkgs);
    expect(chains.get("node_modules/express")).toEqual(["express"]);
    expect(chains.get("node_modules/qs")).toEqual(["express", "qs"]); // shortest path wins
    expect(chains.get("node_modules/body-parser")).toEqual(["express", "body-parser"]);
    expect(chains.get("node_modules/vitest")).toEqual(["vitest"]);
  });

  it("prefers a nested copy over the hoisted one, as Node does", () => {
    const pkgs = {
      "": { dependencies: { a: "1", debug: "4" } },
      "node_modules/a": { version: "1.0.0", dependencies: { debug: "2" } },
      "node_modules/a/node_modules/debug": { version: "2.6.9" },
      "node_modules/debug": { version: "4.3.4" },
    };
    const chains = dependencyChains(pkgs);
    expect(chains.get("node_modules/a/node_modules/debug")).toEqual(["a", "debug"]);
    expect(chains.get("node_modules/debug")).toEqual(["debug"]);
  });

  it("ignores cycles and unknown names", () => {
    const pkgs = {
      "": { dependencies: { a: "1", ghost: "1" } },
      "node_modules/a": { version: "1", dependencies: { b: "1" } },
      "node_modules/b": { version: "1", dependencies: { a: "1" } },
    };
    const chains = dependencyChains(pkgs);
    expect(chains.get("node_modules/b")).toEqual(["a", "b"]);
    expect(chains.size).toBe(2);
  });
});
