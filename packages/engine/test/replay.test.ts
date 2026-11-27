import { describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";
import { applyPatch } from "../src/apply.js";
import { guardPatch } from "../src/diffGuard.js";
import { loadRepo } from "../src/loadRepo.js";
import { registry } from "../src/registry.js";
import { replayDemo } from "../src/replay.js";
import type { RepoSnapshot } from "../src/types.js";

const root = fileURLToPath(new URL("../../../", import.meta.url));

// Every auto fix the guard accepts, except the dependency bump (needs OSV over the network).
async function patched(repo: RepoSnapshot): Promise<RepoSnapshot> {
  for (const check of registry) {
    if (check.id === "dependency-audit" || check.mode === "report" || !check.fix) continue;
    const findings = await check.detect({ repo });
    if (findings.length === 0) continue;
    const patch = await check.fix({ repo }, findings);
    if (patch && guardPatch(repo, patch).ok) repo = applyPatch(repo, patch);
  }
  return repo;
}

describe("replayDemo", () => {
  it("replays each attack on the original and the patched demo shop", async () => {
    const before = await loadRepo(root + "demo/vulnerable-app");
    const after = await patched(before);
    const report = await replayDemo({ before, after, runtimeDir: root + "node_modules" });
    expect(report.available, report.reason).toBe(true);

    const verdict = Object.fromEntries(report.attacks.map((a) => [a.id, a.verdict]));
    expect(verdict).toEqual({
      "sqli-dump": "still-open", // report-only: the owner rewrites the query
      "admin-open": "blocked",
      "brute-force": "blocked",
      "cors-read": "blocked",
      clickjack: "blocked",
      "fake-payment": "blocked", // the fix wires a Razorpay signature check into the route
      "secret-read": "blocked",
    });
    const pay = report.attacks.find((a) => a.id === "fake-payment")!;
    expect(pay.before.detail).toContain("pass issued for a payment that never happened");
    expect(pay.after.detail).toMatch(/^400/);
    expect(pay.control?.ok, "a correctly signed payment still gets its pass").toBe(true);
    for (const a of report.attacks) {
      expect(a.before.exploited, a.id).toBe(true);
      if (a.control) expect(a.control.ok, a.control.label).toBe(true);
    }
    // Evidence is counts only; no leaked password text reaches the report.
    expect(JSON.stringify(report)).not.toMatch(/password123|welcome2024|fest2025|pk_demo_/);

    expect(report.tests?.ran).toBe(true);
    expect(report.tests?.failed).toBe(0);

    const path = Object.fromEntries(report.paths.map((p) => [p.id, p]));
    expect(path["steal-accounts"].openBefore).toBe(true);
    expect(path["steal-accounts"].openAfter).toBe(true);
    expect(path["steal-accounts"].cutBy).toEqual(["sql-string-concat"]);
    expect(path["guess-accounts"].openBefore).toBe(true);
    expect(path["guess-accounts"].openAfter).toBe(false);
    expect(path["guess-accounts"].cutBy).toEqual(["auth-on-endpoints", "rate-limit"]);
  }, 30_000);

  it("fails soft when the app cannot boot", async () => {
    const broken: RepoSnapshot = { name: "x", files: [{ path: "server.js", content: "process.exit(3)\n" }] };
    const report = await replayDemo({ before: broken, after: broken, runtimeDir: root + "node_modules" });
    expect(report.available).toBe(false);
    expect(report.reason).toMatch(/replay unavailable here/);
  }, 15_000);
});
