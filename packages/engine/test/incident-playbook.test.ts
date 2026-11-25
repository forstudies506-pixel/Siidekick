import { describe, expect, it } from "vitest";
import { incidentPlaybook } from "../src/checks/incident-playbook";
import { applyPatch } from "../src/apply";
import { guardPatch } from "../src/diffGuard";
import type { RepoSnapshot } from "../src/types";

function repo(files: { path: string; content: string }[]): RepoSnapshot { return { name: "demo", files }; }

describe("incident-playbook", () => {
  it("fails when no playbook exists", async () => {
    const f = await incidentPlaybook.detect({ repo: repo([{ path: "app.js", content: "const x = 1;" }]) });
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ checkId: "incident-playbook", severity: "low" });
  });

  it("passes when SECURITY_PLAYBOOK.md exists", async () => {
    const f = await incidentPlaybook.detect({ repo: repo([{ path: "SECURITY_PLAYBOOK.md", content: "# playbook" }]) });
    expect(f).toEqual([]);
  });

  it("passes when an INCIDENT*.md exists", async () => {
    const f = await incidentPlaybook.detect({ repo: repo([{ path: "docs/INCIDENT-RESPONSE.md", content: "# incident" }]) });
    expect(f).toEqual([]);
  });

  it("passes when SECURITY.md exists", async () => {
    const f = await incidentPlaybook.detect({ repo: repo([{ path: "SECURITY.md", content: "# security" }]) });
    expect(f).toEqual([]);
  });

  it("fix creates SECURITY_PLAYBOOK.md with the five steps, passes guardPatch, applies, and re-detect is clean", async () => {
    const ctx = { repo: repo([{ path: "package.json", content: JSON.stringify({ name: "campuskart" }) }, { path: "app.js", content: "const x = 1;" }]) };
    const patch = await incidentPlaybook.fix!(ctx, await incidentPlaybook.detect(ctx));
    expect(patch).not.toBeNull();
    expect(patch!.class).toBe("additive");
    expect(guardPatch(ctx.repo, patch!).ok).toBe(true);
    const fixed = applyPatch(ctx.repo, patch!);
    const pb = fixed.files.find((x) => x.path === "SECURITY_PLAYBOOK.md")!.content;
    expect(pb).toContain("campuskart");
    for (const step of ["Detect", "Contain", "Eradicate", "Recover", "Review"]) {
      expect(pb).toContain(`## ${step}`);
    }
    expect(await incidentPlaybook.detect({ repo: fixed })).toEqual([]);
  });
});
