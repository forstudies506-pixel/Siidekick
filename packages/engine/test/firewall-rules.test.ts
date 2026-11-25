import { describe, expect, it } from "vitest";
import { firewallRules } from "../src/checks/firewall-rules";
import { applyPatch } from "../src/apply";
import { guardPatch } from "../src/diffGuard";
import type { RepoSnapshot } from "../src/types";

function repo(files: { path: string; content: string }[]): RepoSnapshot { return { name: "demo", files }; }

describe("firewall-rules", () => {
  it("fails when there is no security-group.yaml and no AWS::EC2::SecurityGroup or ufw rule", async () => {
    const f = await firewallRules.detect({ repo: repo([{ path: "app.js", content: "const x = 1;" }]) });
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ checkId: "firewall-rules", severity: "medium" });
  });

  it("passes when infra/security-group.yaml exists", async () => {
    const f = await firewallRules.detect({ repo: repo([{ path: "infra/security-group.yaml", content: "Resources:\n  AppSecurityGroup:\n    Type: AWS::EC2::SecurityGroup\n" }]) });
    expect(f).toEqual([]);
  });

  it("passes when a file declares AWS::EC2::SecurityGroup", async () => {
    const f = await firewallRules.detect({ repo: repo([{ path: "infra/template.yaml", content: "Resources:\n  Sg:\n    Type: AWS::EC2::SecurityGroup\n" }]) });
    expect(f).toEqual([]);
  });

  it("passes when a file contains ufw ", async () => {
    const f = await firewallRules.detect({ repo: repo([{ path: "infra/ufw.sh", content: "#!/bin/sh\nufw allow 80/tcp\n" }]) });
    expect(f).toEqual([]);
  });

  it("fix creates security-group.yaml and ufw.sh, passes guardPatch, applies, and re-detect is clean", async () => {
    const ctx = { repo: repo([{ path: "app.js", content: "const x = 1;" }]) };
    const patch = await firewallRules.fix!(ctx, await firewallRules.detect(ctx));
    expect(patch).not.toBeNull();
    expect(patch!.class).toBe("additive");
    expect(guardPatch(ctx.repo, patch!).ok).toBe(true);
    const fixed = applyPatch(ctx.repo, patch!);
    const sg = fixed.files.find((x) => x.path === "infra/security-group.yaml")!.content;
    const ufw = fixed.files.find((x) => x.path === "infra/ufw.sh")!.content;
    expect(sg).toContain("AWS::EC2::SecurityGroup");
    expect(sg).toContain("FromPort: 443");
    expect(sg).toContain("FromPort: 80");
    expect(ufw).toContain("ufw allow 443/tcp");
    expect(ufw).toContain("ufw --force enable");
    expect(await firewallRules.detect({ repo: fixed })).toEqual([]);
  });

  it("does not count a ufw rule mentioned only in docs", async () => {
    const f = await firewallRules.detect({ repo: repo([{ path: "README.md", content: "Run ufw allow 80 on the box." }]) });
    expect(f.length).toBeGreaterThan(0);
  });
});
