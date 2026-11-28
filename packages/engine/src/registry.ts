import type { Check, CheckContext, CheckResult, ScanReport, Severity } from "./types.js";
import { aiChecks } from "./checks/ai.js";
import { deliveryChecks } from "./checks/delivery.js";
import { securityChecks } from "./checks/security.js";
import { IGNORE_FILE, isIgnored, parseIgnore } from "./ignore.js";

/** Every check the engine runs. Do not edit: add checks to the owning barrel in ./checks. */
export const registry: Check[] = [...securityChecks, ...deliveryChecks, ...aiChecks];

const WEIGHT: Record<Severity, number> = { critical: 5, high: 3, medium: 2, low: 1, info: 0.5 };

export async function runScan(ctx: CheckContext, checks: Check[] = registry): Promise<ScanReport> {
  const startedAt = new Date().toISOString();
  // Siidekick's own audit trail quotes the code it changed, so scanning it would re-report fixed issues.
  let files = ctx.repo.files.filter((f) => !f.path.startsWith(".siidekick/"));
  // The owner's .siidekickignore (demos, fixtures, rule definitions) is honoured, and counted in the report.
  const ignoreFile = files.find((f) => f.path === IGNORE_FILE);
  let ignored: ScanReport["ignored"];
  if (ignoreFile) {
    const rules = parseIgnore(ignoreFile.content);
    const kept = files.filter((f) => f.path === IGNORE_FILE || !isIgnored(f.path, rules));
    const patterns = ignoreFile.content.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith("#"));
    ignored = { files: files.length - kept.length, patterns };
    files = kept;
  }
  ctx = { ...ctx, repo: { ...ctx.repo, files } };
  const results = await Promise.all(
    checks.map(async (c): Promise<CheckResult> => {
      const base = { checkId: c.id, title: c.title, group: c.group, severity: c.severity, mode: c.mode };
      try {
        const skipped = c.skip?.(ctx) ?? null;
        if (skipped) return { ...base, passed: true, findings: [], skipped };
        const findings = await c.detect(ctx);
        return { ...base, passed: findings.length === 0, findings };
      } catch (err) {
        // A crashing detector counts as failed, never as passed.
        return { ...base, passed: false, findings: [], error: err instanceof Error ? err.message : String(err) };
      }
    }),
  );
  const report = summarize(ctx.repo.name, startedAt, results);
  return ignored ? { ...report, ignored } : report;
}

/** Severity-weighted score over the checks that applied; shared by repo and website scans. */
export function summarize(repo: string, startedAt: string, results: CheckResult[]): ScanReport {
  const applicable = results.filter((r) => !r.skipped);
  const total = applicable.reduce((s, r) => s + WEIGHT[r.severity], 0);
  const got = applicable.reduce((s, r) => s + (r.passed ? WEIGHT[r.severity] : 0), 0);
  return {
    repo,
    startedAt,
    score: total === 0 ? 100 : Math.round((got / total) * 100),
    passed: applicable.filter((r) => r.passed).length,
    total: applicable.length,
    skipped: results.length - applicable.length,
    results,
  };
}
