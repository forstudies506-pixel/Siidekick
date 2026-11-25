import type { CheckResult, ScanReport } from "../types.js";
import { summarize } from "../registry.js";
import { siteChecks, type SiteCheck, type SiteSnapshot } from "./checks.js";

export { siteChecks, headerRemedy, hostOf, type SiteCheck, type SiteSnapshot } from "./checks.js";

/** Score a live website from what was fetched; the same weights as a repo scan. */
export function runSiteScan(site: SiteSnapshot, checks: SiteCheck[] = siteChecks): ScanReport {
  const results = checks.map((c): CheckResult => {
    const base = { checkId: c.id, title: c.title, group: c.group, severity: c.severity, mode: "report" as const };
    try {
      const skipped = c.skip?.(site) ?? null;
      if (skipped) return { ...base, passed: true, findings: [], skipped };
      const findings = c.detect(site);
      return { ...base, passed: findings.length === 0, findings };
    } catch (err) {
      // A crashing detector counts as failed, never as passed.
      return { ...base, passed: false, findings: [], error: err instanceof Error ? err.message : String(err) };
    }
  });
  return summarize(new URL(site.url).hostname, site.fetchedAt, results);
}
