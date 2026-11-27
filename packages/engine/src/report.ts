import type { CheckResult, Finding, GuardResult, Patch, RepoSnapshot, ScanReport, Severity } from "./types.js";
import { unifiedFileDiff } from "./unifiedDiff.js";
import type { ReplayReport } from "./replay.js";
import { secretValues } from "./checks/secrets.js";

/**
 * The before/after change report: for every change Siidekick made, the diff, why it was made, which
 * findings it closed, and which evidence says it worked. Evidence is labelled by kind, because a
 * rescan with the same rules is weaker proof than tests, an isolated build or a live attack.
 */

export interface Verification {
  /** Where the checks ran: "AWS CodeBuild (isolated)", "local CLI", … */
  where: string;
  install?: { ok: boolean; detail?: string };
  build?: { ok: boolean; detail?: string };
  tests?: { ok: boolean; passed?: number; failed?: number; detail?: string };
  /** Findings of an independent scanner (e.g. Trivy) before and after, when it ran. */
  scanner?: { name: string; before: number; after: number };
  logUrl?: string;
}

export interface ChangeReportInput {
  repo: string;
  original: RepoSnapshot;
  before: ScanReport;
  after: ScanReport;
  /** Patches in the order they were applied, with the guard's verdict. Only approved ones count as changes. */
  patches: { patch: Patch; guard: GuardResult; approved: boolean }[];
  verification?: Verification;
  replay?: ReplayReport;
  /** AI explanations by check id, already grounded and labelled by the caller. */
  explanations?: Record<string, string>;
  generatedAt?: string;
}

export interface ChangeEntry {
  patchId: string;
  checkId: string;
  title: string;
  class: Patch["class"];
  reason: string;
  files: { path: string; kind: "create" | "modify"; added: number; removed: number; diff: string }[];
  closed: Finding[];
  stillOpen: Finding[];
  evidence: { kind: "rescan" | "tests" | "build" | "scanner" | "attack"; ok: boolean | null; text: string }[];
  revert: string;
}

export interface ChangeReport {
  repo: string;
  generatedAt: string;
  score: { before: number; after: number };
  risk: { before: string; after: string };
  open: { before: Record<Severity, number>; after: Record<Severity, number> };
  checks: { fixed: string[]; stillFailing: { id: string; title: string; why: string }[] };
  changes: ChangeEntry[];
  skipped: { patchId: string; title: string; why: string }[];
  remaining: Finding[];
  limits: string[];
}

const SEV_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

function key(f: Finding): string {
  return `${f.checkId}|${f.file ?? ""}|${f.title}|${f.evidence ?? ""}`;
}

function countLines(diff: string): { added: number; removed: number } {
  let added = 0;
  let removed = 0;
  for (const l of diff.split("\n")) {
    if (l.startsWith("+") && !l.startsWith("+++")) added++;
    else if (l.startsWith("-") && !l.startsWith("---")) removed++;
  }
  return { added, removed };
}

function whyFailing(r: CheckResult, patches: ChangeReportInput["patches"]): string {
  const p = patches.find((x) => x.patch.checkId === r.checkId);
  if (r.error) return `the check could not run: ${r.error}`;
  if (p && !p.approved) return "a fix was proposed but not approved";
  if (p && !p.guard.ok) return "the proposed fix was refused by the diff guard";
  if (p) return "the fix is a starting point; the remaining findings need the owner";
  if (r.mode === "report") return "report-only: the safe fix depends on what the code means, so the owner makes it";
  return "no automatic fix for this case";
}

export function buildChangeReport(input: ChangeReportInput): ChangeReport {
  const { before, after, original } = input;
  const beforeByCheck = new Map(before.results.map((r) => [r.checkId, r]));
  const afterByCheck = new Map(after.results.map((r) => [r.checkId, r]));
  const afterKeys = new Set(after.results.flatMap((r) => r.findings.map(key)));
  const secrets = secretValues(original.files);
  const mask = (s: string) => secrets.reduce((acc, v) => (v.length >= 8 ? acc.split(v).join(`${v.slice(0, 4)}…(redacted)`) : acc), s);

  let current = new Map(original.files.map((f) => [f.path, f.content]));
  const changes: ChangeEntry[] = [];
  const skipped: ChangeReport["skipped"] = [];

  for (const { patch, guard, approved } of input.patches) {
    if (!approved || !guard.ok) {
      skipped.push({ patchId: patch.id, title: patch.title, why: !guard.ok ? `refused by the diff guard (${guard.violations.map((v) => v.reason).join(", ")})` : "not approved" });
      continue;
    }
    const next = new Map(current);
    const files: ChangeEntry["files"] = [];
    for (const e of patch.edits) {
      const prev = e.kind === "create" ? null : current.get(e.path) ?? e.before;
      const content = e.kind === "create" ? e.content : e.after;
      const diff = mask(unifiedFileDiff(e.path, prev, content));
      files.push({ path: e.path, kind: e.kind, ...countLines(diff), diff });
      next.set(e.path, content);
    }
    current = next;

    const was = beforeByCheck.get(patch.checkId)?.findings ?? [];
    const now = afterByCheck.get(patch.checkId);
    const closed = was.filter((f) => !afterKeys.has(key(f)));
    const stillOpen = now?.findings ?? [];
    const evidence: ChangeEntry["evidence"] = [
      {
        kind: "rescan",
        ok: now ? now.passed : null,
        text: now ? (now.passed ? `Rescan with the same rules: ${patch.checkId} now passes (${closed.length} finding${closed.length === 1 ? "" : "s"} closed).` : `Rescan with the same rules: ${closed.length} closed, ${stillOpen.length} still open.`) : "Not rescanned.",
      },
    ];
    const v = input.verification;
    if (v?.install) evidence.push({ kind: "build", ok: v.install.ok, text: `${v.where}: dependency install ${v.install.ok ? "succeeded" : "failed"}${v.install.detail ? ` (${v.install.detail})` : ""}.` });
    if (v?.build) evidence.push({ kind: "build", ok: v.build.ok, text: `${v.where}: build ${v.build.ok ? "passed" : "failed"}${v.build.detail ? ` (${v.build.detail})` : ""}.` });
    if (v?.tests) evidence.push({ kind: "tests", ok: v.tests.ok, text: `${v.where}: the project's tests ${v.tests.ok ? "passed" : "failed"}${v.tests.passed !== undefined ? ` (${v.tests.passed} passed, ${v.tests.failed ?? 0} failed)` : ""}.` });
    if (v?.scanner && patch.checkId === "dependency-audit") evidence.push({ kind: "scanner", ok: v.scanner.after < v.scanner.before, text: `${v.scanner.name} (independent scanner): ${v.scanner.before} → ${v.scanner.after} known vulnerabilities.` });
    for (const a of input.replay?.attacks ?? []) {
      if (a.checkId !== patch.checkId) continue;
      evidence.push({ kind: "attack", ok: a.verdict === "blocked", text: `Live attack "${a.title}": before ${a.before.exploited ? "worked" : "failed"}, after ${a.after.exploited ? "still works" : "blocked"}${a.control ? `; control "${a.control.label}" ${a.control.ok ? "still works" : "BROKE"}` : ""}.` });
    }
    changes.push({ patchId: patch.id, checkId: patch.checkId, title: patch.title, class: patch.class, reason: patch.reason, files, closed, stillOpen, evidence, revert: `git apply -R .siidekick/${patch.id}.patch` });
  }

  const fixed = before.results.filter((r) => !r.passed && !r.skipped && afterByCheck.get(r.checkId)?.passed).map((r) => r.checkId);
  const stillFailing = after.results.filter((r) => !r.passed && !r.skipped).map((r) => ({ id: r.checkId, title: r.title, why: whyFailing(r, input.patches) }));
  const remaining = after.results
    .filter((r) => !r.skipped)
    .flatMap((r) => r.findings)
    .sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));

  const limits = [
    "\"Rescan\" reuses the rules that found the problem, so it shows the pattern is gone, not that the app is safe.",
    input.verification ? `Install, build and test results come from ${input.verification.where}. Passing tests mean the change did not break what the tests cover, nothing more.` : "No build or tests ran for this report: run npm install and your tests (or the isolated verify step) before shipping a dependency change.",
    input.replay?.available ? "Live attacks ran only against the bundled demo shop, never against uploaded code." : "No live attacks ran: those run only for the bundled demo shop.",
    "Static analysis finds known patterns. A clean result means none were found, not that none exist. Risk reduced, not removed.",
  ];

  const zero = (): Record<Severity, number> => ({ critical: 0, high: 0, medium: 0, low: 0, info: 0 });
  return {
    repo: input.repo,
    generatedAt: input.generatedAt ?? new Date().toISOString(),
    score: { before: before.score, after: after.score },
    risk: { before: before.risk ?? "unknown", after: after.risk ?? "unknown" },
    open: { before: before.open ?? zero(), after: after.open ?? zero() },
    checks: { fixed, stillFailing },
    changes,
    skipped,
    remaining,
    limits,
  };
}

// ---------------------------------------------------------------------------------------------
// Markdown

function sevLine(o: Record<Severity, number>): string {
  return SEV_ORDER.filter((s) => s !== "info").map((s) => `${o[s]} ${s}`).join(", ");
}

const mark = (ok: boolean | null) => (ok === null ? "–" : ok ? "✅" : "❌");

export function changeReportMarkdown(r: ChangeReport): string {
  const out: string[] = [];
  out.push(`# Siidekick change report: ${r.repo}`, "", `Generated ${r.generatedAt}. Risk reduced, not removed.`, "");
  out.push("## Before and after", "", "| | Before | After |", "|---|---|---|");
  out.push(`| Score (weighted share of passing checks) | ${r.score.before}/100 | ${r.score.after}/100 |`);
  out.push(`| Worst open risk | ${r.risk.before} | ${r.risk.after} |`);
  out.push(`| Open findings | ${sevLine(r.open.before)} | ${sevLine(r.open.after)} |`, "");
  if (r.checks.fixed.length) out.push(`Checks that now pass: ${r.checks.fixed.map((c) => `\`${c}\``).join(", ")}.`, "");

  out.push(`## Changes (${r.changes.length})`, "");
  r.changes.forEach((c, i) => {
    const added = c.files.reduce((s, f) => s + f.added, 0);
    const removed = c.files.reduce((s, f) => s + f.removed, 0);
    out.push(`### ${i + 1}. ${c.title}`, "");
    out.push(`- Check: \`${c.checkId}\` · ${c.class === "additive" ? "adds code only" : "minimal edit (declared lines only)"} · +${added} −${removed} lines`);
    out.push(`- Why: ${c.reason}`);
    if (c.closed.length) out.push(`- Closes: ${c.closed.map((f) => `${f.title}${f.file ? ` (${f.file}${f.line ? `:${f.line}` : ""})` : ""}`).join("; ")}`);
    if (c.stillOpen.length) out.push(`- Still open for this check: ${c.stillOpen.length} finding${c.stillOpen.length === 1 ? "" : "s"} (see Remaining risk)`);
    out.push(`- Undo: \`${c.revert}\``, "", "Evidence:", "");
    for (const e of c.evidence) out.push(`- ${mark(e.ok)} **${e.kind}** ${e.text}`);
    out.push("");
    for (const f of c.files) out.push("```diff", f.diff.trimEnd(), "```", "");
  });
  if (r.skipped.length) {
    out.push("## Proposed but not applied", "");
    for (const s of r.skipped) out.push(`- ${s.title}: ${s.why}`);
    out.push("");
  }
  out.push("## Remaining risk", "");
  if (r.remaining.length === 0) out.push("No open findings from the checks that ran.", "");
  for (const f of r.remaining) {
    out.push(`- **${f.severity}** ${f.title}${f.file ? ` — \`${f.file}${f.line ? `:${f.line}` : ""}\`` : ""}`);
    if (f.evidence) out.push(`  - Evidence: ${f.evidence}`);
    if (f.remedy) out.push(`  - Fix: ${f.remedy}`);
  }
  out.push("", "## Checks still failing", "");
  for (const c of r.checks.stillFailing) out.push(`- \`${c.id}\` ${c.title}: ${c.why}`);
  out.push("", "## Limits of this report", "");
  for (const l of r.limits) out.push(`- ${l}`);
  return out.join("\n") + "\n";
}

// ---------------------------------------------------------------------------------------------
// HTML (self-contained, for sharing or printing)

const esc = (s: string) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

function diffHtml(diff: string): string {
  return diff
    .trimEnd()
    .split("\n")
    .map((l) => {
      const cls = l.startsWith("+++") || l.startsWith("---") || l.startsWith("diff ") ? "m" : l.startsWith("+") ? "a" : l.startsWith("-") ? "d" : l.startsWith("@@") ? "h" : "";
      return `<span class="${cls}">${esc(l)}</span>`;
    })
    .join("\n");
}

export function changeReportHtml(r: ChangeReport): string {
  const sev = (s: Severity) => `<span class="sev ${s}">${s}</span>`;
  const changes = r.changes
    .map((c, i) => {
      const added = c.files.reduce((s, f) => s + f.added, 0);
      const removed = c.files.reduce((s, f) => s + f.removed, 0);
      return `<section class="change"><h3>${i + 1}. ${esc(c.title)}</h3>
<p class="meta"><code>${esc(c.checkId)}</code> · ${c.class === "additive" ? "adds code only" : "minimal edit"} · <span class="plus">+${added}</span> <span class="minus">−${removed}</span></p>
<p>${esc(c.reason)}</p>
${c.closed.length ? `<p><b>Closes:</b> ${c.closed.map((f) => esc(`${f.title}${f.file ? ` (${f.file}${f.line ? `:${f.line}` : ""})` : ""}`)).join("; ")}</p>` : ""}
<ul class="evidence">${c.evidence.map((e) => `<li class="${e.ok === null ? "na" : e.ok ? "ok" : "bad"}"><b>${e.kind}</b> ${esc(e.text)}</li>`).join("")}</ul>
${c.files.map((f) => `<details><summary>${esc(f.path)} <span class="plus">+${f.added}</span> <span class="minus">−${f.removed}</span></summary><pre class="diff">${diffHtml(f.diff)}</pre></details>`).join("")}
<p class="undo">Undo: <code>${esc(c.revert)}</code></p></section>`;
    })
    .join("\n");
  const remaining = r.remaining
    .map((f) => `<li>${sev(f.severity)} ${esc(f.title)}${f.file ? ` <code>${esc(`${f.file}${f.line ? `:${f.line}` : ""}`)}</code>` : ""}${f.remedy ? `<div class="fix">${esc(f.remedy)}</div>` : ""}</li>`)
    .join("");
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Siidekick change report: ${esc(r.repo)}</title>
<style>
:root{--bg:#f7f6f2;--fg:#1d1e21;--muted:#62636a;--line:#dddbd3;--card:#fff;--add:#e3f4e8;--del:#fbe6e6;--accent:#a8650b}
@media (prefers-color-scheme:dark){:root{--bg:#141517;--fg:#ecebe6;--muted:#a3a29b;--line:#2f3034;--card:#1c1d20;--add:#16301f;--del:#3d1c1c;--accent:#f2b544}}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,Segoe UI,sans-serif}
main{max-width:900px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:1.7rem;margin:0 0 4px}h2{margin-top:36px;border-bottom:2px solid var(--fg);padding-bottom:4px}
table{border-collapse:collapse;width:100%}td,th{text-align:left;padding:8px;border-bottom:1px solid var(--line)}
.change{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin:14px 0}
.meta{color:var(--muted);font-size:13px}.plus{color:#1f7a4a}.minus{color:#b4232a}
pre.diff{overflow-x:auto;font:12.5px/1.5 ui-monospace,Consolas,monospace;background:var(--bg);padding:10px;border-radius:6px}
pre.diff .a{background:var(--add);display:block}pre.diff .d{background:var(--del);display:block}pre.diff .h,pre.diff .m{color:var(--muted)}
.evidence{list-style:none;padding:0}.evidence li{padding:4px 0}.evidence li::before{margin-right:6px}
.evidence .ok::before{content:"✔";color:#1f7a4a}.evidence .bad::before{content:"✘";color:#b4232a}.evidence .na::before{content:"–"}
.sev{font-size:11px;padding:2px 7px;border-radius:99px;text-transform:uppercase;letter-spacing:.04em;background:var(--line)}
.sev.critical{background:#b4232a;color:#fff}.sev.high{background:#d9622b;color:#fff}.sev.medium{background:#e9b949;color:#000}
.fix{color:var(--muted);font-size:13px;margin:2px 0 8px}code{font-family:ui-monospace,Consolas,monospace;font-size:.9em}
ul.remaining li{margin:6px 0}.undo{font-size:13px;color:var(--muted)}
</style></head><body><main>
<h1>Siidekick change report</h1><p class="meta">${esc(r.repo)} · ${esc(r.generatedAt)} · risk reduced, not removed</p>
<h2>Before and after</h2>
<table><tr><th></th><th>Before</th><th>After</th></tr>
<tr><td>Score</td><td>${r.score.before}/100</td><td>${r.score.after}/100</td></tr>
<tr><td>Worst open risk</td><td>${esc(r.risk.before)}</td><td>${esc(r.risk.after)}</td></tr>
<tr><td>Open findings</td><td>${esc(sevLine(r.open.before))}</td><td>${esc(sevLine(r.open.after))}</td></tr></table>
<h2>Changes (${r.changes.length})</h2>${changes || "<p>No changes were applied.</p>"}
${r.skipped.length ? `<h2>Proposed but not applied</h2><ul>${r.skipped.map((s) => `<li>${esc(s.title)}: ${esc(s.why)}</li>`).join("")}</ul>` : ""}
<h2>Remaining risk</h2><ul class="remaining">${remaining || "<li>No open findings from the checks that ran.</li>"}</ul>
<h2>Checks still failing</h2><ul>${r.checks.stillFailing.map((c) => `<li><code>${esc(c.id)}</code> ${esc(c.title)}: ${esc(c.why)}</li>`).join("")}</ul>
<h2>Limits of this report</h2><ul>${r.limits.map((l) => `<li>${esc(l)}</li>`).join("")}</ul>
</main></body></html>`;
}
