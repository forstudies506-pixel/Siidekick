// Siidekick GitHub Action: scans the checked-out repo on every push and pull request.
// Plain Node (no dependencies, nothing to build). It reads the repo's text files, sends them to the Siidekick
// API, and turns the report into annotations on the changed lines plus a job summary.
// .env files are never sent: a committed one is reported from here, without its contents leaving the runner.
import { appendFileSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";

const input = (name, fallback) => (process.env[`INPUT_${name.toUpperCase()}`] ?? "").trim() || fallback;
const API = input("api-url", "https://d1ulntgja5qae0.cloudfront.net").replace(/\/+$/, "");
const ROOT = join(process.env.GITHUB_WORKSPACE || process.cwd(), input("path", "."));
const FAIL_ON = input("fail-on", "none").toLowerCase();

// Same caps as the API (apps/api/src/router.ts) and the dashboard's folder upload.
const MAX_FILES = 500;
const MAX_TOTAL = 2 * 1024 * 1024;
const MAX_FILE = 512 * 1024;
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "coverage", ".next", ".nuxt", "vendor", ".venv", "venv", "__pycache__", ".siidekick", ".turbo", ".cache"]);
const isEnvFile = (p) => {
  const base = p.split("/").pop() ?? "";
  return (base === ".env" || base.startsWith(".env.")) && !/\.(example|sample|template)$/.test(base);
};
// Read first, so the dependency audit and config checks always fit inside the caps.
const priority = (p) => (/(^|\/)(package(-lock)?\.json|requirements\.txt|pyproject\.toml)$/.test(p) ? 0 : /\.(m|c)?(j|t)sx?$|\.py$/.test(p) ? 1 : 2);

function walk(dir, out) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    let st;
    try {
      st = statSync(full);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      if (!SKIP_DIRS.has(name)) walk(full, out);
    } else if (st.isFile()) {
      out.push({ full, path: relative(ROOT, full).split(sep).join("/"), size: st.size });
    }
  }
  return out;
}

const esc = (s) => String(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
const escProp = (s) => esc(s).replace(/:/g, "%3A").replace(/,/g, "%2C");
function annotate(level, f) {
  const props = [f.file && `file=${escProp(join(input("path", "."), f.file).split(sep).join("/").replace(/^\.\//, ""))}`, f.line && `line=${f.line}`, `title=${escProp(`Siidekick: ${f.title}`)}`]
    .filter(Boolean)
    .join(",");
  console.log(`::${level} ${props}::${esc(`${f.explanation}${f.remedy ? `\n\nFix: ${f.remedy}` : ""}`)}`);
}
const RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const levelOf = (sev) => (sev === "critical" || sev === "high" ? "error" : sev === "medium" ? "warning" : "notice");

async function main() {
  const all = walk(ROOT, []).sort((a, b) => priority(a.path) - priority(b.path) || a.path.localeCompare(b.path));
  const envFiles = all.filter((f) => isEnvFile(f.path));
  const files = [];
  let total = 0;
  let left = 0;
  for (const f of all) {
    if (isEnvFile(f.path) || f.size > MAX_FILE) continue;
    const buf = readFileSync(f.full);
    if (buf.subarray(0, 8000).includes(0)) continue; // binary
    if (files.length >= MAX_FILES || total + buf.length > MAX_TOTAL) {
      left++;
      continue;
    }
    files.push({ path: f.path, content: buf.toString("utf8") });
    total += buf.length;
  }
  if (files.length === 0) throw new Error(`no readable text files under ${ROOT}`);

  const name = process.env.GITHUB_REPOSITORY || "repo";
  const res = await fetch(`${API}/api/scans`, {
    method: "POST",
    headers: { "content-type": "application/json", "user-agent": "siidekick-action" },
    body: JSON.stringify({ name, files }),
    signal: AbortSignal.timeout(90_000),
  });
  const body = await res.json().catch(() => ({}));
  if (!res.ok || !body.report) throw new Error(`Siidekick API answered ${res.status}: ${body.error ?? "no report"}`);

  const report = body.report;
  const scanUrl = `${API}/app?scan=${encodeURIComponent(body.id)}&step=findings`;
  const failing = report.results.filter((r) => !r.passed && !r.skipped);
  const findings = failing.flatMap((r) => r.findings.map((f) => ({ ...f, severity: f.severity ?? r.severity })));
  for (const f of envFiles) {
    findings.unshift({
      checkId: "secrets-in-repo",
      title: "Environment file committed to the repo",
      severity: "critical",
      file: f.path,
      explanation: "This .env file is in git, so anyone with the repo can read the keys in it. It was not sent to Siidekick.",
      remedy: "Delete it from the repo, add .env to .gitignore, and rotate every key it held.",
    });
  }
  findings.sort((a, b) => (RANK[b.severity] ?? 0) - (RANK[a.severity] ?? 0));
  // GitHub shows at most 10 annotations of each level per step; the summary lists everything.
  for (const f of findings.slice(0, 30)) annotate(levelOf(f.severity), f);

  const count = (s) => findings.filter((f) => f.severity === s).length;
  const lines = [
    `## Siidekick security scan: ${report.score}/100`,
    "",
    `${report.passed} of ${report.total} checks pass · **${count("critical")} critical** · **${count("high")} high** · ${count("medium")} medium · ${count("low")} low`,
    "",
    `**[Open the full report, fixes and explanations in your language →](${scanUrl})**`,
    "",
    "| Severity | Check | Where | Finding |",
    "| --- | --- | --- | --- |",
    ...findings.slice(0, 50).map((f) => `| ${f.severity} | ${f.checkId} | ${f.file ? `\`${f.file}${f.line ? `:${f.line}` : ""}\`` : "repo"} | ${String(f.title).replace(/\|/g, "\\|")} |`),
    ...(findings.length > 50 ? [`| | | | …and ${findings.length - 50} more in the full report |`] : []),
    "",
    `<sub>Scanned ${files.length} files${left ? ` (${left} more left out past the size limits)` : ""}${envFiles.length ? ` · ${envFiles.length} .env file(s) checked locally, never sent` : ""}. Code is read as text on AWS, never run; scan records expire after 7 days. Siidekick reduces risk; it does not make an app secure.</sub>`,
  ];
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, lines.join("\n") + "\n");
  if (process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `score=${report.score}\nscan-url=${scanUrl}\n`);
  console.log(`Siidekick: ${report.score}/100, ${findings.length} findings. Full report: ${scanUrl}`);

  const threshold = { critical: 4, high: 3, medium: 2 }[FAIL_ON];
  if (threshold && findings.some((f) => (RANK[f.severity] ?? 0) >= threshold)) {
    console.log(`::error::Siidekick found ${FAIL_ON} or worse findings (fail-on: ${FAIL_ON}).`);
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.log(`::error title=Siidekick::${esc(err instanceof Error ? err.message : String(err))}`);
  process.exitCode = 1;
});
