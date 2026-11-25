#!/usr/bin/env node
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { applyPatch, GuardRejected } from "./apply.js";
import { guardPatch } from "./diffGuard.js";
import { loadRepo } from "./loadRepo.js";
import { registry, runScan } from "./registry.js";
import type { Patch, RepoSnapshot } from "./types.js";

const USAGE = `siidekick scan <dir> [--json]
siidekick fix <dir> [--out <dir>]   dry run by default; --out writes a fixed copy (original untouched)`;

async function main(argv: string[]): Promise<number> {
  const [cmd, dir, ...rest] = argv;
  if (!cmd || !dir || !["scan", "fix"].includes(cmd)) {
    console.error(USAGE);
    return 2;
  }
  let repo = await loadRepo(resolve(dir));
  const before = await runScan({ repo });

  if (cmd === "scan") {
    if (rest.includes("--json")) console.log(JSON.stringify(before, null, 2));
    else printReport(before);
    return before.passed === before.total ? 0 : 1;
  }

  const outIdx = rest.indexOf("--out");
  const out = outIdx >= 0 ? rest[outIdx + 1] : undefined;
  const patches: Patch[] = [];
  for (const check of registry) {
    const res = before.results.find((r) => r.checkId === check.id);
    if (!res || res.passed || !check.fix || check.mode === "report") continue;
    const patch = await check.fix({ repo }, res.findings);
    if (!patch) continue;
    const g = guardPatch(repo, patch);
    console.log(`\n[${g.ok ? "GUARD OK" : "GUARD REJECTED"}] ${patch.title}  (+${g.added} / -${g.removed})`);
    for (const v of g.violations) console.log(`   ✗ ${v.path}: ${v.reason}${v.line ? ` → ${v.line}` : ""}`);
    if (!g.ok) continue;
    try {
      repo = applyPatch(repo, patch);
      patches.push(patch);
    } catch (e) {
      if (!(e instanceof GuardRejected)) throw e;
    }
  }
  const after = await runScan({ repo });
  console.log(`\nScore ${before.score} → ${after.score}  (${patches.length} patch(es), status: rescan-${after.passed === after.total ? "clean" : "partial"}, tests not run)`);
  if (out) await writeRepo(repo, resolve(out));
  return 0;
}

async function writeRepo(repo: RepoSnapshot, out: string): Promise<void> {
  for (const f of repo.files) {
    const p = join(out, f.path);
    await mkdir(dirname(p), { recursive: true });
    await writeFile(p, f.content);
  }
  console.log(`Fixed copy written to ${out}`);
}

function printReport(r: Awaited<ReturnType<typeof runScan>>): void {
  console.log(`${r.repo}: score ${r.score}/100, ${r.passed}/${r.total} checks pass`);
  for (const c of r.results) {
    console.log(`${c.passed ? "✓" : "✗"} [${c.severity}] ${c.title}${c.error ? ` (error: ${c.error})` : ""}`);
    for (const f of c.findings) console.log(`    ${f.file ?? ""}${f.line ? ":" + f.line : ""}  ${f.title}${f.evidence ? "  " + f.evidence : ""}`);
  }
}

main(process.argv.slice(2)).then((code) => process.exit(code), (e) => { console.error(e); process.exit(1); });
