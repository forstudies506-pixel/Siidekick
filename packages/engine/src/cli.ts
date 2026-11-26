#!/usr/bin/env node
import { existsSync } from "node:fs";
import { mkdir, readdir, symlink, unlink } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { applyPatch, GuardRejected } from "./apply.js";
import { guardPatch } from "./diffGuard.js";
import { loadRepo } from "./loadRepo.js";
import { registry, runScan } from "./registry.js";
import { replayDemo, sameFiles, type ReplayReport } from "./replay.js";
import type { Patch } from "./types.js";
import { patchArtifacts } from "./unifiedDiff.js";
import { verifyPatches, writeRepo } from "./verify.js";

const USAGE = `siidekick scan <dir> [--json]
siidekick fix <dir> [--out <dir>] [--verify] [--prove]
  dry run by default; --out writes a fixed copy (original untouched) with .siidekick/*.patch and SIIDEKICK_LOG.md
  --verify (needs --out) runs your npm test before and after each patch and rolls back any patch that breaks it
  --prove boots the app before and after the patches and fires the same attacks at both.
          It runs only on the bundled demo shop (demo/vulnerable-app), never on other code.`;

async function main(argv: string[]): Promise<number> {
  const [cmd, dir, ...rest] = argv;
  if (!cmd || !dir || !["scan", "fix"].includes(cmd)) {
    console.error(USAGE);
    return 2;
  }
  const original = await loadRepo(resolve(dir));
  const prove = cmd === "fix" && rest.includes("--prove");
  let runtimeDir: string | null = null;
  // Checked before any scan: --prove executes the app, so it must be byte-for-byte the shipped demo.
  if (prove) {
    const here = dirname(fileURLToPath(import.meta.url));
    const demoDir = findUp(here, (d) => join(d, "demo", "vulnerable-app"));
    if (!demoDir || !sameFiles(original, await loadRepo(demoDir))) {
      console.error("--prove runs attacks against a live copy of the app, so it only runs on the bundled demo shop (demo/vulnerable-app), unchanged. This folder is not that copy; nothing was run.");
      return 2;
    }
    runtimeDir = findUp(here, (d) => {
      const nm = join(d, "node_modules");
      return existsSync(join(nm, "express")) && existsSync(join(nm, "lodash")) ? nm : null;
    });
    if (!runtimeDir) {
      console.error("--prove needs express and lodash installed (run npm install at the repo root)");
      return 2;
    }
  }
  let repo = original;
  const before = await runScan({ repo });

  if (cmd === "scan") {
    if (rest.includes("--json")) console.log(JSON.stringify(before, null, 2));
    else printReport(before);
    return before.passed === before.total ? 0 : 1;
  }

  const outIdx = rest.indexOf("--out");
  const out = outIdx >= 0 ? rest[outIdx + 1] : undefined;
  const verify = rest.includes("--verify");
  if ((outIdx >= 0 && !out) || (verify && !out)) {
    console.error(USAGE);
    return 2;
  }
  // Never write over files that are already there.
  if (out && existsSync(out) && (await readdir(out)).length > 0) {
    console.error(`--out ${out} is not empty; pick a new folder`);
    return 2;
  }
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
  let kept = patches;
  let tests = "tests not run";
  if (out && verify) {
    const outDir = resolve(out);
    const link = await linkNodeModules(resolve(dir), outDir);
    try {
      const v = await verifyPatches(outDir, original, patches, undefined, async (current, stale) => {
        const check = registry.find((c) => c.id === stale.checkId);
        if (!check?.fix) return null;
        const findings = await check.detect({ repo: current });
        return findings.length ? check.fix({ repo: current }, findings) : null;
      });
      repo = v.repo;
      kept = v.verdicts.filter((x) => x.kept).map((x) => x.patch);
      console.log(`\nTests before patches: ${v.baseline ? (v.baseline.ok ? "pass" : "FAIL") : "no test script"}`);
      for (const x of v.verdicts) console.log(`  ${x.kept ? "kept  " : "undone"}  ${x.patch.title}  (${x.note})`);
      tests = v.baseline?.ok ? `tests pass, ${v.verdicts.length - kept.length} rolled back` : "tests not verified";
    } finally {
      if (link) await unlink(link);
    }
  }
  const after = await runScan({ repo });
  console.log(`\nScore ${before.score} → ${after.score}  (${kept.length} patch(es), status: rescan-${after.passed === after.total ? "clean" : "partial"}, ${tests})`);
  if (prove && runtimeDir) printReplay(await replayDemo({ before: original, after: repo, runtimeDir }));
  if (out) {
    await writeRepo({ name: repo.name, files: [...repo.files, ...patchArtifacts(original, kept)] }, resolve(out));
    console.log(`Fixed copy written to ${out} (see SIIDEKICK_LOG.md there)`);
  }
  return 0;
}

/** Tests in the copy need the owner's installed packages; links the nearest node_modules above `src`. */
async function linkNodeModules(src: string, out: string): Promise<string | null> {
  for (let d = src; ; d = dirname(d)) {
    const nm = join(d, "node_modules");
    if (existsSync(nm)) {
      const link = join(out, "node_modules");
      await mkdir(out, { recursive: true });
      await symlink(nm, link, "dir");
      return link;
    }
    if (dirname(d) === d) return null;
  }
}

/** Walks up from `start` and returns the first non-null `probe(dir)`. */
function findUp(start: string, probe: (dir: string) => string | null): string | null {
  for (let d = start; ; d = dirname(d)) {
    const hit = probe(d);
    if (hit && existsSync(hit)) return hit;
    if (dirname(d) === d) return null;
  }
}

function printReplay(r: ReplayReport): void {
  if (!r.available) {
    console.log(`\nAttack replay: ${r.reason}`);
    return;
  }
  console.log(`\nAttack replay (${r.ms} ms): the same requests against the app as scanned and as patched`);
  for (const a of r.attacks) {
    console.log(`  ${a.verdict.padEnd(14)} ${a.title}`);
    console.log(`      before: ${a.before.detail}`);
    console.log(`      after:  ${a.after.detail}${a.control ? `  (control: ${a.control.label} ${a.control.ok ? "ok" : "FAILED"})` : ""}`);
  }
  for (const p of r.paths) console.log(`  path ${p.openAfter ? "STILL OPEN" : "cut       "} ${p.title}${p.cutBy.length ? `  (${p.openAfter ? "needs" : "cut by"} ${p.cutBy.join(", ")})` : ""}`);
  if (r.tests?.ran) console.log(`  patched app's own tests: ${r.tests.passed} passed, ${r.tests.failed} failed`);
}

function printReport(r: Awaited<ReturnType<typeof runScan>>): void {
  console.log(`${r.repo}: score ${r.score}/100, ${r.passed}/${r.total} checks pass`);
  for (const c of r.results) {
    console.log(`${c.passed ? "✓" : "✗"} [${c.severity}] ${c.title}${c.error ? ` (error: ${c.error})` : ""}`);
    for (const f of c.findings) console.log(`    ${f.file ?? ""}${f.line ? ":" + f.line : ""}  ${f.title}${f.evidence ? "  " + f.evidence : ""}`);
  }
}

main(process.argv.slice(2)).then((code) => process.exit(code), (e) => { console.error(e); process.exit(1); });
