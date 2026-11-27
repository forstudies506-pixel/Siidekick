// Siidekick isolated verification, run by AWS CodeBuild (one build per scan, started by Step Functions).
//
// For the original repo and for the patched repo it: installs dependencies (npm ci, install scripts
// off), runs the build and test scripts if the project has them, and scans the tree with Trivy. The
// result goes to S3, where the pipeline's collect stage reads it.
//
// The repo is untrusted code. Every command that runs it gets an environment with no AWS_*,
// CODEBUILD_* or ECS_* variables, so it cannot find the build role's credentials, plus a time limit.
// This lowers the risk; it is not a sandbox. The pipeline sends only the demo shop here unless the
// operator turns on VerifyUntrustedRepos and gives CodeBuild a role with no other permissions.
//
// No dependencies: Node's standard library and the AWS CLI that the CodeBuild image ships.

import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, normalize, isAbsolute } from "node:path";
import { gunzipSync } from "node:zlib";

const { BUCKET, ORIGINAL_KEY, PATCHED_KEY, RESULT_KEY, CODEBUILD_BUILD_ID } = process.env;
if (!BUCKET || !ORIGINAL_KEY || !PATCHED_KEY || !RESULT_KEY) {
  console.error("BUCKET, ORIGINAL_KEY, PATCHED_KEY and RESULT_KEY are required");
  process.exit(2);
}

const STEP_TIMEOUT_MS = 8 * 60 * 1000;
// For a local dry run: SIIDEKICK_AWS_SHIM=path/to/fake-aws.mjs stands in for the AWS CLI.
const AWS = process.env.SIIDEKICK_AWS_SHIM ? [process.execPath, process.env.SIIDEKICK_AWS_SHIM] : ["aws"];
const aws = (args, opts) => execFileSync(AWS[0], [...AWS.slice(1), ...args], opts);
const WORK = process.env.SIIDEKICK_WORK ?? "/tmp/siidekick";

const untrustedEnv = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(AWS_|CODEBUILD_|ECS_)/.test(k)));
Object.assign(untrustedEnv, { CI: "1", npm_config_ignore_scripts: "true", npm_config_audit: "false", npm_config_fund: "false" });

function s3Json(key) {
  const tmp = join(WORK, key.replace(/[^\w.-]/g, "_"));
  mkdirSync(dirname(tmp), { recursive: true });
  aws(["s3", "cp", `s3://${BUCKET}/${key}`, tmp], { stdio: "inherit" });
  const bytes = readFileSync(tmp);
  return JSON.parse((bytes[0] === 0x1f && bytes[1] === 0x8b ? gunzipSync(bytes) : bytes).toString("utf8"));
}

function writeRepo(snapshot, dir) {
  for (const f of snapshot.files) {
    const rel = normalize(f.path);
    if (isAbsolute(rel) || rel.startsWith("..")) continue; // never write outside the folder
    const p = join(dir, rel);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, f.content);
  }
}

function run(cmd, args, cwd) {
  const r = spawnSync(cmd, args, { cwd, env: untrustedEnv, timeout: STEP_TIMEOUT_MS, encoding: "utf8", maxBuffer: 32 * 1024 * 1024, shell: process.platform === "win32" });
  const out = `${r.stdout ?? ""}${r.stderr ?? ""}`;
  console.log(`$ ${cmd} ${args.join(" ")} (in ${cwd}) → ${r.status ?? r.signal}`);
  console.log(out.split("\n").slice(-40).join("\n"));
  const tail = out.trim().split("\n").slice(-3).join(" ").slice(0, 300);
  return { ok: r.status === 0, detail: r.error ? String(r.error.message) : r.status === 0 ? undefined : `exit ${r.status ?? r.signal}: ${tail}` };
}

function trivyCount(dir) {
  const r = spawnSync("trivy", ["fs", "--scanners", "vuln", "--format", "json", "--quiet", "--timeout", "6m", dir], {
    env: untrustedEnv,
    timeout: STEP_TIMEOUT_MS,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });
  if (r.status !== 0 || !r.stdout) return undefined;
  try {
    const report = JSON.parse(r.stdout);
    return { vulns: (report.Results ?? []).reduce((n, res) => n + (res.Vulnerabilities?.length ?? 0), 0) };
  } catch {
    return undefined;
  }
}

function verify(snapshot, name) {
  const dir = join(WORK, name);
  mkdirSync(dir, { recursive: true });
  writeRepo(snapshot, dir);
  const result = {};
  const pkgPath = join(dir, "package.json");
  if (existsSync(pkgPath)) {
    let pkg = {};
    try {
      pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
    } catch {
      return { install: { ok: false, detail: "package.json is not valid JSON" } };
    }
    const lock = existsSync(join(dir, "package-lock.json")) || existsSync(join(dir, "npm-shrinkwrap.json"));
    result.install = lock ? run("npm", ["ci", "--ignore-scripts"], dir) : run("npm", ["install", "--ignore-scripts", "--no-package-lock"], dir);
    if (result.install.ok && pkg.scripts?.build) result.build = run("npm", ["run", "build"], dir);
    if (result.install.ok && pkg.scripts?.test && !/no test specified/.test(pkg.scripts.test)) result.tests = run("npm", ["test"], dir);
  }
  result.trivy = trivyCount(dir);
  return result;
}

const original = verify(s3Json(ORIGINAL_KEY), "original");
const patched = verify(s3Json(PATCHED_KEY), "patched");
const resultFile = join(WORK, "result.json");
writeFileSync(resultFile, JSON.stringify({ original, patched, buildId: CODEBUILD_BUILD_ID }, null, 2));
// This upload runs with the build role; the repo's own commands above never saw it.
aws(["s3", "cp", resultFile, `s3://${BUCKET}/${RESULT_KEY}`, "--sse", "AES256", "--content-type", "application/json"], { stdio: "inherit" });
console.log(JSON.stringify({ original, patched }, null, 2));
