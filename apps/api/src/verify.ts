/**
 * Verified fixes: the owner's repo (before) and the repo with the approved patches (after) are zipped to S3,
 * and a Step Functions workflow runs them in a throwaway CodeBuild container:
 *   npm install → npm test → npm audit, for both copies,
 * then an evaluate step applies the trust rule and writes a verdict next to the build output.
 *
 * Trust rule (project brief §13): a fix is "verified" only when the targeted vulnerabilities are gone in an
 * independent follow-up check (npm audit, a different advisory source from the OSV.dev scan) AND the
 * project's own tests pass after the change. Anything less is reported as what it is.
 */
import type { RepoSnapshot } from "@siidekick/engine";
import { zipBuffer } from "./zip.js";

/** Runs inside CodeBuild. Ours, not the repo's: it sits outside before/ and after/. */
export const VERIFY_SCRIPT = `#!/bin/bash
set -u
# The repository is untrusted. Drop the build role's credentials before any of its code runs,
# so install hooks or tests cannot reach the AWS account. (Install scripts are also skipped.)
unset AWS_CONTAINER_CREDENTIALS_RELATIVE_URI AWS_CONTAINER_CREDENTIALS_FULL_URI AWS_CONTAINER_AUTHORIZATION_TOKEN \\
      AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
export CI=true NPM_CONFIG_UPDATE_NOTIFIER=false NPM_CONFIG_FUND=false
ROOT="$(pwd)"
OUT="$ROOT/out"
mkdir -p "$OUT"

has_tests() {
  node -e 'const s=(require("./package.json").scripts||{}).test||"";process.exit(s&&!/no test specified/.test(s)?0:1)' 2>/dev/null
}

run_side() {
  local side="$1" log="$OUT/$1"
  cd "$ROOT/$side" || return
  date +%s%3N > "$log.t0"
  if [ "$side" = "before" ] && [ -f package-lock.json ]; then
    timeout 300 npm ci --ignore-scripts --no-audit > "$log.install.txt" 2>&1
    code=$?
    if [ $code -ne 0 ]; then
      timeout 300 npm install --ignore-scripts --no-audit >> "$log.install.txt" 2>&1
      code=$?
    fi
  else
    # After a version bump the old lockfile no longer matches package.json; npm install refreshes it.
    timeout 300 npm install --ignore-scripts --no-audit > "$log.install.txt" 2>&1
    code=$?
  fi
  echo $code > "$log.install.code"
  if has_tests; then
    timeout 300 npm test > "$log.test.txt" 2>&1
    echo $? > "$log.test.code"
  else
    echo none > "$log.test.code"
  fi
  timeout 120 npm audit --json > "$log.audit.json" 2> "$log.audit.err"
  date +%s%3N > "$log.t1"
  cd "$ROOT"
}

node --version > "$OUT/node.txt"
npm --version > "$OUT/npm.txt"
run_side before
run_side after
[ -f after/package-lock.json ] && cp after/package-lock.json "$OUT/package-lock.after.json"
node siidekick/collect.cjs > "$OUT/result.json"
rm -f "$OUT"/*.t0 "$OUT"/*.t1
echo "verify done"
`;

/** Runs inside CodeBuild after the script: folds the logs into one result.json. */
export const COLLECT_SCRIPT = `const fs = require("fs");
const read = (p) => { try { return fs.readFileSync(p, "utf8"); } catch { return null; } };
const tail = (s) => (s ?? "").split("\\n").slice(-40).join("\\n").slice(-4000);
function audit(raw) {
  if (!raw) return { ok: false, packages: {} };
  try {
    const j = JSON.parse(raw);
    const packages = {};
    for (const [name, v] of Object.entries(j.vulnerabilities || {})) {
      const via = (v.via || []).map((x) => (typeof x === "string" ? x : x.title || x.url || x.source)).filter(Boolean).slice(0, 5);
      packages[name] = { severity: v.severity, isDirect: !!v.isDirect, via, fixAvailable: !!v.fixAvailable };
    }
    return { ok: true, counts: (j.metadata && j.metadata.vulnerabilities) || {}, packages };
  } catch (e) { return { ok: false, error: String(e).slice(0, 200), packages: {} }; }
}
function side(name) {
  const o = "out/" + name;
  const installCode = Number(read(o + ".install.code"));
  const testCode = (read(o + ".test.code") || "").trim();
  const t0 = Number(read(o + ".t0")), t1 = Number(read(o + ".t1"));
  return {
    install: { ok: installCode === 0, code: installCode, tail: tail(read(o + ".install.txt")) },
    tests: testCode === "none" ? { ran: false } : { ran: true, code: Number(testCode), passed: Number(testCode) === 0, tail: tail(read(o + ".test.txt")) },
    audit: audit(read(o + ".audit.json")),
    ms: t1 && t0 ? t1 - t0 : undefined,
  };
}
process.stdout.write(JSON.stringify({
  node: (read("out/node.txt") || "").trim(),
  npm: (read("out/npm.txt") || "").trim(),
  before: side("before"),
  after: side("after"),
  lockfileRefreshed: fs.existsSync("out/package-lock.after.json"),
}));
`;

export interface SideResult {
  install: { ok: boolean; code: number; tail: string };
  tests: { ran: false } | { ran: true; code: number; passed: boolean; tail: string };
  audit: {
    ok: boolean;
    counts?: Record<string, number>;
    packages: Record<string, { severity: string; isDirect: boolean; via: string[]; fixAvailable: boolean }>;
  };
  ms?: number;
}

export interface BuildResult {
  node?: string;
  npm?: string;
  before: SideResult;
  after: SideResult;
  lockfileRefreshed: boolean;
}

export type VerdictStatus = "verified" | "inconclusive" | "not-verified" | "regression" | "error";

export interface Verdict {
  jobId: string;
  scanId: string;
  status: VerdictStatus;
  headline: string;
  checks: Array<{ label: string; ok: boolean | null; detail: string }>;
  targets: Array<{ name: string; before: string | null; after: string | null; fixed: boolean }>;
  /** Vulnerable packages npm audit still reports after the change, targeted or not. */
  remaining: Array<{ name: string; severity: string }>;
  result?: BuildResult;
  finishedAt: string;
}

export interface JobMeta {
  jobId: string;
  scanId: string;
  repo: string;
  /** Packages the OSV.dev scan flagged; each must be absent from the follow-up audit to count as fixed. */
  targets: string[];
  approved: string[];
  startedAt: string;
}

/** The CodeBuild source bundle: before/, after/ and our two scripts. */
export function buildSourceZip(before: RepoSnapshot, after: RepoSnapshot): Buffer {
  return zipBuffer([
    { path: "siidekick/verify.sh", content: VERIFY_SCRIPT, mode: 0o755 },
    { path: "siidekick/collect.cjs", content: COLLECT_SCRIPT },
    ...before.files.map((f) => ({ path: `before/${f.path}`, content: f.content })),
    ...after.files.map((f) => ({ path: `after/${f.path}`, content: f.content })),
  ]);
}

const testsLabel = (s: SideResult["tests"]) => (!s.ran ? "no test script" : s.passed ? "passed" : `failed (exit ${s.code})`);

/** The trust rule, as code. Pure, so it is tested without AWS. */
export function evaluate(meta: JobMeta, result: BuildResult | null, buildError?: string): Verdict {
  const base = { jobId: meta.jobId, scanId: meta.scanId, finishedAt: new Date().toISOString() };
  if (!result) {
    return {
      ...base,
      status: "error",
      headline: "The isolated build did not finish, so nothing was verified.",
      checks: [{ label: "Isolated build ran", ok: false, detail: buildError ?? "no result was produced" }],
      targets: meta.targets.map((name) => ({ name, before: null, after: null, fixed: false })),
      remaining: [],
    };
  }
  const { before, after } = result;
  const targets = meta.targets.map((name) => {
    const b = before.audit.packages[name]?.severity ?? null;
    const a = after.audit.packages[name]?.severity ?? null;
    return { name, before: b, after: a, fixed: after.audit.ok && a === null };
  });
  const remaining = Object.entries(after.audit.packages).map(([name, v]) => ({ name, severity: v.severity }));
  const fixedAll = targets.every((t) => t.fixed);
  const testsPass = after.tests.ran && after.tests.passed;
  const regression = before.tests.ran && before.tests.passed && after.tests.ran && !after.tests.passed;

  const checks: Verdict["checks"] = [
    { label: "Dependencies install after the fix", ok: after.install.ok, detail: after.install.ok ? "npm install succeeded" : `npm install exited ${after.install.code}` },
    {
      label: "Project tests after the fix",
      ok: after.tests.ran ? after.tests.passed : null,
      detail: `before: ${testsLabel(before.tests)} · after: ${testsLabel(after.tests)}`,
    },
    {
      label: "Independent audit (npm audit) after the fix",
      ok: after.audit.ok ? fixedAll : null,
      detail: after.audit.ok
        ? `${targets.filter((t) => t.fixed).length}/${targets.length} targeted packages clean · ${remaining.length} vulnerable package(s) left in total`
        : "npm audit did not return a report",
    },
  ];

  let status: VerdictStatus;
  let headline: string;
  if (regression) {
    status = "regression";
    headline = "Caught a breaking fix: the tests passed before the change and fail after it. Do not merge as is.";
  } else if (!after.install.ok) {
    status = "not-verified";
    headline = "The fixed copy does not install, so it is not verified.";
  } else if (!after.tests.ran) {
    status = "inconclusive";
    headline = fixedAll
      ? "The audit is clean for the targeted packages, but the project has no tests, so behaviour is unverified."
      : "The project has no tests and some targeted packages are still vulnerable.";
  } else if (testsPass && fixedAll) {
    status = "verified";
    headline = `Verified: tests pass and npm audit no longer reports ${targets.length === 0 ? "the targeted issues" : targets.map((t) => t.name).join(", ")}.`;
  } else {
    status = "not-verified";
    headline = !testsPass ? "Tests fail after the change, so it is not verified." : "Tests pass, but some targeted packages are still vulnerable.";
  }
  return { ...base, status, headline, checks, targets, remaining, result };
}

/** S3 and Step Functions calls, injected so the router is tested without AWS. */
export interface VerifyBackend {
  bucket: string;
  put(key: string, body: Buffer | string, contentType: string): Promise<void>;
  get(key: string): Promise<string | null>;
  /** Starts the workflow; the execution is named after the job, so it can be found again by job id. */
  start(jobId: string, input: unknown): Promise<string>;
  describe(jobId: string): Promise<{ status: string; error?: string }>;
}

export async function awsVerifyBackend(env: { bucket: string; stateMachineArn: string }): Promise<VerifyBackend> {
  const { S3Client, PutObjectCommand, GetObjectCommand, NoSuchKey } = await import("@aws-sdk/client-s3");
  const { SFNClient, StartExecutionCommand, DescribeExecutionCommand } = await import("@aws-sdk/client-sfn");
  const s3 = new S3Client({});
  const sfn = new SFNClient({});
  return {
    bucket: env.bucket,
    async put(key, body, contentType) {
      await s3.send(new PutObjectCommand({ Bucket: env.bucket, Key: key, Body: body, ContentType: contentType }));
    },
    async get(key) {
      try {
        const out = await s3.send(new GetObjectCommand({ Bucket: env.bucket, Key: key }));
        return (await out.Body?.transformToString("utf8")) ?? null;
      } catch (err) {
        if (err instanceof NoSuchKey || (err as { name?: string }).name === "NoSuchKey") return null;
        throw err;
      }
    },
    async start(jobId, input) {
      const out = await sfn.send(new StartExecutionCommand({ stateMachineArn: env.stateMachineArn, name: jobId, input: JSON.stringify(input) }));
      return out.executionArn!;
    },
    async describe(jobId) {
      // arn:aws:states:<region>:<account>:stateMachine:<name> -> arn:aws:states:<region>:<account>:execution:<name>:<jobId>
      const executionArn = `${env.stateMachineArn.replace(":stateMachine:", ":execution:")}:${jobId}`;
      const out = await sfn.send(new DescribeExecutionCommand({ executionArn }));
      return { status: out.status ?? "UNKNOWN", error: out.error ?? out.cause };
    },
  };
}

/** Step Functions' evaluate task: reads the build output, applies the trust rule, stores the verdict. */
export async function evaluateJob(backend: VerifyBackend, input: { jobId: string; error?: { Error?: string; Cause?: string } }): Promise<Verdict> {
  const metaRaw = await backend.get(`jobs/${input.jobId}/meta.json`);
  if (!metaRaw) throw new Error(`no meta for job ${input.jobId}`);
  const meta = JSON.parse(metaRaw) as JobMeta;
  const raw = await backend.get(`jobs/${input.jobId}/out/result.json`);
  let result: BuildResult | null = null;
  try {
    result = raw ? (JSON.parse(raw) as BuildResult) : null;
  } catch {
    result = null;
  }
  const err = input.error ? `${input.error.Error ?? "error"}: ${(input.error.Cause ?? "").slice(0, 300)}` : undefined;
  const verdict = evaluate(meta, result, err);
  await backend.put(`jobs/${input.jobId}/verdict.json`, JSON.stringify(verdict), "application/json");
  console.log(JSON.stringify({ audit: "verify.verdict", jobId: meta.jobId, scanId: meta.scanId, status: verdict.status }));
  return verdict;
}
