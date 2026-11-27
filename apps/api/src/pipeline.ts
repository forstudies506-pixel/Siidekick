import { PublishCommand, SNSClient } from "@aws-sdk/client-sns";
import {
  buildChangeReport,
  changeReportHtml,
  changeReportMarkdown,
  cycloneDx,
  registry,
  runScan,
  secretValues,
  type Finding,
  type ScanReport,
  type Severity,
} from "@siidekick/engine";
import { artifactsFromEnv, type Artifacts } from "./artifacts.js";
import { advisoryIds, bedrockExplainer, excerptFor, fetchAdvisory, findingKey, UngroundedError, type Explainer } from "./explain.js";
import { fetchGithubRepo, FULL_LIMITS } from "./github.js";
import { proposePatches } from "./patching.js";
import { cachedScanFetch } from "./router.js";
import { createStore, type ScanRecord, type Store } from "./store.js";

/**
 * The AWS pipeline behind a scan, one Lambda handler per Step Functions stage:
 *
 *   prepare → explain → propose → [verify: CodeBuild, run by Step Functions] → collect
 *                                   any failure → fail
 *
 * prepare  re-reads the whole GitHub repo with the large limits when the quick scan had to leave files out
 * explain  asks Bedrock for grounded explanations of the worst findings
 * propose  generates the guard-checked patches and puts the original and patched snapshots in S3
 * collect  reads CodeBuild's result (install, build, tests, Trivy before/after) and writes the change report and SBOM
 * rescan   (EventBridge, daily) rechecks watched scans against today's advisories and alerts on new findings
 */

export interface PipelineDeps {
  store: Store;
  artifacts: Artifacts;
  fetch: typeof fetch;
  explainer: Explainer | null;
  /** Run untrusted repos' install and tests in CodeBuild. Off by default: only the demo shop is verified. */
  verifyUntrusted: boolean;
  notify?: (subject: string, message: string) => Promise<void>;
  now?: () => Date;
}

export interface PipelineState {
  scanId: string;
  fullScan?: boolean;
  files?: number;
  explained?: number;
  explainSkipped?: string;
  patches?: number;
  verify?: boolean;
  bucket?: string;
  originalKey?: string;
  patchedKey?: string;
  resultKey?: string;
  reportKey?: string;
  sbomKey?: string;
  error?: { Error?: string; Cause?: string };
}

export type StageEvent =
  | { stage: "prepare" | "explain" | "propose" | "collect" | "fail"; state: PipelineState }
  | { stage: "rescan" };

const SEV: Severity[] = ["critical", "high", "medium", "low", "info"];
const MAX_EXPLAIN = 8;

async function load(deps: PipelineDeps, id: string): Promise<ScanRecord> {
  const rec = await deps.store.get(id);
  if (!rec) throw new Error(`scan ${id} not found`);
  return rec;
}

function mark(rec: ScanRecord, deps: PipelineDeps, stage: string, status = "running"): void {
  rec.pipeline = { executionArn: rec.pipeline?.executionArn ?? "", status, stage, updatedAt: (deps.now?.() ?? new Date()).toISOString() };
}

const keys = (id: string) => ({
  originalKey: `verify/${id}/original.json`,
  patchedKey: `verify/${id}/patched.json`,
  resultKey: `verify/${id}/result.json`,
  reportKey: `reports/${id}/change-report`,
  sbomKey: `reports/${id}/sbom.cdx.json`,
});

async function prepare(deps: PipelineDeps, state: PipelineState): Promise<PipelineState> {
  const rec = await load(deps, state.scanId);
  mark(rec, deps, "prepare");
  let fullScan = false;
  if (rec.source?.kind === "github" && (rec.omitted ?? 0) > 0) {
    // The quick scan left files out; read everything this time.
    const { omitted, ...repo } = await fetchGithubRepo(rec.source.url, { fetch: deps.fetch, limits: FULL_LIMITS });
    rec.repo = repo;
    rec.report = await runScan({ repo, fetch: deps.fetch }, registry);
    rec.omitted = omitted;
    rec.patches = undefined;
    fullScan = true;
  }
  await deps.artifacts.putJson(keys(rec.id).originalKey, rec.repo, { gzip: true });
  await deps.store.put(rec.id, rec);
  return { ...state, fullScan, files: rec.repo.files.length };
}

function worstFindings(report: ScanReport): Finding[] {
  return report.results
    .filter((r) => !r.skipped && !r.passed)
    .flatMap((r) => r.findings)
    .filter((f) => f.severity === "critical" || f.severity === "high")
    .sort((a, b) => SEV.indexOf(a.severity) - SEV.indexOf(b.severity))
    .slice(0, MAX_EXPLAIN);
}

async function explain(deps: PipelineDeps, state: PipelineState): Promise<PipelineState> {
  const rec = await load(deps, state.scanId);
  mark(rec, deps, "explain");
  if (!deps.explainer) {
    await deps.store.put(rec.id, rec);
    return { ...state, explained: 0, explainSkipped: "no Bedrock model configured" };
  }
  const secrets = secretValues(rec.repo.files);
  const out: NonNullable<ScanRecord["explanations"]> = { ...(rec.explanations ?? {}) };
  let rejected = 0;
  for (const f of worstFindings(rec.report)) {
    const key = findingKey(f);
    if (out[key]) continue;
    const ids = f.checkId === "dependency-audit" ? advisoryIds(f) : [];
    const advisory = ids.length ? await fetchAdvisory(ids.find((i) => i.startsWith("GHSA")) ?? ids[0], deps.fetch) : undefined;
    try {
      const e = await deps.explainer.explain(f, { excerpt: excerptFor(rec.repo, f, secrets), advisory });
      out[key] = { text: e.text, model: e.model, advisory: advisory?.id, at: (deps.now?.() ?? new Date()).toISOString() };
    } catch (err) {
      // An ungrounded or failed answer is dropped; the rule's own explanation stays.
      if (err instanceof UngroundedError) rejected++;
      else console.error("explain failed:", err);
    }
  }
  rec.explanations = out;
  await deps.store.put(rec.id, rec);
  return { ...state, explained: Object.keys(out).length, ...(rejected ? { explainSkipped: `${rejected} answer(s) rejected as not grounded in the evidence` } : {}) };
}

async function propose(deps: PipelineDeps, state: PipelineState): Promise<PipelineState> {
  const rec = await load(deps, state.scanId);
  mark(rec, deps, "propose");
  const { entries, patched, after } = await proposePatches(rec.repo, rec.report, deps.fetch);
  // Keep approvals the owner already made while the pipeline ran.
  const approved = new Set((rec.patches ?? []).filter((p) => p.approved).map((p) => p.patchId));
  rec.patches = entries.map((e) => ({ ...e, approved: approved.has(e.patchId) }));
  rec.after = after;
  const verify = rec.demo === true || deps.verifyUntrusted;
  const k = keys(rec.id);
  await deps.artifacts.putJson(k.patchedKey, patched, { gzip: true });
  if (verify) rec.verification = { status: "pending", where: "AWS CodeBuild (isolated)" };
  await deps.store.put(rec.id, rec);
  return { ...state, patches: entries.length, verify, bucket: deps.artifacts.bucket, originalKey: k.originalKey, patchedKey: k.patchedKey, resultKey: k.resultKey };
}

interface VariantResult {
  install?: { ok: boolean; detail?: string };
  build?: { ok: boolean; detail?: string };
  tests?: { ok: boolean; detail?: string };
  trivy?: { vulns: number };
}

interface VerifyResult {
  original: VariantResult;
  patched: VariantResult;
  buildId?: string;
}

async function collect(deps: PipelineDeps, state: PipelineState): Promise<PipelineState> {
  const rec = await load(deps, state.scanId);
  mark(rec, deps, "collect");
  const k = keys(rec.id);
  const result = state.verify ? await deps.artifacts.getJson<VerifyResult>(k.resultKey) : null;
  if (result) {
    const p = result.patched;
    const regression = result.original.tests?.ok === true && p.tests?.ok === false;
    rec.verification = {
      status: "done",
      where: "AWS CodeBuild (isolated)",
      buildId: result.buildId,
      install: p.install,
      build: p.build,
      tests: p.tests && { ok: p.tests.ok, detail: regression ? "passed before the patches and fail after them" : p.tests.detail },
      scanner: result.original.trivy && p.trivy ? { name: "Trivy", before: result.original.trivy.vulns, after: p.trivy.vulns } : undefined,
    };
  } else if (state.verify) {
    rec.verification = { status: "failed", where: "AWS CodeBuild (isolated)", install: { ok: false, detail: "the build wrote no result" } };
  }

  // The proposal report: every guard-accepted patch, as if approved, with the evidence gathered so far.
  const after = rec.after ?? (await runScan({ repo: rec.repo, fetch: deps.fetch }, registry));
  const report = buildChangeReport({
    repo: rec.repo.name,
    original: rec.repo,
    before: rec.report,
    after,
    patches: (rec.patches ?? []).map((p) => ({ patch: p.patch, guard: p.guard, approved: p.guard.ok })),
    verification: rec.verification?.status === "done" ? rec.verification : undefined,
    replay: rec.replay,
  });
  await deps.artifacts.putText(`${k.reportKey}.md`, changeReportMarkdown(report), "text/markdown; charset=utf-8");
  await deps.artifacts.putText(`${k.reportKey}.html`, changeReportHtml(report), "text/html; charset=utf-8");
  const bom = cycloneDx(rec.repo);
  if (bom) await deps.artifacts.putJson(k.sbomKey, bom);
  mark(rec, deps, "done", "succeeded");
  await deps.store.put(rec.id, rec);
  return { ...state, reportKey: k.reportKey, ...(bom ? { sbomKey: k.sbomKey } : {}) };
}

async function fail(deps: PipelineDeps, state: PipelineState): Promise<PipelineState> {
  const rec = await deps.store.get(state.scanId);
  const cause = state.error?.Cause ?? state.error?.Error ?? "unknown error";
  if (rec) {
    mark(rec, deps, rec.pipeline?.stage ?? "unknown", "failed");
    rec.pipeline!.error = cause.slice(0, 500);
    if (rec.verification?.status === "pending" || rec.verification?.status === "running") rec.verification.status = "failed";
    await deps.store.put(rec.id, rec);
  }
  await deps.notify?.("Siidekick pipeline failed", `Scan ${state.scanId} failed: ${cause.slice(0, 1000)}`);
  return state;
}

/** Daily: rescan every watched record against today's advisories; alert on findings that were not there before. */
async function rescan(deps: PipelineDeps): Promise<{ checked: number; alerts: number }> {
  const index = (await deps.artifacts.getJson<{ ids: string[] }>("watch/index.json")) ?? { ids: [] };
  let alerts = 0;
  const alive: string[] = [];
  for (const id of index.ids) {
    const rec = await deps.store.get(id);
    if (!rec || !rec.watch) continue; // expired or unwatched records drop out of the index
    alive.push(id);
    const now = await runScan({ repo: rec.repo, fetch: deps.fetch }, registry);
    const known = new Set(rec.report.results.flatMap((r) => r.findings.map(findingKey)));
    const fresh = now.results.flatMap((r) => r.findings).filter((f) => !known.has(findingKey(f)) && (f.severity === "critical" || f.severity === "high"));
    if (fresh.length === 0) continue;
    const at = (deps.now?.() ?? new Date()).toISOString();
    rec.alerts = [...fresh.map((f) => ({ at, title: f.title, severity: f.severity, detail: f.evidence ?? f.explanation.slice(0, 200) })), ...(rec.alerts ?? [])].slice(0, 50);
    await deps.store.put(id, rec);
    alerts += fresh.length;
    await deps.notify?.(`Siidekick: ${fresh.length} new finding(s) in ${rec.repo.name}`, fresh.map((f) => `[${f.severity}] ${f.title}${f.evidence ? ` — ${f.evidence}` : ""}`).join("\n"));
  }
  await deps.artifacts.putJson("watch/index.json", { ids: alive });
  return { checked: alive.length, alerts };
}

export async function runStage(deps: PipelineDeps, event: StageEvent): Promise<unknown> {
  switch (event.stage) {
    case "prepare":
      return prepare(deps, event.state);
    case "explain":
      return explain(deps, event.state);
    case "propose":
      return propose(deps, event.state);
    case "collect":
      return collect(deps, event.state);
    case "fail":
      return fail(deps, event.state);
    case "rescan":
      return rescan(deps);
    default:
      throw new Error(`unknown stage ${(event as { stage: string }).stage}`);
  }
}

function depsFromEnv(): PipelineDeps {
  const artifacts = artifactsFromEnv();
  if (!artifacts) throw new Error("ARTIFACTS_BUCKET is required for the pipeline");
  const topic = process.env.ALERT_TOPIC_ARN;
  const sns = topic ? new SNSClient({}) : null;
  return {
    store: createStore(),
    artifacts,
    fetch: cachedScanFetch(fetch),
    explainer: process.env.BEDROCK_MODEL_ID ? bedrockExplainer({ modelId: process.env.BEDROCK_MODEL_ID }) : null,
    verifyUntrusted: process.env.VERIFY_UNTRUSTED === "true",
    notify: sns ? async (subject, message) => void (await sns.send(new PublishCommand({ TopicArn: topic, Subject: subject.slice(0, 100), Message: message }))) : undefined,
  };
}

let cached: PipelineDeps | null = null;

/** Lambda entry point. Step Functions passes { stage, state }; EventBridge's schedule passes { stage: "rescan" }. */
export const handler = async (event: StageEvent): Promise<unknown> => {
  cached ??= depsFromEnv();
  return runStage(cached, event);
};
