import { describe, expect, it } from "vitest";
import type { Finding } from "@siidekick/engine";
import { runStage, type PipelineDeps, type PipelineState } from "../src/pipeline.js";
import { bedrockExplainer, checkGrounded, UngroundedError, type Explainer } from "../src/explain.js";
import { makeRouter } from "../src/router.js";
import type { Artifacts } from "../src/artifacts.js";
import type { ScanRecord, Store } from "../src/store.js";

function memStore(): Store & { data: Map<string, ScanRecord> } {
  const data = new Map<string, ScanRecord>();
  return { kind: "local", data, get: async (id) => structuredClone(data.get(id) ?? null), put: async (id, r) => void data.set(id, structuredClone(r)) };
}

function memArtifacts(): Artifacts & { objects: Map<string, unknown> } {
  const objects = new Map<string, unknown>();
  return {
    bucket: "test-bucket",
    objects,
    putJson: async (k, v) => void objects.set(k, structuredClone(v)),
    getJson: async <T,>(k: string) => (objects.has(k) ? (structuredClone(objects.get(k)) as T) : null),
    putText: async (k, t) => void objects.set(k, t),
  };
}

const offline = (async () => new Response("{}", { status: 404 })) as unknown as typeof fetch;

describe("Bedrock explanations stay grounded", () => {
  it("accepts a cited answer and rejects one that cites nothing or invents an advisory", async () => {
    expect(() => checkGrounded("Fix it. [sql-string-concat]", "sql-string-concat", [])).not.toThrow();
    expect(() => checkGrounded("Fix it.", "sql-string-concat", [])).toThrow(UngroundedError);
    expect(() => checkGrounded("Like CVE-2021-44228. [GHSA-p6mc-m468-83gg]", "GHSA-p6mc-m468-83gg", ["GHSA-p6mc-m468-83gg", "CVE-2021-23337"])).toThrow(/CVE-2021-44228/);

    const sent: unknown[] = [];
    const client = { send: async (cmd: { input: unknown }) => (sent.push(cmd.input), { output: { message: { content: [{ text: "An attacker can read every row. Use placeholders. [sql-string-concat]" }] } } }) };
    const ex = bedrockExplainer({ modelId: "amazon.nova-lite-v1:0", client: client as never });
    const f: Finding = { checkId: "sql-string-concat", title: "SQL", severity: "critical", file: "a.js", line: 1, explanation: "x" };
    const out = await ex.explain(f, { excerpt: "   1| db.query('…' + q)" });
    expect(out).toMatchObject({ cites: "sql-string-concat", model: "amazon.nova-lite-v1:0" });
    expect(JSON.stringify(sent[0])).toContain("db.query"); // the model saw the code, not just the title
  });
});

describe("pipeline stages", () => {
  const demoRepo = {
    name: "shop",
    files: [
      { path: "package.json", content: JSON.stringify({ name: "shop", scripts: { test: "node --test" } }) },
      { path: "server.js", content: "const express = require('express');\nconst app = express();\napp.get('/', (req, res) => res.send('ok'));\napp.listen(3000);\n" },
    ],
  };

  async function seeded(): Promise<{ deps: PipelineDeps; store: ReturnType<typeof memStore>; artifacts: ReturnType<typeof memArtifacts> }> {
    const store = memStore();
    const artifacts = memArtifacts();
    const router = makeRouter({ store, fetch: offline, startPipeline: async (id) => `arn:aws:states:test:exec:${id}` });
    const res = await router.handle({ method: "POST", path: "/api/scans", body: { name: "shop", files: demoRepo.files } });
    const id = (res.body as { id: string }).id;
    const rec = store.data.get(id)!;
    store.data.set(id, { ...rec, demo: true });
    const explainer: Explainer = { model: "fake", explain: async (f) => ({ text: `Explained. [${f.checkId}]`, model: "fake", cites: f.checkId }) };
    return { deps: { store, artifacts, fetch: offline, explainer, verifyUntrusted: false }, store, artifacts };
  }

  it("runs prepare → explain → propose → verify result → collect and writes the report", async () => {
    const { deps, store, artifacts } = await seeded();
    const id = [...store.data.keys()][0];
    expect(store.data.get(id)!.pipeline).toMatchObject({ status: "running", executionArn: `arn:aws:states:test:exec:${id}` });

    let state: PipelineState = { scanId: id };
    state = (await runStage(deps, { stage: "prepare", state })) as PipelineState;
    expect(artifacts.objects.has(`verify/${id}/original.json`)).toBe(true);
    state = (await runStage(deps, { stage: "explain", state })) as PipelineState;
    expect(state.explained).toBeGreaterThan(0);
    state = (await runStage(deps, { stage: "propose", state })) as PipelineState;
    expect(state).toMatchObject({ verify: true, bucket: "test-bucket", resultKey: `verify/${id}/result.json` });
    expect(store.data.get(id)!.verification?.status).toBe("pending");

    // What the CodeBuild runner writes: tests pass before and after, Trivy finds 3 then 1.
    await artifacts.putJson(state.resultKey!, {
      original: { install: { ok: true }, tests: { ok: true }, trivy: { vulns: 3 } },
      patched: { install: { ok: true }, tests: { ok: true }, trivy: { vulns: 1 } },
      buildId: "siidekick-verify:1",
    });
    state = (await runStage(deps, { stage: "collect", state })) as PipelineState;

    const rec = store.data.get(id)!;
    expect(rec.pipeline).toMatchObject({ status: "succeeded", stage: "done" });
    expect(rec.verification).toMatchObject({ status: "done", where: "AWS CodeBuild (isolated)", tests: { ok: true }, scanner: { name: "Trivy", before: 3, after: 1 } });
    expect(Object.values(rec.explanations!)[0].text).toMatch(/\[[\w-]+\]$/);
    const md = artifacts.objects.get(`${state.reportKey}.md`) as string;
    expect(md).toContain("AWS CodeBuild (isolated): the project's tests passed");
    expect(md).toContain("Trivy (independent scanner): 3 → 1");
  });

  it("marks the scan failed and alerts when a stage fails", async () => {
    const { deps, store } = await seeded();
    const sent: string[] = [];
    deps.notify = async (s) => void sent.push(s);
    const id = [...store.data.keys()][0];
    await runStage(deps, { stage: "fail", state: { scanId: id, error: { Error: "Lambda.Unknown", Cause: "boom" } } });
    expect(store.data.get(id)!.pipeline).toMatchObject({ status: "failed", error: "boom" });
    expect(sent).toEqual(["Siidekick pipeline failed"]);
  });

  it("daily rescan alerts only on findings that are new since the scan", async () => {
    const { deps, store, artifacts } = await seeded();
    const id = [...store.data.keys()][0];
    const rec = store.data.get(id)!;
    // Pretend the original scan found nothing for secrets; today's rescan of the same code finds a key.
    const withKey = { ...rec, watch: true, repo: { ...rec.repo, files: [...rec.repo.files, { path: "k.js", content: `const k = "${"ghp_" + "b".repeat(36)}";\n` }] } };
    store.data.set(id, withKey);
    await artifacts.putJson("watch/index.json", { ids: [id, "gone-id"] });
    const sent: string[] = [];
    deps.notify = async (s) => void sent.push(s);
    const out = (await runStage(deps, { stage: "rescan" })) as { checked: number; alerts: number };
    expect(out).toEqual({ checked: 1, alerts: 1 });
    expect(store.data.get(id)!.alerts![0]).toMatchObject({ severity: "critical", title: "GitHub token in source" });
    expect(sent[0]).toMatch(/1 new finding/);
    expect(await artifacts.getJson("watch/index.json")).toEqual({ ids: [id] }); // expired ids drop out
  });
});
