import { BedrockRuntimeClient, ConverseCommand } from "@aws-sdk/client-bedrock-runtime";
import type { Finding, RepoSnapshot } from "@siidekick/engine";

/**
 * Plain-language explanations from a model on Amazon Bedrock, kept tied to evidence:
 * - the model sees only the finding, ~30 lines of code around it (secrets masked) and, for a
 *   dependency, the advisory text fetched from OSV.dev;
 * - an answer must cite the check id or advisory id it was given, and may not name any CVE/GHSA id
 *   that was not in the evidence; otherwise it is rejected and the template text stays.
 * Explanations are labelled as AI-written wherever they are shown.
 */

export interface Advisory {
  id: string;
  aliases: string[];
  summary?: string;
  details?: string;
}

export interface Explanation {
  text: string;
  model: string;
  /** The id the answer cites (advisory or check). */
  cites: string;
}

export class UngroundedError extends Error {}

export interface Explainer {
  readonly model: string;
  explain(finding: Finding, ctx: { excerpt: string; advisory?: Advisory }): Promise<Explanation>;
}

const SYSTEM = [
  "You explain one security finding to the owner of a small web app who is not a security expert.",
  "Use only the evidence in the message: the finding, the code excerpt and the advisory, if any.",
  "Never invent CVE or GHSA ids, versions, file names or behaviour the evidence does not show; when the evidence does not settle something, say so.",
  "Write at most 170 words in three short parts: what an attacker could do here, the smallest safe fix (with a code line when it helps), and what to test after the fix.",
  "End with the citation token you were given, in square brackets, exactly as written.",
].join(" ");

const IDS = /\b(CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})\b/gi;

/** Lines around the finding, numbered, with known secret values masked. */
export function excerptFor(repo: RepoSnapshot, finding: Finding, secrets: string[], radius = 15): string {
  const file = finding.file ? repo.files.find((f) => f.path === finding.file) : undefined;
  if (!file) return "";
  const lines = file.content.split("\n");
  const at = Math.max(1, finding.line ?? 1);
  const from = Math.max(1, at - radius);
  const to = Math.min(lines.length, at + radius);
  let text = lines.slice(from - 1, to).map((l, i) => `${String(from + i).padStart(4)}| ${l}`).join("\n");
  for (const s of secrets) if (s.length >= 6) text = text.split(s).join(`${s.slice(0, 3)}…[masked]`);
  return text.slice(0, 6000);
}

/** The advisory ids named in a dependency finding's evidence, e.g. "GHSA-p6mc-m468-83gg / CVE-2021-23337". */
export function advisoryIds(f: Finding): string[] {
  return [...new Set([...(f.evidence ?? "").matchAll(IDS)].map((m) => m[1].toUpperCase()))];
}

/** Full advisory text from OSV.dev, so the model explains the real advisory rather than its memory of it. */
export async function fetchAdvisory(id: string, fetchFn: typeof fetch = fetch): Promise<Advisory | undefined> {
  try {
    const res = await fetchFn(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(6000) });
    if (!res.ok) return undefined;
    const v = (await res.json()) as { id?: string; aliases?: string[]; summary?: string; details?: string };
    return { id: v.id ?? id, aliases: v.aliases ?? [], summary: v.summary, details: v.details?.slice(0, 4000) };
  } catch {
    return undefined;
  }
}

/** Reject answers that cite nothing or name ids that were not in the evidence. */
export function checkGrounded(text: string, cite: string, allowedIds: string[]): void {
  if (!text.trim()) throw new UngroundedError("empty answer");
  if (!text.includes(`[${cite}]`)) throw new UngroundedError(`answer does not cite [${cite}]`);
  const allowed = new Set(allowedIds.map((s) => s.toUpperCase()));
  for (const m of text.matchAll(IDS)) {
    if (!allowed.has(m[1].toUpperCase())) throw new UngroundedError(`answer names ${m[1]}, which is not in the evidence`);
  }
}

export function bedrockExplainer(opts: { modelId: string; client?: Pick<BedrockRuntimeClient, "send">; timeoutMs?: number }): Explainer {
  const client = opts.client ?? new BedrockRuntimeClient({});
  return {
    model: opts.modelId,
    async explain(finding, ctx) {
      const cite = ctx.advisory?.id ?? finding.checkId;
      const allowed = [...advisoryIds(finding), ...(ctx.advisory ? [ctx.advisory.id, ...ctx.advisory.aliases] : [])];
      const evidence = {
        citation_token: cite,
        finding: { check: finding.checkId, title: finding.title, severity: finding.severity, file: finding.file, line: finding.line, evidence: finding.evidence, rule_explanation: finding.explanation, suggested_fix: finding.remedy },
        code_excerpt: ctx.excerpt || "(no code excerpt: the finding is about configuration or a dependency)",
        advisory: ctx.advisory ?? null,
      };
      const out = await client.send(
        new ConverseCommand({
          modelId: opts.modelId,
          system: [{ text: SYSTEM }],
          messages: [{ role: "user", content: [{ text: JSON.stringify(evidence) }] }],
          inferenceConfig: { maxTokens: 450, temperature: 0 },
        }),
        { abortSignal: AbortSignal.timeout(opts.timeoutMs ?? 20_000) },
      );
      const text = (out.output?.message?.content ?? []).map((c) => ("text" in c && typeof c.text === "string" ? c.text : "")).join("").trim();
      checkGrounded(text, cite, allowed);
      return { text, model: opts.modelId, cites: cite };
    },
  };
}

/** Stable key for a finding, shared by the pipeline, the record and the UI. */
export function findingKey(f: Finding): string {
  return `${f.checkId}|${f.file ?? ""}|${f.line ?? ""}|${f.title}`;
}
