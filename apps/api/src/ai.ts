/**
 * AI explanations on Amazon Bedrock. The model explains a finding in the owner's language; it never writes
 * patches (those stay deterministic templates behind the diff guard). Every answer goes through
 * groundingCheck: an explanation that names an advisory id or version absent from the evidence is
 * rejected, so the model cannot invent a CVE or a "fixed in" version.
 */
import type { Finding } from "@siidekick/engine";

export const LANGUAGES = {
  en: "English",
  hi: "Hindi (हिन्दी)",
  bn: "Bengali (বাংলা)",
  mr: "Marathi (मराठी)",
  ta: "Tamil (தமிழ்)",
  te: "Telugu (తెలుగు)",
  gu: "Gujarati (ગુજરાતી)",
  kn: "Kannada (ಕನ್ನಡ)",
} as const;
export type Lang = keyof typeof LANGUAGES;
export const isLang = (v: unknown): v is Lang => typeof v === "string" && v in LANGUAGES;

export interface Explanation {
  /** One or two sentences a non-expert understands. */
  summary: string;
  /** What could happen to the app and its users. */
  impact: string;
  /** What to do, step by step. */
  fix: string;
  /** Remediation options and their trade-offs. */
  options: Array<{ option: string; tradeoff: string }>;
  /** What the evidence does not settle (reachability, exploit availability…). */
  unknowns: string;
}

export interface ExplainResult {
  explanation: Explanation;
  lang: Lang;
  model: string;
  /** Tokens the evidence does not contain. Non-empty means the answer was rejected. */
  ungrounded: string[];
  ms: number;
}

/** What the model may use: the finding and, when there is one, the proposed patch's reason. Nothing else. */
export function evidenceFor(f: Finding, extra: { patchReason?: string; repo?: string } = {}): string {
  const lines = [
    `TARGET: code repository ${extra.repo ?? ""}`.trim(),
    `CHECK: ${f.checkId}`,
    `TITLE: ${f.title}`,
    `SEVERITY: ${f.severity}`,
    f.file ? `LOCATION: ${f.file}${f.line ? `:${f.line}` : ""}` : "",
    f.evidence ? `SCANNER EVIDENCE: ${f.evidence}` : "",
    `SCANNER EXPLANATION: ${f.explanation}`,
    f.remedy ? `SUGGESTED REMEDY: ${f.remedy}` : "",
    f.chain && f.chain.length > 0 ? `DEPENDENCY PATH (app first): ${["your app", ...f.chain].join(" -> ")}` : "",
    ...(f.advisories ?? []).map(
      (a) =>
        `ADVISORY ${a.id}${a.aliases.length ? ` (${a.aliases.join(", ")})` : ""}: ${a.summary ?? "no summary"}; ` +
        `severity ${a.severity ?? "not listed"}; fixed in ${a.fixed ?? "no fixed version published"}`,
    ),
    extra.patchReason ? `PROPOSED SIIDEKICK PATCH: ${extra.patchReason}` : "",
  ];
  return lines.filter(Boolean).join("\n");
}

const ID_RE = /\b(?:CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})\b/gi;
const VERSION_RE = /\bv?\d+\.\d+\.\d+(?:-[0-9a-z.]+)?\b/gi;

/** Advisory ids and versions in `text` that `evidence` does not contain. */
export function groundingCheck(text: string, evidence: string): string[] {
  const ev = evidence.toLowerCase();
  const found = new Set<string>();
  for (const re of [ID_RE, VERSION_RE]) for (const m of text.matchAll(re)) found.add(m[0]);
  return [...found].filter((t) => !ev.includes(t.toLowerCase().replace(/^v/, "")));
}

function systemPrompt(lang: Lang): string {
  return [
    "You are Siidekick, a patient security mentor for small Indian businesses, student developers and colleges who have no security engineer.",
    `Write every value in ${LANGUAGES[lang]}. Keep package names, file names, commands, advisory ids, version numbers and brand or product names (Razorpay, Paytm, PhonePe, UPI, Aadhaar, PAN, OTP, GitHub) exactly as written in Latin letters (do not translate or transliterate them).`,
    "Use ONLY the facts in the EVIDENCE block. Do not mention any CVE, GHSA id, version number, exploit or statistic that is not in the evidence.",
    "If the evidence does not say whether the vulnerable code is reachable or exploited in the wild, say that it is unknown, in the unknowns field.",
    "Never say the app is or will be fully secure. Plain words, short sentences, no jargon without a one-line meaning.",
    'Reply with one JSON object only, no markdown: {"summary": string, "impact": string, "fix": string, "options": [{"option": string, "tradeoff": string}], "unknowns": string}. 1 to 3 options.',
  ].join("\n");
}

function parseExplanation(raw: string): Explanation | null {
  const start = raw.indexOf("{");
  const end = raw.lastIndexOf("}");
  if (start === -1 || end <= start) return null;
  let v: unknown;
  try {
    v = JSON.parse(raw.slice(start, end + 1));
  } catch {
    return null;
  }
  const o = v as Record<string, unknown>;
  const str = (x: unknown) => (typeof x === "string" ? x.trim().slice(0, 1500) : "");
  const options = Array.isArray(o.options)
    ? o.options
        .slice(0, 3)
        .map((x) => ({ option: str((x as Record<string, unknown>)?.option), tradeoff: str((x as Record<string, unknown>)?.tradeoff) }))
        .filter((x) => x.option)
    : [];
  const e = { summary: str(o.summary), impact: str(o.impact), fix: str(o.fix), options, unknowns: str(o.unknowns) };
  return e.summary && e.fix ? e : null;
}

/** The slice of the Bedrock Converse API we use; injected so tests run offline. */
export type ConverseFn = (req: {
  modelId: string;
  system: string;
  user: string;
  maxTokens: number;
}) => Promise<string>;

export async function bedrockConverse(region?: string): Promise<ConverseFn> {
  const { BedrockRuntimeClient, ConverseCommand } = await import("@aws-sdk/client-bedrock-runtime");
  const client = new BedrockRuntimeClient(region ? { region } : {});
  return async ({ modelId, system, user, maxTokens }) => {
    const out = await client.send(
      new ConverseCommand({
        modelId,
        system: [{ text: system }],
        messages: [{ role: "user", content: [{ text: user }] }],
        inferenceConfig: { maxTokens, temperature: 0.2 },
      }),
    );
    return (out.output?.message?.content ?? []).map((c) => ("text" in c && c.text ? c.text : "")).join("");
  };
}

/**
 * Explains one finding. Tries twice: a first answer that fails the grounding check is retried once with
 * the offending tokens named; a second failure is returned with `ungrounded` set so the UI can refuse it.
 */
export async function explainFinding(opts: {
  converse: ConverseFn;
  modelId: string;
  finding: Finding;
  lang: Lang;
  patchReason?: string;
  repo?: string;
}): Promise<ExplainResult> {
  const t0 = Date.now();
  const evidence = evidenceFor(opts.finding, opts);
  let user = `EVIDENCE:\n${evidence}\n\nExplain this finding for the owner.`;
  let last: { e: Explanation | null; bad: string[] } = { e: null, bad: [] };
  for (let attempt = 0; attempt < 2; attempt++) {
    const raw = await opts.converse({ modelId: opts.modelId, system: systemPrompt(opts.lang), user, maxTokens: 900 });
    const e = parseExplanation(raw);
    const bad = e ? groundingCheck(JSON.stringify(e), evidence) : [];
    last = { e, bad };
    if (e && bad.length === 0) break;
    user =
      `EVIDENCE:\n${evidence}\n\n` +
      (e ? `Your previous answer mentioned ${bad.join(", ")}, which are not in the evidence. Remove them.` : "Your previous answer was not valid JSON.") +
      " Explain this finding for the owner, JSON only.";
  }
  if (!last.e) throw new Error("the model did not return a usable explanation");
  return { explanation: last.e, lang: opts.lang, model: opts.modelId, ungrounded: last.bad, ms: Date.now() - t0 };
}
