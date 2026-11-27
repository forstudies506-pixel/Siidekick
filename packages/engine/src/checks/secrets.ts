import type { Check, FileEdit, Finding, Patch } from "../types.js";
import { CODE_EXT, DOC_EXT, lineAt, redact } from "../util.js";

const SKIP_FILE = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|\.env\.example)$/;
// Test fixtures hold made-up passwords the tests depend on; rewriting them breaks the owner's tests.
const TEST_PATH = /(^|\/)(test|tests|__tests__)(\/|$)|\.(test|spec)\.[jt]sx?$/;
const PLACEHOLDER = /(process\.env|your[_-]|xxx|example|changeme|placeholder|<.+>)/i;

/** Generic `name = "literal"` where the name says it is a secret. Group 1 = name, 3 = value. */
const ASSIGN = /\b([A-Za-z0-9_]*(?:api[_-]?key|secret|token|passw(?:or)?d)[A-Za-z0-9_]*)\b["']?\s*[:=]\s*(['"`])([^'"`\s]{8,})\2/gi;
/** Provider key formats. Each is specific enough to be a real credential wherever it appears. */
export const VENDOR_SECRETS: Array<[string, RegExp]> = [
  ["AWS access key", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g],
  ["Stripe live key", /\b(?:sk|rk)_live_[0-9a-zA-Z]{16,}/g],
  ["GitHub token", /\bgh[pousr]_[A-Za-z0-9]{36,}/g],
  ["GitHub fine-grained token", /\bgithub_pat_[A-Za-z0-9_]{60,}/g],
  ["GitLab token", /\bglpat-[A-Za-z0-9_-]{20,}/g],
  ["Slack token", /\bxox[abprs]-[A-Za-z0-9-]{10,}/g],
  ["Slack webhook", /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{20,}/g],
  ["Discord webhook", /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]{40,}/g],
  ["Telegram bot token", /\b\d{8,10}:AA[0-9A-Za-z_-]{33}\b/g],
  ["Google API key", /\bAIza[0-9A-Za-z_-]{35}\b/g],
  ["Google OAuth client secret", /\bGOCSPX-[A-Za-z0-9_-]{28}\b/g],
  ["OpenAI API key", /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20}T3BlbkFJ[A-Za-z0-9_-]{20,}|\bsk-proj-[A-Za-z0-9_-]{40,}/g],
  ["Anthropic API key", /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}/g],
  ["Hugging Face token", /\bhf_[A-Za-z0-9]{34,}\b/g],
  ["Groq API key", /\bgsk_[A-Za-z0-9]{48,}\b/g],
  ["Replicate token", /\br8_[A-Za-z0-9]{37}\b/g],
  ["SendGrid API key", /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g],
  ["Mailgun API key", /\bkey-[0-9a-f]{32}\b/g],
  ["Twilio API key", /\bSK[0-9a-f]{32}\b/g],
  ["npm token", /\bnpm_[A-Za-z0-9]{36}\b/g],
  ["PyPI token", /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}/g],
  ["Shopify access token", /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/g],
  ["Azure storage key", /AccountKey=[A-Za-z0-9+/]{86}==/g],
  ["Private key", /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----/g],
];

/** A database or broker URL with a password in it: scheme://user:password@host. */
const CREDENTIAL_URL = /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver):\/\/[^\s:@/'"`]+:([^\s@/'"`]{4,})@[^\s'"`]+/g;
/** Committed environment files (the example/sample/template ones are meant to be committed). */
const ENV_FILE = /(^|\/)\.env(\.[\w-]+)?$/;
const ENV_EXAMPLE = /\.(example|sample|template|dist|defaults?)$/i;
/** Config formats where values are often unquoted: YAML, INI, TOML, properties, docker-compose. */
const CONFIG_FILE = /\.(ya?ml|ini|toml|properties|cfg|conf)$/i;
const CONFIG_ASSIGN = /^[ \t-]*["']?([A-Za-z0-9_.-]*(?:api[_-]?key|secret|token|passw(?:or)?d|private[_-]?key)[A-Za-z0-9_.-]*)["']?\s*[:=]\s*["']?([^\s"'#]{8,})["']?\s*(?:#.*)?$/gim;
const SECRET_NAME = /(api[_-]?key|secret|token|passw(?:or)?d|private[_-]?key|credential|auth)/i;
/** Values that are references, not secrets: ${VAR}, {{ var }}, $VAR, %(var)s, <placeholder>. */
const REFERENCE = /^\$\{|^\$[A-Z_]|^\{\{|^%\(|^<|^!(Ref|Sub|GetAtt)|^arn:|^(true|false|null|none)$/i;

/** Shannon entropy in bits per character: random keys score high, words and paths low. */
export function entropy(s: string): number {
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

interface Hit { file: string; line: number; name?: string; value: string; kind: string }

function findHits(files: { path: string; content: string }[]): Hit[] {
  const hits: Hit[] = [];
  for (const f of files) {
    if (SKIP_FILE.test(f.path) || /(^|\/)node_modules\//.test(f.path)) continue;
    const seen = new Set<number>();
    const isTest = TEST_PATH.test(f.path);
    // In tests only vendor-format keys count: those are real credentials wherever they sit.
    // Prose and examples in docs often show `password = "..."`; provider-format keys in docs still count.
    for (const m of isTest || DOC_EXT.test(f.path) ? [] : f.content.matchAll(ASSIGN)) {
      if (PLACEHOLDER.test(m[3])) continue;
      const line = lineAt(f.content, m.index!);
      seen.add(line);
      hits.push({ file: f.path, line, name: m[1], value: m[3], kind: "Hardcoded secret" });
    }
    if (!isTest && ENV_FILE.test(f.path) && !ENV_EXAMPLE.test(f.path)) {
      f.content.split("\n").forEach((raw, i) => {
        const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*["']?([^"'\s#]+)["']?/.exec(raw);
        if (!m || seen.has(i + 1) || PLACEHOLDER.test(m[2]) || REFERENCE.test(m[2])) return;
        if (!SECRET_NAME.test(m[1]) && !(m[2].length >= 20 && entropy(m[2]) > 3.5)) return;
        seen.add(i + 1);
        hits.push({ file: f.path, line: i + 1, name: m[1], value: m[2], kind: "Secret in a committed .env file" });
      });
    }
    if (!isTest && CONFIG_FILE.test(f.path)) {
      for (const m of f.content.matchAll(CONFIG_ASSIGN)) {
        const line = lineAt(f.content, m.index!);
        if (seen.has(line) || PLACEHOLDER.test(m[2]) || REFERENCE.test(m[2]) || entropy(m[2]) < 2.5) continue;
        seen.add(line);
        hits.push({ file: f.path, line, name: m[1], value: m[2], kind: "Secret in a config file" });
      }
    }
    for (const m of isTest ? [] : f.content.matchAll(CREDENTIAL_URL)) {
      const line = lineAt(f.content, m.index!);
      if (seen.has(line) || PLACEHOLDER.test(m[1]) || REFERENCE.test(m[1]) || /^(password|pass|pwd|secret|user)$/i.test(m[1])) continue;
      seen.add(line);
      hits.push({ file: f.path, line, value: m[1], kind: "Database URL with a password" });
    }
    for (const [kind, re] of VENDOR_SECRETS) {
      for (const m of f.content.matchAll(re)) {
        const line = lineAt(f.content, m.index!);
        if (seen.has(line)) continue;
        seen.add(line);
        hits.push({ file: f.path, line, value: m[0], kind });
      }
    }
  }
  return hits;
}

/** Secret literals in `files`, so callers can mask them before writing anything the owner might commit. */
export function secretValues(files: { path: string; content: string }[]): string[] {
  return [...new Set(findHits(files).map((h) => h.value))];
}

function envName(name: string | undefined, i: number): string {
  if (!name) return `SECRET_${i + 1}`;
  return name.replace(/([a-z0-9])([A-Z])/g, "$1_$2").replace(/[^A-Za-z0-9]/g, "_").toUpperCase();
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

export const secretsInRepo: Check = {
  id: "secrets-in-repo",
  group: "C-security",
  title: "Secrets out of the repo",
  severity: "critical",
  mode: "auto",

  detect({ repo }): Finding[] {
    return findHits(repo.files).map((h) => ({
      checkId: "secrets-in-repo",
      title: / in |^Database/.test(h.kind) ? h.kind : `${h.kind} in source`,
      severity: "critical",
      file: h.file,
      line: h.line,
      evidence: `${h.name ? h.name + " = " : ""}${redact(h.value)}`,
      explanation: "Anyone who can read this repo can use this key. Move it to an environment variable and rotate it, since it is already in git history.",
    }));
  },

  fix({ repo }): Patch | null {
    // Only code files are rewritten: process.env means nothing inside JSON, YAML or a .env file.
    const hits = findHits(repo.files).filter((h) => !TEST_PATH.test(h.file) && CODE_EXT.test(h.file));
    if (hits.length === 0) return null;
    const byFile = new Map<string, string>(repo.files.map((f) => [f.path, f.content]));
    const edits: FileEdit[] = [];
    const removals: string[] = [];
    const names: string[] = [];

    const grouped = new Map<string, Hit[]>();
    hits.forEach((h) => grouped.set(h.file, [...(grouped.get(h.file) ?? []), h]));
    let i = 0;
    for (const [path, fileHits] of grouped) {
      const before = byFile.get(path)!;
      const lines = before.split("\n");
      for (const h of fileHits) {
        const name = envName(h.name, i++);
        const original = lines[h.line - 1];
        const replaced = original.replace(new RegExp(`(['"\`])${escapeRe(h.value)}\\1`), `process.env.${name}`);
        if (replaced === original) continue; // not a plain string literal (e.g. a PEM block): report only
        lines[h.line - 1] = replaced;
        removals.push(original.trim());
        names.push(name);
      }
      const after = lines.join("\n");
      if (after !== before) edits.push({ kind: "modify", path, before, after });
    }
    if (edits.length === 0) return null;

    const envLines = names.map((n) => `${n}=`).join("\n") + "\n";
    const example = byFile.get(".env.example");
    edits.push(example === undefined
      ? { kind: "create", path: ".env.example", content: envLines }
      : { kind: "modify", path: ".env.example", before: example, after: example.replace(/\n?$/, "\n") + envLines });

    const gi = byFile.get(".gitignore");
    if (gi === undefined) edits.push({ kind: "create", path: ".gitignore", content: ".env\n" });
    else if (!/^\.env$/m.test(gi)) edits.push({ kind: "modify", path: ".gitignore", before: gi, after: gi.replace(/\n?$/, "\n") + ".env\n" });

    return {
      id: "secrets-in-repo-1",
      checkId: "secrets-in-repo",
      title: `Move ${names.length} hardcoded ${names.length === 1 ? "secret" : "secrets"} to environment variables`,
      class: "minimal-edit",
      reason: "Keys in source are readable by anyone with repo access. After applying, rotate each key with its provider.",
      edits,
      allowedRemovals: removals,
    };
  },
};
