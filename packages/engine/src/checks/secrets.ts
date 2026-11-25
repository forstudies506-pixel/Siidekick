import type { Check, FileEdit, Finding, Patch } from "../types.js";
import { lineAt, redact } from "../util.js";

const SKIP_FILE = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|\.env\.example)$/;
// Test fixtures hold made-up passwords the tests depend on; rewriting them breaks the owner's tests.
const TEST_PATH = /(^|\/)(test|tests|__tests__)(\/|$)|\.(test|spec)\.[jt]sx?$/;
const PLACEHOLDER = /(process\.env|your[_-]|xxx|example|changeme|placeholder|<.+>)/i;

/** Generic `name = "literal"` where the name says it is a secret. Group 1 = name, 3 = value. */
const ASSIGN = /\b([A-Za-z0-9_]*(?:api[_-]?key|secret|token|passw(?:or)?d)[A-Za-z0-9_]*)\b["']?\s*[:=]\s*(['"`])([^'"`\s]{8,})\2/gi;
const VENDOR: Array<[string, RegExp]> = [
  ["AWS access key", /AKIA[0-9A-Z]{16}/g],
  ["Stripe live key", /sk_live_[0-9a-zA-Z]{16,}/g],
  ["GitHub token", /gh[pousr]_[A-Za-z0-9]{36,}/g],
  ["Private key", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g],
];

interface Hit { file: string; line: number; name?: string; value: string; kind: string }

function findHits(files: { path: string; content: string }[]): Hit[] {
  const hits: Hit[] = [];
  for (const f of files) {
    if (SKIP_FILE.test(f.path)) continue;
    const seen = new Set<number>();
    const isTest = TEST_PATH.test(f.path);
    // In tests only vendor-format keys count: those are real credentials wherever they sit.
    for (const m of isTest ? [] : f.content.matchAll(ASSIGN)) {
      if (PLACEHOLDER.test(m[3])) continue;
      const line = lineAt(f.content, m.index!);
      seen.add(line);
      hits.push({ file: f.path, line, name: m[1], value: m[3], kind: "Hardcoded secret" });
    }
    for (const [kind, re] of VENDOR) {
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
      title: `${h.kind} in source`,
      severity: "critical",
      file: h.file,
      line: h.line,
      evidence: `${h.name ? h.name + " = " : ""}${redact(h.value)}`,
      explanation: "Anyone who can read this repo can use this key. Move it to an environment variable and rotate it, since it is already in git history.",
    }));
  },

  fix({ repo }): Patch | null {
    const hits = findHits(repo.files).filter((h) => !TEST_PATH.test(h.file));
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
      title: `Move ${names.length} hardcoded secret(s) to environment variables`,
      class: "minimal-edit",
      reason: "Keys in source are readable by anyone with repo access. After applying, rotate each key with its provider.",
      edits,
      allowedRemovals: removals,
    };
  },
};
