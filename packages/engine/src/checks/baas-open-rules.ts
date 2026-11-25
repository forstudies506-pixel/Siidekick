import type { Check, FileEdit, Finding, Patch, RepoFile, Severity } from "../types.js";
import { lineAt } from "../util.js";

const SKIP = /(^|\/)node_modules\//;
const FIREBASE_RULES = /(^|\/)[\w.-]*\.rules$/;
const RTDB_RULES = /(^|\/)[\w.-]*\.rules\.json$/;
/** Only Supabase projects: a plain Postgres app without RLS is normal, a Supabase one is wide open. */
const SUPABASE_SQL = /(^|\/)supabase\/.*\.sql$/;
const AUTH_RULE = "request.auth != null";

interface RuleHit {
  file: string;
  line: number;
  title: string;
  severity: Severity;
  evidence: string;
  /** The whole line rewritten to require sign-in, or null when the line cannot be fixed safely. */
  fixed: string | null;
}

/** Blank out comments with spaces so offsets, and so line numbers, stay true. */
function blankComments(content: string, marker: "//" | "--"): string {
  const re = marker === "//" ? /\/\/[^\n]*/g : /--[^\n]*/g;
  return content.replace(re, (m) => " ".repeat(m.length));
}

const writes = (ops: string) => /\b(write|create|update|delete)\b/.test(ops);

function firebaseHits(f: RepoFile): RuleHit[] {
  const hits: RuleHit[] = [];
  const lines = blankComments(f.content, "//").split("\n");
  const raw = f.content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    let m = /\ballow\s+([a-z, ]+?)\s*:\s*if\s+true\s*;/.exec(line);
    if (m) {
      hits.push({
        file: f.path,
        line: i + 1,
        title: `Rules allow anyone to ${m[1].trim()}`,
        severity: writes(m[1]) ? "critical" : "high",
        evidence: line.trim(),
        fixed: raw[i].replace(/if\s+true\s*;/, `if ${AUTH_RULE};`),
      });
      continue;
    }
    m = /\ballow\s+([a-z, ]+?)\s*:\s*if\s+request\.time\s*<\s*timestamp\.date\([^)]*\)\s*;/.exec(line);
    if (m) {
      hits.push({
        file: f.path,
        line: i + 1,
        title: "Rules are still in test mode",
        severity: "critical",
        evidence: line.trim(),
        fixed: raw[i].replace(/if\s+request\.time\s*<\s*timestamp\.date\([^)]*\)\s*;/, `if ${AUTH_RULE};`),
      });
      continue;
    }
    // `allow read, write;` with no condition at all grants access to everyone.
    m = /\ballow\s+([a-z, ]+?)\s*;/.exec(line);
    if (m && /^(read|write|get|list|create|update|delete)(\s*,\s*(read|write|get|list|create|update|delete))*$/.test(m[1].trim())) {
      hits.push({
        file: f.path,
        line: i + 1,
        title: `Rules allow anyone to ${m[1].trim()}`,
        severity: writes(m[1]) ? "critical" : "high",
        evidence: line.trim(),
        fixed: raw[i].replace(/(\ballow\s+[a-z, ]+?)\s*;/, `$1: if ${AUTH_RULE};`),
      });
    }
  }
  return hits;
}

function rtdbHits(f: RepoFile): RuleHit[] {
  const hits: RuleHit[] = [];
  const raw = f.content.split("\n");
  for (let i = 0; i < raw.length; i++) {
    const m = /"\.(read|write)"\s*:\s*(true|"true")/.exec(raw[i]);
    if (!m) continue;
    hits.push({
      file: f.path,
      line: i + 1,
      title: `Realtime Database lets anyone ${m[1]}`,
      severity: m[1] === "write" ? "critical" : "high",
      evidence: raw[i].trim(),
      fixed: raw[i].replace(/("\.(read|write)"\s*:\s*)(true|"true")/, '$1"auth != null"'),
    });
  }
  return hits;
}

function supabaseHits(files: RepoFile[]): RuleHit[] {
  const sql = files.filter((f) => !SKIP.test(f.path) && SUPABASE_SQL.test(f.path));
  const clean = sql.map((f) => ({ f, text: blankComments(f.content, "--") }));
  const protectedTables = new Set<string>();
  for (const { text } of clean) {
    const re = /alter\s+table\s+(?:if\s+exists\s+)?(?:only\s+)?(?:"?public"?\.)?"?(\w+)"?\s+enable\s+row\s+level\s+security/gi;
    for (const m of text.matchAll(re)) protectedTables.add(m[1].toLowerCase());
  }

  const hits: RuleHit[] = [];
  for (const { f, text } of clean) {
    // Tables outside public (auth, private, extensions) are not served by the Data API.
    const create = /create\s+table\s+(?:if\s+not\s+exists\s+)?(?:("?)(\w+)\1\.)?"?(\w+)"?/gi;
    for (const m of text.matchAll(create)) {
      const schema = (m[2] ?? "public").toLowerCase();
      const table = m[3].toLowerCase();
      if (schema !== "public" || protectedTables.has(table)) continue;
      hits.push({
        file: f.path,
        line: lineAt(f.content, m.index!),
        title: `Table ${table} has no row level security`,
        severity: "critical",
        evidence: `create table without "alter table ${table} enable row level security"`,
        fixed: null,
      });
    }
    // A select policy of true is a deliberate public read; a write policy of true is not.
    for (const stmt of text.matchAll(/create\s+policy[^;]*;/gi)) {
      const s = stmt[0];
      if (!/\bfor\s+(insert|update|delete|all)\b/i.test(s) && /\bfor\s+select\b/i.test(s)) continue;
      if (!/\b(using|with\s+check)\s*\(\s*true\s*\)/i.test(s)) continue;
      const name = /create\s+policy\s+("[^"]+"|\w+)/i.exec(s)?.[1] ?? "policy";
      hits.push({
        file: f.path,
        line: lineAt(f.content, stmt.index!),
        title: `Policy ${name} allows any write`,
        severity: "high",
        evidence: "policy condition is (true)",
        fixed: null,
      });
    }
  }
  return hits;
}

function findHits(files: RepoFile[]): RuleHit[] {
  const hits: RuleHit[] = [];
  for (const f of files) {
    if (SKIP.test(f.path)) continue;
    if (RTDB_RULES.test(f.path)) hits.push(...rtdbHits(f));
    else if (FIREBASE_RULES.test(f.path)) hits.push(...firebaseHits(f));
  }
  return [...hits, ...supabaseHits(files)];
}

const EXPLAIN: Record<string, string> = {
  firebase:
    "Firebase apps talk to the database straight from the browser, so these rules are the only lock. With this rule anyone who opens DevTools can read or overwrite the data. The fix requires a signed-in user; you still need rules that check each user owns the document.",
  rtdb: "The Realtime Database is reached straight from the browser, so this rule is the only lock. Anyone with the database URL can read or overwrite it. The fix requires a signed-in user; add per-user rules on top.",
  supabase:
    "Supabase serves every public table through its API, and the anon key that reaches it ships in your frontend. Without row level security anyone can read and change every row. Enable RLS on the table and add policies for who may read and write.",
};

export const baasOpenRules: Check = {
  id: "baas-open-rules",
  group: "F-ai",
  title: "Firebase and Supabase data is locked",
  severity: "critical",
  mode: "auto",

  detect({ repo }): Finding[] {
    return findHits(repo.files).map((h) => ({
      checkId: "baas-open-rules",
      title: h.title,
      severity: h.severity,
      file: h.file,
      line: h.line,
      evidence: h.evidence,
      explanation: SUPABASE_SQL.test(h.file) ? EXPLAIN.supabase : RTDB_RULES.test(h.file) ? EXPLAIN.rtdb : EXPLAIN.firebase,
    }));
  },

  fix({ repo }): Patch | null {
    const byFile = new Map<string, RuleHit[]>();
    for (const h of findHits(repo.files)) {
      if (h.fixed === null) continue;
      byFile.set(h.file, [...(byFile.get(h.file) ?? []), h]);
    }
    const edits: FileEdit[] = [];
    const removals: string[] = [];
    for (const [path, hits] of byFile) {
      const file = repo.files.find((f) => f.path === path)!;
      const lines = file.content.split("\n");
      for (const h of hits) {
        if (h.fixed === lines[h.line - 1]) continue;
        removals.push(lines[h.line - 1].trim());
        lines[h.line - 1] = h.fixed!;
      }
      const after = lines.join("\n");
      if (after !== file.content) edits.push({ kind: "modify", path, before: file.content, after });
    }
    if (edits.length === 0) return null;
    return {
      id: "baas-open-rules-1",
      checkId: "baas-open-rules",
      title: "Require sign-in in Firebase rules",
      class: "minimal-edit",
      reason:
        "Open or test-mode rules let anyone read and write the database from the browser. Each changed rule now requires a signed-in user. Risk reduced, not removed: any signed-in user can still reach other users' data until you add ownership checks.",
      edits,
      allowedRemovals: removals,
    };
  },
};
