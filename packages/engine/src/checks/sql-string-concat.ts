import type { Check, Finding } from "../types.js";
import { CODE_EXT, lineAt } from "../util.js";

const SKIP = /(^|\/)node_modules\//;
/** A statement shape, not a lone keyword, so URLs like '/api/update/' + id do not count. */
const SQL_SHAPE = /\bSELECT\b[\s\S]*\bFROM\b|\bINSERT\s+INTO\b|\bUPDATE\b[\s\S]+\bSET\b|\bDELETE\s+FROM\b/i;
/** prepare|query|exec|run|all|get( with an optional receiver, e.g. db.all( or bare query(. */
const CALL = /\b((?:[A-Za-z_$][\w$]*\s*\.\s*)*)(prepare|query|exec|run|all|get)\s*\(/g;

interface Token {
  k: "lit" | "expr";
  v: string;
}

function isQuoted(s: string): boolean {
  const t = s.trim();
  return t.length >= 2 && ((t.startsWith("'") && t.endsWith("'")) || (t.startsWith('"') && t.endsWith('"')) || (t.startsWith("`") && t.endsWith("`")));
}

/** Split the first argument on top-level `+`, ignoring operators inside strings and nested calls. */
function splitPlus(arg: string): string[] {
  const parts: string[] = [];
  let buf = "";
  let depth = 0;
  let quote: string | null = null;
  let esc = false;
  for (let i = 0; i < arg.length; i++) {
    const ch = arg[i];
    if (quote !== null) {
      buf += ch;
      if (esc) esc = false;
      else if (ch === "\\") esc = true;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      quote = ch;
      buf += ch;
      continue;
    }
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    else if (ch === ")" || ch === "]" || ch === "}") depth = Math.max(0, depth - 1);
    else if (ch === "+" && depth === 0 && arg[i + 1] !== "+" && arg[i - 1] !== "+") {
      parts.push(buf);
      buf = "";
      continue;
    }
    buf += ch;
  }
  parts.push(buf);
  return parts.filter((p, i) => p.trim() !== "" || i === 0);
}

/** Flatten the operands into literal fragments (strings, template text) and expressions. */
function tokens(arg: string): Token[] {
  const toks: Token[] = [];
  for (const raw of splitPlus(arg)) {
    const op = raw.trim();
    if (op.startsWith("`")) {
      const inner = op.slice(1, op.endsWith("`") && op.length > 1 ? -1 : undefined);
      let last = 0;
      for (const m of inner.matchAll(/\$\{([^}]*)\}/g)) {
        if (m.index! > last) toks.push({ k: "lit", v: inner.slice(last, m.index) });
        toks.push({ k: "expr", v: m[1].trim() });
        last = m.index! + m[0].length;
      }
      if (last < inner.length) toks.push({ k: "lit", v: inner.slice(last) });
    } else if (isQuoted(op)) {
      toks.push({ k: "lit", v: op.slice(1, -1) });
    } else {
      toks.push({ k: "expr", v: op });
    }
  }
  return toks;
}

/** '...name = \'' + name + '\'' -> the quotes around a spliced value go, since a ? placeholder must not be quoted. */
function unquoteSpliced(toks: Token[]): Token[] {
  const t = toks.map((x) => ({ ...x }));
  for (let i = 1; i < t.length - 1; i++) {
    if (t[i].k !== "expr" || t[i - 1].k !== "lit" || t[i + 1].k !== "lit") continue;
    const q = t[i - 1].v.slice(-1);
    if ((q === "'" || q === '"') && t[i + 1].v.startsWith(q)) {
      t[i - 1].v = t[i - 1].v.slice(0, -1);
      t[i + 1].v = t[i + 1].v.slice(1);
    }
  }
  return t;
}

/** The parameterised argument list: each literal run becomes one string with `?` where an expression sat. */
function rewriteArgs(toks: Token[], rest: string[]): string[] {
  const out: string[] = [];
  let buf: string | null = null;
  for (const t of unquoteSpliced(toks)) {
    if (t.k === "lit") {
      buf = (buf ?? "") + t.v;
      continue;
    }
    out.push(JSON.stringify((buf ?? "") + "?"));
    buf = null;
    out.push(t.v);
  }
  if (buf !== null && buf !== "") {
    // A trailing literal fragment belongs inside the previous string, e.g. LIKE '%?%' → '%?' + '%'.
    let i = out.length - 1;
    while (i >= 0 && !out[i].startsWith('"')) i--;
    if (i >= 0) out[i] = JSON.stringify(JSON.parse(out[i]) + buf);
    else out.push(JSON.stringify(buf));
  }
  return [...out, ...rest];
}

/** Does this first argument build SQL by concatenation? (literal text shaped like a SQL statement plus a spliced expression.) */
function isInjectedSql(arg: string): boolean {
  const toks = tokens(arg);
  if (!toks.some((t) => t.k === "expr")) return false;
  return SQL_SHAPE.test(toks.filter((t) => t.k === "lit").map((t) => t.v).join(" "));
}

interface Hit {
  file: string;
  line: number;
  call: string; // receiver + method, e.g. "db.all"
  firstArg: string;
  rewrite: string; // the parameterised call for the explanation
}

function findHits(files: { path: string; content: string }[]): Hit[] {
  const hits: Hit[] = [];
  for (const f of files) {
    if (!CODE_EXT.test(f.path) || SKIP.test(f.path)) continue;
    for (const m of f.content.matchAll(CALL)) {
      const open = m.index! + m[0].length - 1;
      const args = callArgs(f.content, open + 1);
      if (args.length === 0) continue;
      const firstArg = args[0].trim();
      if (!isInjectedSql(firstArg)) continue;
      const receiver = m[1].replace(/\s+/g, "");
      const rest = args.slice(1).map((a) => a.trim().replace(/\s+/g, " "));
      hits.push({
        file: f.path,
        line: lineAt(f.content, m.index!),
        call: `${receiver}${m[2]}`,
        firstArg: firstArg.replace(/\s+/g, " "),
        rewrite: `${receiver}${m[2]}(${rewriteArgs(tokens(firstArg), rest).join(", ")})`,
      });
    }
  }
  return hits;
}

/** Same balanced-paren scan as auth-on-endpoints: the arguments of the call opened just before `from`. */
function callArgs(content: string, from: number): string[] {
  const args: string[] = [];
  let buf = "";
  let depth = 0;
  let quote: string | null = null;
  let esc = false;
  for (let i = from; i < content.length; i++) {
    const ch = content[i];
    if (quote !== null) {
      buf += ch;
      if (esc) esc = false;
      else if (ch === "\\") esc = true;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      quote = ch;
      buf += ch;
      continue;
    }
    if (ch === "(" || ch === "[" || ch === "{") {
      depth++;
      buf += ch;
      continue;
    }
    if (ch === ")" || ch === "]" || ch === "}") {
      if (depth === 0 && ch === ")") {
        args.push(buf);
        return args;
      }
      if (depth > 0) depth--;
      buf += ch;
      continue;
    }
    if (ch === "," && depth === 0) {
      args.push(buf);
      buf = "";
      continue;
    }
    buf += ch;
  }
  return args;
}

export const sqlStringConcat: Check = {
  id: "sql-string-concat",
  group: "C-security",
  title: "Parameterised SQL queries",
  severity: "critical",
  mode: "report",

  detect({ repo }): Finding[] {
    return findHits(repo.files).map((h) => ({
      checkId: "sql-string-concat",
      title: "SQL built by string concatenation",
      severity: "critical" as const,
      file: h.file,
      line: h.line,
      evidence: `${h.call}(${h.firstArg.length > 120 ? h.firstArg.slice(0, 117) + "…" : h.firstArg})`,
      explanation:
        `Rewrite as ${h.rewrite}. String-built SQL lets a request change the query it receives (SQL injection); ` +
        "keeping the query fixed with ? placeholders and passing values as arguments reduces that risk.",
    }));
  },
  // Report-only per the brief: no fixer, the owner rewrites the query with placeholders.
};
