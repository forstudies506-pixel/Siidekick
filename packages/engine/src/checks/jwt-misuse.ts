import type { Check, FileEdit, Finding, Patch, Severity } from "../types.js";
import { callArgs, lineAt, redact } from "../util.js";

const SKIP = /(^|\/)(node_modules|dist|build|\.next|out|coverage|venv|\.venv)\//;
const TEST_PATH = /(^|\/)(test|tests|__tests__)(\/|$)|\.(test|spec)\.[jt]sx?$|(^|\/)test_[\w-]*\.py$/;
const JS = /\.(c|m)?(j|t)sx?$/;
const PY = /\.py$/;
const JS_LIB = /(?:require\(\s*|from\s+)["'](jsonwebtoken|jose)["']/;
const PY_LIB = /^\s*(import\s+jwt\b|from\s+jwt\s+import)/m;
const STRING = /^\s*(["'`])([^"'`$]*)\1\s*$/;

interface Hit {
  file: string;
  line: number;
  title: string;
  severity: Severity;
  evidence: string;
  explanation: string;
  /** Exact text to swap on that line for the fix, or none when the fix needs the owner. */
  swap?: [string, string];
}

const WHY = {
  decode:
    "decode() only reads the token; it never checks the signature. Anyone can write a token that says they are an admin and this code will believe it. Use verify() with your secret or public key and trust only what it returns.",
  none:
    "The 'none' algorithm means an unsigned token. Allowing it lets anyone forge a token by setting alg to none and dropping the signature. List only the algorithm you sign with, such as HS256 or RS256.",
  noSig:
    "Turning off signature checking means any token anyone writes is accepted. Read claims only after jwt.decode has verified the signature with your key.",
  expiry:
    "With expiry checks off, a token that leaks stays valid for ever, including after logout or a password change. The fix turns the check back on; issue short-lived tokens and refresh them.",
  literal:
    "The signing secret is written in the code, so anyone who sees the repo, or guesses a common value like 'secret', can sign their own tokens as any user. Load it from an environment variable or secret manager and rotate it.",
  fallback:
    "If the environment variable is missing the app silently signs with a value written in the code, which anyone reading the repo can use to forge tokens. Fail at startup when the secret is not set instead of falling back.",
};

function jsHits(path: string, content: string): Hit[] {
  if (!JS_LIB.test(content)) return [];
  const hits: Hit[] = [];
  const at = (i: number) => lineAt(content, i);

  if (!/\b(verify|jwtVerify)\s*\(/.test(content)) {
    for (const m of content.matchAll(/\b(?:jwt|jsonwebtoken)\.decode\s*\(|\bdecodeJwt\s*\(/g)) {
      hits.push({ file: path, line: at(m.index!), title: "Token is decoded but never verified", severity: "high", evidence: m[0].replace(/\s*\($/, "()"), explanation: WHY.decode });
    }
  }
  for (const m of content.matchAll(/\balgorithms?\s*:\s*(\[[^\]]*\]|["'][^"']*["'])/g)) {
    if (!/["']none["']/i.test(m[1])) continue;
    hits.push({ file: path, line: at(m.index!), title: "Unsigned tokens (alg none) are accepted", severity: "critical", evidence: m[0], explanation: WHY.none });
  }
  for (const m of content.matchAll(/\bignoreExpiration\s*:\s*true\b/g)) {
    hits.push({ file: path, line: at(m.index!), title: "Expired tokens are accepted", severity: "high", evidence: m[0], explanation: WHY.expiry, swap: [m[0], m[0].replace("true", "false")] });
  }
  for (const m of content.matchAll(/\b(?:jwt|jsonwebtoken)\.(sign|verify)\s*\(/g)) {
    const key = callArgs(content, m.index! + m[0].length)[1];
    const lit = key === undefined ? null : STRING.exec(key);
    if (!lit) continue;
    hits.push({ file: path, line: at(m.index!), title: "JWT secret is written in the code", severity: "critical", evidence: `jwt.${m[1]}(…, ${redact(lit[2])})`, explanation: WHY.literal });
  }
  for (const m of content.matchAll(/\b([A-Z0-9_]*(?:JWT|TOKEN|AUTH)[A-Z0-9_]*SECRET[A-Z0-9_]*|[A-Z0-9_]*SECRET[A-Z0-9_]*JWT[A-Z0-9_]*)\s*(?:\|\||\?\?)\s*(["'`])([^"'`$]+)\2/g)) {
    hits.push({ file: path, line: at(m.index!), title: "JWT secret falls back to a value in the code", severity: "high", evidence: `${m[1]} || ${redact(m[3])}`, explanation: WHY.fallback });
  }
  return hits;
}

function pyHits(path: string, content: string): Hit[] {
  if (!PY_LIB.test(content)) return [];
  const hits: Hit[] = [];
  const at = (i: number) => lineAt(content, i);
  for (const m of content.matchAll(/\balgorithms?\s*=\s*(\[[^\]]*\]|["'][^"']*["'])/g)) {
    if (!/["']none["']/i.test(m[1])) continue;
    hits.push({ file: path, line: at(m.index!), title: "Unsigned tokens (alg none) are accepted", severity: "critical", evidence: m[0], explanation: WHY.none });
  }
  for (const m of content.matchAll(/["']verify_signature["']\s*:\s*False\b/g)) {
    hits.push({ file: path, line: at(m.index!), title: "Token signature is not checked", severity: "critical", evidence: m[0], explanation: WHY.noSig });
  }
  for (const m of content.matchAll(/["']verify_exp["']\s*:\s*False\b/g)) {
    hits.push({ file: path, line: at(m.index!), title: "Expired tokens are accepted", severity: "high", evidence: m[0], explanation: WHY.expiry, swap: [m[0], m[0].replace("False", "True")] });
  }
  for (const m of content.matchAll(/\bjwt\.(encode|decode)\s*\(/g)) {
    const key = callArgs(content, m.index! + m[0].length)[1];
    const lit = key === undefined ? null : /^\s*(["'])([^"']*)\1\s*$/.exec(key);
    if (!lit) continue;
    hits.push({ file: path, line: at(m.index!), title: "JWT secret is written in the code", severity: "critical", evidence: `jwt.${m[1]}(…, ${redact(lit[2])})`, explanation: WHY.literal });
  }
  for (const m of content.matchAll(/\b(?:os\.getenv|os\.environ\.get)\(\s*["']([A-Z0-9_]*(?:JWT|SECRET)[A-Z0-9_]*)["']\s*,\s*["']([^"']+)["']\s*\)/g)) {
    hits.push({ file: path, line: at(m.index!), title: "JWT secret falls back to a value in the code", severity: "high", evidence: `${m[1]} default ${redact(m[2])}`, explanation: WHY.fallback });
  }
  return hits;
}

function findHits(files: { path: string; content: string }[]): Hit[] {
  const hits: Hit[] = [];
  for (const f of files) {
    if (SKIP.test(f.path) || TEST_PATH.test(f.path)) continue;
    if (JS.test(f.path)) hits.push(...jsHits(f.path, f.content));
    else if (PY.test(f.path)) hits.push(...pyHits(f.path, f.content));
  }
  return hits.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
}

export const jwtMisuse: Check = {
  id: "jwt-misuse",
  group: "F-ai",
  title: "Login tokens are verified properly",
  severity: "critical",
  mode: "auto",

  detect({ repo }): Finding[] {
    return findHits(repo.files).map((h) => ({
      checkId: "jwt-misuse",
      title: h.title,
      severity: h.severity,
      file: h.file,
      line: h.line,
      evidence: h.evidence,
      explanation: h.explanation,
    }));
  },

  fix({ repo }): Patch | null {
    const byFile = new Map<string, Hit[]>();
    for (const h of findHits(repo.files)) if (h.swap) byFile.set(h.file, [...(byFile.get(h.file) ?? []), h]);
    const edits: FileEdit[] = [];
    const removals: string[] = [];
    for (const [path, hits] of byFile) {
      const before = repo.files.find((f) => f.path === path)!.content;
      const lines = before.split("\n");
      for (const h of hits) {
        const old = lines[h.line - 1];
        const next = old.replace(h.swap![0], h.swap![1]);
        if (next === old) continue;
        removals.push(old.trim());
        lines[h.line - 1] = next;
      }
      const after = lines.join("\n");
      if (after !== before) edits.push({ kind: "modify", path, before, after });
    }
    if (edits.length === 0) return null;
    return {
      id: "jwt-misuse-1",
      checkId: "jwt-misuse",
      title: "Reject expired login tokens",
      class: "minimal-edit",
      reason:
        "Token verification was told to accept expired tokens, so a leaked token never stops working. Each changed line turns the expiry check back on. Risk reduced, not removed: users whose tokens have expired must sign in again, and decode-only, alg none and hardcoded secrets still need your fix.",
      edits,
      allowedRemovals: removals,
    };
  },
};
