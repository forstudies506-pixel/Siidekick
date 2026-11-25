import type { RepoFile } from "./types.js";

/** "sk_live_abcdef123456" -> "sk_l…3456 (20 chars)". Never log a full secret. */
export function redact(secret: string): string {
  if (secret.length <= 8) return `${"*".repeat(secret.length)} (${secret.length} chars)`;
  return `${secret.slice(0, 4)}…${secret.slice(-4)} (${secret.length} chars)`;
}

/** 1-based line number of a character offset. */
export function lineAt(content: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < content.length; i++) if (content.charCodeAt(i) === 10) line++;
  return line;
}

export const CODE_EXT = /\.(c|m)?(j|t)sx?$/;
/** Prose files: a README that mentions helmet or ufw is not the protection itself. */
export const DOC_EXT = /\.(md|mdx|markdown|txt|rst|adoc)$/i;

/** Split the arguments of the call whose '(' sits just before `from`; stops at its closing ')'. */
export function callArgs(content: string, from: number): string[] {
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
  return args; // unterminated call: no usable handler list
}

const VENDOR = /(^|\/)(node_modules|dist|build|\.next|out|coverage|venv|\.venv|vendor)\//;
const TEST_FILE = /(^|\/)(test|tests|__tests__)\/|\.(test|spec)\.[jt]sx?$/;
const NODE_SERVER = /\bexpress\s*\(\s*\)|require\(\s*["']express["']\s*\)\s*\(|\bfastify\s*\(|\bnew\s+(Koa|Hono)\s*\(|\bhttps?2?\.createServer\s*\(|\{[^}]*\bcreateServer\b[^}]*\}\s*(?:=\s*require\(\s*|from\s*)["'](?:node:)?https?["']|\bnew\s+Elysia\s*\(/;
const PY_SERVER = /\b(Flask|FastAPI|Sanic|Quart)\s*\(|\bfrom\s+django\b|\bimport\s+django\b|\baiohttp\.web\b/;
/** File-routed serverless handlers: Vercel/Netlify functions and Next.js route handlers. */
const FUNCTION_PATH = /(^|\/)(api|netlify\/functions)\/[^/]+(\/[^/]+)*\.(c|m)?[jt]s$|(^|\/)api\/[^/]+\.py$|(^|\/)app\/(.+\/)?route\.[jt]s$|(^|\/)pages\/api\//;

export interface ServerShape {
  /** A Node.js HTTP server (Express, Fastify, Koa, Hono, node:http). */
  node: boolean;
  /** A Python web server (Flask, FastAPI, Django, ...). */
  python: boolean;
  /** Serverless functions routed by file path. */
  functions: boolean;
  /** A container image, which usually runs a long-lived server. */
  container: boolean;
}

/** What kind of server code the repo holds, read from source only; nothing is executed. */
export function serverShape(files: RepoFile[]): ServerShape {
  const shape: ServerShape = { node: false, python: false, functions: false, container: false };
  for (const f of files) {
    if (VENDOR.test(f.path) || TEST_FILE.test(f.path) || DOC_EXT.test(f.path)) continue;
    if (/(^|\/)Dockerfile[^/]*$/.test(f.path)) shape.container = true;
    if (FUNCTION_PATH.test(f.path)) shape.functions = true;
    if (CODE_EXT.test(f.path) && NODE_SERVER.test(f.content)) shape.node = true;
    else if (f.path.endsWith(".py") && PY_SERVER.test(f.content)) shape.python = true;
  }
  return shape;
}
