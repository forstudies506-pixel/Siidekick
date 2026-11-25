import type { Check, Finding, Patch, RepoFile } from "../types.js";
import { findAppFile, insertAfterAppLine, isEsm, siblingPath } from "./security-headers.js";

const SKIP = /(^|\/)node_modules\//;
/** Auth endpoints mentioned as string literals: '/login', "/signup", `/reset?next=…`. */
const AUTH_ROUTE = /['"`]\/(login|signup|register|reset)\b/g;
/** Any limiter in use: rateLimit(), express-rate-limit, a `limiter` binding. */
const LIMITER = /rate-?limit|\blimiter\b/i;
const ROUTE_LIST = "['/login', '/signup', '/register', '/reset']";

interface Scan {
  routes: Set<string>;
  limiter: boolean;
}

function scan(files: RepoFile[]): Scan {
  const routes = new Set<string>();
  let limiter = false;
  for (const f of files) {
    if (SKIP.test(f.path)) continue;
    for (const m of f.content.matchAll(AUTH_ROUTE)) routes.add("/" + m[1]);
    if (!limiter && LIMITER.test(f.content)) limiter = true;
  }
  return { routes, limiter };
}

function rateLimitModule(esm: boolean): string {
  return `// In-memory fixed-window rate limiter for auth endpoints; no npm dependencies.
// Defaults: 5 requests per 15 minutes per IP, override with RATE_LIMIT_MAX and
// RATE_LIMIT_WINDOW_MS. Counters reset on process restart, so this slows abuse
// attempts (risk reduced) but does not replace an upstream gateway or WAF limit.
const WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000;
const MAX_REQUESTS = Number(process.env.RATE_LIMIT_MAX) || 5;
const windows = new Map();

${esm ? "export default" : "module.exports ="} () => (req, res, next) => {
  const ip = req.ip || (req.socket && req.socket.remoteAddress) || "unknown";
  const now = Date.now();
  let entry = windows.get(ip);
  if (!entry || entry.resetAt <= now) {
    entry = { count: 0, resetAt: now + WINDOW_MS };
    windows.set(ip, entry);
  }
  entry.count += 1;
  if (entry.count > MAX_REQUESTS) {
    res.status(429).json({ error: "Too many requests. Try again later." });
    return;
  }
  res.setHeader("X-RateLimit-Limit", String(MAX_REQUESTS));
  res.setHeader("X-RateLimit-Remaining", String(Math.max(0, MAX_REQUESTS - entry.count)));
  next();
};
`;
}

export const rateLimitCheck: Check = {
  id: "rate-limit",
  group: "C-security",
  title: "Rate limiting on auth endpoints",
  severity: "high",
  mode: "auto",

  detect({ repo }): Finding[] {
    const { routes, limiter } = scan(repo.files);
    if (routes.size === 0 || limiter) return [];
    const loc = findAppFile(repo.files);
    const finding: Finding = {
      checkId: "rate-limit",
      title: "Auth endpoints without rate limiting",
      severity: "high",
      evidence: `no limiter found; routes present: ${[...routes].sort().join(", ")}`,
      explanation:
        "Login and reset endpoints are favourite targets for credential stuffing. A per-IP fixed-window limit slows that down; it reduces risk rather than removing it, since distributed attacks can still proceed.",
    };
    if (loc) {
      finding.file = loc.file.path;
      finding.line = loc.lineNo;
    }
    return [finding];
  },

  fix({ repo }): Patch | null {
    const { routes, limiter } = scan(repo.files);
    if (routes.size === 0 || limiter) return null;
    const loc = findAppFile(repo.files);
    if (!loc) return null; // no Express app to mount the limiter on
    const path = siblingPath(loc.file.path, "rateLimit.js");
    if (repo.files.some((f) => f.path === path)) return null; // never overwrite an existing file
    const esm = isEsm(repo, loc.file);
    const useLine = `${loc.varName}.use(${ROUTE_LIST}, `;
    const insert = esm
      ? [`import rateLimit from './rateLimit.js';`, `${useLine}rateLimit());`]
      : [`${useLine}require('./rateLimit')());`];
    return {
      id: "rate-limit-1",
      checkId: "rate-limit",
      title: "Add a rate limiter to auth endpoints",
      class: "additive",
      reason:
        "Auth endpoints currently accept unlimited attempts per IP. This template adds an in-memory fixed-window limiter (5 per 15 minutes by default); risk reduced, not eliminated.",
      edits: [{ kind: "create", path, content: rateLimitModule(esm) }, insertAfterAppLine(loc, insert)],
    };
  },
};
