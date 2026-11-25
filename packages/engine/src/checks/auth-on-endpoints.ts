import type { Check, Finding, Patch, RepoFile } from "../types.js";
import { CODE_EXT, lineAt, callArgs } from "../util.js";
import { findAppFile, insertAfterAppLine, isEsm, siblingPath } from "./security-headers.js";

const SKIP = /(^|\/)node_modules\//;
/** The admin subtree only: /admin/... and /api/admin/...; the lookahead keeps /administrator out. */
const ADMIN_ROUTE = /^\/(?:api\/)?admin(?=\/|$)/;
/** Route forms per the brief: app|router.(get|post|put|patch|delete)('<path>', ...handlers). */
const ROUTE = /\b(app|router)\s*\.\s*(get|post|put|patch|delete)\s*\(\s*(['"`])([^'"`\n]*)\3/g;
/** Any .use( call; its first argument decides whether it mounts on the admin subtree. */
const MOUNT = /\.\s*use\s*\(/g;
const ADMIN_MOUNT_PATH = /^(['"`])(\/(?:api\/)?admin(?:\/[^'"`]*)?)\1$/;
/** One segment of a handler name that reads as a guard: adminAuth, verifyAdmin, requireAdmin, isLoggedIn, authenticate. */
const GUARD_SEGMENT = /auth|protect|verify|guard|^(require|ensure|check|is)(Admin|Auth|Login|LoggedIn|User|Role|Token|Session)/i;

interface RouteHit {
  file: RepoFile;
  /** Char offset of the call in the file. */
  offset: number;
  path: string;
}

/**
 * A handler counts as protective only by *name* (the brief's rule): requireAdmin, auth.check,
 * require('./auth').requireAdmin … Anonymous arrows have no name and do not count.
 */
function handlerName(arg: string): string {
  // A bare require('./adminAuth') is named after its module file.
  const mod = /^require\s*\(\s*['"]([^'"]*)['"]\s*\)$/.exec(arg.trim());
  if (mod) return mod[1].split("/").pop()!.replace(/\.[^.]*$/, "");
  const m = /^(?:require\s*\(\s*['"][^'"]*['"]\s*\)\s*\.\s*)?([A-Za-z_$][\w$]*(?:\s*\.\s*[A-Za-z_$][\w$]*)*)/.exec(arg.trim());
  return m ? m[1].replace(/\s+/g, "") : "";
}

/** Dotted names are tested per segment: adminController.list is not a guard, passport.authenticate is. */
function isGuard(arg: string): boolean {
  return handlerName(arg).split(".").some((seg) => GUARD_SEGMENT.test(seg));
}

/** Does a mount path cover the route (with a segment boundary, so /admin ≠ /administrator)? */
function covers(mountPath: string, routePath: string): boolean {
  if (routePath === mountPath) return true;
  if (mountPath.endsWith("/")) return routePath.startsWith(mountPath);
  return routePath.startsWith(mountPath + "/");
}

function mountGuards(files: RepoFile[], routeFile: string, routeOffset: number, routePath: string): boolean {
  for (const f of files) {
    for (const m of f.content.matchAll(MOUNT)) {
      const args = callArgs(f.content, m.index + m[0].length);
      const mountPath = ADMIN_MOUNT_PATH.exec(args[0]?.trim() ?? "")?.[2];
      if (!mountPath || !covers(mountPath, routePath)) continue;
      if (!args.slice(1).some(isGuard)) continue; // mounting an unguarded admin router protects nothing
      // Same file: Express runs middleware in declaration order, so the mount must precede the route.
      // Another file: cross-module ordering is not statically knowable, so a matching mount counts.
      if (f.path !== routeFile || m.index! < routeOffset) return true;
    }
  }
  return false;
}

/** Every admin route with no named guard handler and no prior admin mount. Recomputed on every call. */
function offendingRoutes(files: RepoFile[]): RouteHit[] {
  const hits: RouteHit[] = [];
  for (const file of files) {
    if (!CODE_EXT.test(file.path) || SKIP.test(file.path)) continue;
    for (const m of file.content.matchAll(ROUTE)) {
      const routePath = m[4];
      if (!ADMIN_ROUTE.test(routePath)) continue;
      const handlers = callArgs(file.content, m.index + m[0].length);
      if (handlers.length > 0 && handlers[0].trim() === "") handlers.shift(); // whitespace between path literal and first comma
      // The last handler is the endpoint itself; only the ones before it can guard it.
      if (handlers.slice(0, -1).some(isGuard)) continue;
      if (mountGuards(files, file.path, m.index, routePath)) continue;
      hits.push({ file, offset: m.index, path: routePath });
    }
  }
  return hits;
}

function authModule(esm: boolean): string {
  const body = `// Minimal admin gate: compares Authorization: Bearer <token> with process.env.ADMIN_TOKEN
// and answers 401 otherwise (also when the variable is unset, so a missing config fails closed).
// In production replace this shared token with a verified Cognito JWT; this static check only
// reduces risk while ADMIN_TOKEN is set and kept secret.
function requireAdmin(req, res, next) {
  const header = req.get("Authorization") || "";
  const expected = process.env.ADMIN_TOKEN;
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!expected || token !== expected) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  next();
}
`;
  return esm ? body + "export { requireAdmin };\n" : body + "module.exports = { requireAdmin };\n";
}

export const authOnEndpoints: Check = {
  id: "auth-on-endpoints",
  group: "C-security",
  title: "Auth on admin endpoints",
  severity: "critical",
  mode: "auto",

  detect({ repo }): Finding[] {
    return offendingRoutes(repo.files).map((hit) => ({
      checkId: "auth-on-endpoints",
      title: "Admin route without an auth guard",
      severity: "critical" as const,
      file: hit.file.path,
      line: lineAt(hit.file.content, hit.offset),
      evidence: `${hit.path} has no named auth middleware and no prior admin use() mount`,
      explanation:
        "Admin endpoints run with the app's privileges, so anyone who finds the URL can call them. The generated requireAdmin middleware checks a bearer token and reduces that risk; verify a Cognito JWT in production instead of a shared token.",
    }));
  },

  fix({ repo }): Patch | null {
    const offenders = offendingRoutes(repo.files); // recompute: earlier patches may have moved lines
    if (offenders.length === 0) return null;
    const loc = findAppFile(repo.files);
    if (!loc) return null; // no Express app to mount the guard on
    const path = siblingPath(loc.file.path, "auth.js");
    if (repo.files.some((f) => f.path === path)) return null; // never overwrite an existing file
    const esm = isEsm(repo, loc.file);
    // One mount per admin prefix the offending routes live under (/admin vs /api/admin).
    const prefixes = [...new Set(offenders.map((o) => (o.path.startsWith("/api/admin") ? "/api/admin" : "/admin")))].sort();
    const insert: string[] = [];
    if (esm) insert.push(`import { requireAdmin } from './auth.js';`);
    for (const p of prefixes) {
      insert.push(esm ? `${loc.varName}.use('${p}', requireAdmin);` : `${loc.varName}.use('${p}', require('./auth').requireAdmin);`);
    }
    return {
      id: "auth-on-endpoints-1",
      checkId: "auth-on-endpoints",
      title: "Guard admin routes with a bearer-token check",
      class: "additive",
      reason:
        "Admin routes currently accept any caller. This template adds requireAdmin (Bearer token vs ADMIN_TOKEN, 401 otherwise) and mounts it on the admin subtree; risk reduced — swap in a verified Cognito JWT for production.",
      edits: [{ kind: "create", path, content: authModule(esm) }, insertAfterAppLine(loc, insert)],
    };
  },
};
