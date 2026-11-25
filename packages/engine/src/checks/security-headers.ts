import type { Check, FileEdit, Finding, Patch, RepoFile, RepoSnapshot } from "../types.js";
import { lineAt } from "../util.js";

/**
 * Shared Express helpers for the security checks (Phase A). They live here because
 * the workstream only owns one file per check; rate-limit.ts imports them from here.
 */
const SKIP = /(^|\/)node_modules\//;
const APP_LINE = /(?:^|\n)[ \t]*(?:(?:const|let|var)\s+)?([A-Za-z_$][\w$]*)(?:\s*:[^=\n]+)?[ \t]*=[ \t]*express\s*\(/;
const ESM_SYNTAX = /(^|\n)[ \t]*import\s+(?:[\w$*{},\s]+from\s+)?['"]|(^|\n)[ \t]*export\s+(?:default\s+)?(?:async\s+)?(?:const|let|var|function|class|\{)/;

export interface AppLocation {
  file: RepoFile;
  /** 1-based line number of the `... = express()` assignment. */
  lineNo: number;
  /** The variable the app was assigned to, e.g. `app`. */
  varName: string;
}

/** First file where an Express app is created; insertions go right after that line. */
export function findAppFile(files: RepoFile[]): AppLocation | null {
  for (const file of files) {
    if (SKIP.test(file.path)) continue;
    const m = APP_LINE.exec(file.content);
    if (m) {
      const offset = m.index + (m[0].charCodeAt(0) === 10 ? 1 : 0);
      return { file, lineNo: lineAt(file.content, offset), varName: m[1] };
    }
  }
  return null;
}

/** ESM if the file itself uses import/export syntax, else if the root package.json says `"type": "module"`. */
export function isEsm(repo: RepoSnapshot, file: RepoFile): boolean {
  if (ESM_SYNTAX.test(file.content)) return true;
  const pkg = repo.files.find((f) => f.path === "package.json");
  return pkg !== undefined && /"type"\s*:\s*"module"/.test(pkg.content);
}

/** Additive edit: insert lines immediately after the app line. */
export function insertAfterAppLine(loc: AppLocation, newLines: string[]): FileEdit {
  const lines = loc.file.content.split("\n");
  lines.splice(loc.lineNo, 0, ...newLines);
  return { kind: "modify", path: loc.file.path, before: loc.file.content, after: lines.join("\n") };
}

/** Helper modules sit next to the app file so the relative require/import resolves. */
export function siblingPath(appPath: string, name: string): string {
  const i = appPath.lastIndexOf("/");
  return i === -1 ? name : appPath.slice(0, i + 1) + name;
}

const HELMET = /require\s*\(\s*['"]helmet['"]\s*\)|from\s+['"]helmet['"]/;
const HEADERS = /Content-Security-Policy|X-Frame-Options/i;

function lacksHeaders(files: RepoFile[]): boolean {
  const visible = files.filter((f) => !SKIP.test(f.path));
  return !visible.some((f) => HELMET.test(f.content)) && !visible.some((f) => HEADERS.test(f.content));
}

function securityModule(esm: boolean): string {
  return `// Conservative security headers for Express. They reduce clickjacking, MIME-sniffing
// and referrer-leakage risk; they are not a guarantee of safety.
${esm ? "export default" : "module.exports ="} (app) => app.use((req, res, next) => {
  res.setHeader("Content-Security-Policy", "default-src 'self'");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  res.removeHeader("X-Powered-By");
  next();
});
`;
}

export const securityHeaders: Check = {
  id: "security-headers",
  group: "C-security",
  title: "Security headers on responses",
  severity: "high",
  mode: "auto",

  detect({ repo }): Finding[] {
    if (!lacksHeaders(repo.files)) return [];
    const loc = findAppFile(repo.files);
    const finding: Finding = {
      checkId: "security-headers",
      title: "No security headers on responses",
      severity: "high",
      evidence: "no helmet import; no Content-Security-Policy or X-Frame-Options set anywhere",
      explanation:
        "Without these headers a browser can be tricked into framing the app or sniffing response types. Adding conservative defaults reduces that risk; it does not make the app immune to every attack.",
    };
    if (loc) {
      finding.file = loc.file.path;
      finding.line = loc.lineNo;
    }
    return [finding];
  },

  fix({ repo }): Patch | null {
    if (!lacksHeaders(repo.files)) return null;
    const loc = findAppFile(repo.files);
    if (!loc) return null; // no Express app to wire the middleware into
    const path = siblingPath(loc.file.path, "security.js");
    if (repo.files.some((f) => f.path === path)) return null; // never overwrite an existing file
    const esm = isEsm(repo, loc.file);
    const insert = esm
      ? [`import security from './security.js';`, `security(${loc.varName});`]
      : [`require('./security')(${loc.varName});`];
    return {
      id: "security-headers-1",
      checkId: "security-headers",
      title: "Add security headers middleware",
      class: "additive",
      reason:
        "Responses currently ship without clickjacking, MIME-sniffing and referrer protections. This template adds conservative header defaults; risk reduced, not eliminated.",
      edits: [{ kind: "create", path, content: securityModule(esm) }, insertAfterAppLine(loc, insert)],
    };
  },
};
