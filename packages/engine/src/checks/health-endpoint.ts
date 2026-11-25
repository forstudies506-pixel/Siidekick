import type { Check, Finding, Patch, RepoFile } from "../types.js";
import { serverShape } from "../util.js";

/** Express-style apps and routers, Flask/FastAPI decorators, and Django path() entries. */
const HEALTH_ROUTE = /\b\w+\.(get|post|put|delete|patch|route|api_route|all|use)\s*\(\s*['"]\/(api\/)?(health|healthz)\b|\b(re_)?path\(\s*['"]\^?(api\/)?(health|healthz)\b/;
/** File-routed handlers: api/health.py, app/api/health/route.ts, pages/api/health.js, netlify/functions/health.js. */
const HEALTH_FILE = /(^|\/)(api|functions)\/(health|healthz)(\.(c|m)?[jt]sx?|\.py|\/route\.[jt]s|\/index\.[jt]s)$/;
const APP_LINE = /= express\(\)/;

function expressAppFile(files: { path: string; content: string }[]): { path: string; content: string } | undefined {
  return files.find((f) => APP_LINE.test(f.content));
}

function hasHealthRoute(f: RepoFile): boolean {
  return HEALTH_ROUTE.test(f.content) || HEALTH_FILE.test(f.path);
}

export const healthEndpoint: Check = {
  id: "health-endpoint",
  group: "B-monitoring",
  title: "Health endpoint",
  severity: "low",
  mode: "auto",

  skip({ repo }) {
    const s = serverShape(repo.files);
    return s.node || s.python || s.functions || s.container ? null : "No server or API code found. A static site has no process to health-check.";
  },

  detect({ repo }): Finding[] {
    if (repo.files.some(hasHealthRoute)) return [];
    return [{
      checkId: "health-endpoint",
      title: "No /health or /healthz route",
      severity: "low",
      explanation: "The app has no health endpoint for uptime monitors and load balancers to check.",
    }];
  },

  fix({ repo }): Patch | null {
    const appFile = expressAppFile(repo.files);
    if (!appFile) return null;
    const before = appFile.content;
    const lines = before.split("\n");
    let insertAt = -1;
    for (let i = 0; i < lines.length; i++) {
      if (APP_LINE.test(lines[i])) { insertAt = i + 1; break; }
    }
    if (insertAt === -1) return null;
    lines.splice(insertAt, 0, "app.get('/health', (req, res) => res.json({ ok: true }));");
    const after = lines.join("\n");
    return {
      id: "health-endpoint-1",
      checkId: "health-endpoint",
      title: "Add /health route",
      class: "additive",
      reason: "Adds a health route so monitoring can verify the app is up.",
      edits: [{ kind: "modify", path: appFile.path, before, after }],
    };
  },
};
