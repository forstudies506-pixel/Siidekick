import type { Check, Finding, Patch } from "../types.js";

const HEALTH_ROUTE = new RegExp(`app\\.(get|post|put|delete|patch|all|use)\\s*\\(\\s*['"]\\/(health|healthz)\\b`);
const APP_LINE = /= express\(\)/;

function expressAppFile(files: { path: string; content: string }[]): { path: string; content: string } | undefined {
  return files.find((f) => APP_LINE.test(f.content));
}

function hasHealthRoute(content: string): boolean {
  return HEALTH_ROUTE.test(content);
}

export const healthEndpoint: Check = {
  id: "health-endpoint",
  group: "B-monitoring",
  title: "Health endpoint",
  severity: "low",
  mode: "auto",

  detect({ repo }): Finding[] {
    if (repo.files.some((f) => hasHealthRoute(f.content))) return [];
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
