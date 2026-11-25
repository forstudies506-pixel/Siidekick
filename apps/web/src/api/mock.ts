import type { CheckGroup, CheckResult, FixMode, Patch, ScanReport, Severity } from "../../../../packages/engine/src/types";
import type { DownloadResponse, PatchEntry, PatchResponse, ScanResponse } from "./client";

// Same weights as packages/engine/src/registry.ts, so the mock score is computed the real way.
const WEIGHT: Record<Severity, number> = { critical: 5, high: 3, medium: 2, low: 1, info: 0.5 };

type MockCheck = {
  checkId: string;
  title: string;
  group: CheckGroup;
  severity: Severity;
  mode: FixMode;
  passed: boolean;
  file?: string;
  line?: number;
  evidence?: string;
  explanation: string;
};

const checks: MockCheck[] = [
  {
    checkId: "secrets-in-repo",
    title: "Secrets in repository",
    group: "C-security",
    severity: "critical",
    mode: "template",
    passed: false,
    file: "server.js",
    line: 33,
    evidence: 'PAYMENT_API_KEY = "demo…0c"',
    explanation: "A payment key is committed in code. Anyone who can read the repo can use it. Move it to an environment variable and rotate it.",
  },
  {
    checkId: "security-headers",
    title: "Security headers",
    group: "C-security",
    severity: "medium",
    mode: "auto",
    passed: false,
    file: "server.js",
    explanation: "No protective headers are set, so browsers allow framing and MIME sniffing. A small middleware file adds safe defaults.",
  },
  {
    checkId: "rate-limit",
    title: "Rate limiting",
    group: "C-security",
    severity: "medium",
    mode: "template",
    passed: false,
    file: "server.js",
    explanation: "The login route accepts unlimited attempts, which makes password guessing cheap.",
  },
  {
    checkId: "open-cors",
    title: "Open CORS",
    group: "C-security",
    severity: "medium",
    mode: "template",
    passed: false,
    file: "server.js",
    line: 12,
    evidence: "Access-Control-Allow-Origin: *",
    explanation: "Any website can call this API from a visitor's browser. List the origins that should be allowed.",
  },
  {
    checkId: "auth-on-endpoints",
    title: "Auth on endpoints",
    group: "C-security",
    severity: "high",
    mode: "template",
    passed: false,
    file: "server.js",
    evidence: "app.get('/admin/users', …)",
    explanation: "The admin route returns every user with no login check.",
  },
  {
    checkId: "sql-string-concat",
    title: "SQL built from strings",
    group: "C-security",
    severity: "high",
    mode: "report",
    passed: false,
    file: "server.js",
    evidence: "'SELECT * FROM products WHERE name LIKE ' + …",
    explanation: "User input is joined into a SQL query, so a crafted search can read or change data. Use a prepared statement. Reported only: this needs the owner's edit.",
  },
  {
    checkId: "dependency-audit",
    title: "Known-vulnerable dependencies",
    group: "C-security",
    severity: "high",
    mode: "report",
    passed: false,
    file: "package.json",
    evidence: "lodash 4.17.15",
    explanation: "This lodash version has published advisories. Upgrading is the owner's call, so it is reported, not patched.",
  },
  { checkId: "readme", title: "README", group: "A-delivery", severity: "low", mode: "auto", passed: true, explanation: "A README is present." },
  {
    checkId: "ci-workflow",
    title: "CI workflow",
    group: "A-delivery",
    severity: "low",
    mode: "auto",
    passed: false,
    explanation: "No CI workflow runs the tests on each push.",
  },
  {
    checkId: "health-endpoint",
    title: "Health endpoint",
    group: "B-monitoring",
    severity: "medium",
    mode: "auto",
    passed: false,
    file: "server.js",
    explanation: "There is no /health route, so uptime checks cannot tell whether the app is alive.",
  },
  {
    checkId: "error-handler",
    title: "Error handler",
    group: "E-states",
    severity: "medium",
    mode: "auto",
    passed: false,
    file: "server.js",
    explanation: "Unhandled errors print stack traces to visitors.",
  },
  {
    checkId: "ui-heavy-animation",
    title: "Heavy UI animation",
    group: "E-states",
    severity: "low",
    mode: "report",
    passed: true,
    explanation: "No heavy animation libraries found.",
  },
];

function toReport(name: string, fixed: Set<string>): ScanReport {
  const results: CheckResult[] = checks.map((c) => {
    const passed = c.passed || fixed.has(c.checkId);
    return {
      checkId: c.checkId,
      title: c.title,
      group: c.group,
      severity: c.severity,
      mode: c.mode,
      passed,
      findings: passed
        ? []
        : [{ checkId: c.checkId, title: c.title, severity: c.severity, file: c.file, line: c.line, evidence: c.evidence, explanation: c.explanation }],
    };
  });
  const total = results.reduce((s, r) => s + WEIGHT[r.severity], 0);
  const got = results.reduce((s, r) => s + (r.passed ? WEIGHT[r.severity] : 0), 0);
  return {
    repo: name,
    startedAt: new Date().toISOString(),
    score: Math.round((got / total) * 100),
    passed: results.filter((r) => r.passed).length,
    total: results.length,
    results,
  };
}

export function createMockScan(name = "campuskart"): ScanResponse {
  return { id: "demo", report: toReport(name, new Set()), mock: true };
}

const SERVER_HEAD = "const express = require('express');\nconst app = express();\napp.use(express.json());\n";

const securityFile = `module.exports = function securityHeaders(app) {
  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Content-Security-Policy', "default-src 'self'");
    next();
  });
};
`;

const headersPatch: Patch = {
  id: "security-headers-1",
  checkId: "security-headers",
  title: "Add security headers",
  class: "additive",
  reason: "Adds one new middleware file and one require line. No existing line changes.",
  edits: [
    { kind: "create", path: "middleware/security.js", content: securityFile },
    {
      kind: "modify",
      path: "server.js",
      before: SERVER_HEAD,
      after: SERVER_HEAD.replace("const app = express();\n", "const app = express();\nrequire('./middleware/security')(app);\n"),
    },
  ],
};

const authPatch: Patch = {
  id: "auth-on-endpoints-1",
  checkId: "auth-on-endpoints",
  title: "Protect the admin route",
  class: "additive",
  reason: "Adding auth here means rewriting an existing route line, which an additive patch may not do.",
  edits: [
    {
      kind: "modify",
      path: "server.js",
      before: "app.get('/admin/users', listUsers);\n",
      after: "app.get('/admin/users', requireAuth, listUsers);\n",
    },
  ],
};

const entries: PatchEntry[] = [
  {
    patch: headersPatch,
    guard: { ok: true, added: 10, removed: 0, violations: [] },
    diff: [
      { path: "middleware/security.js", lines: securityFile.trimEnd().split("\n").map((text) => ({ type: "add" as const, text })) },
      {
        path: "server.js",
        lines: [
          { type: "same", text: "const express = require('express');" },
          { type: "same", text: "const app = express();" },
          { type: "add", text: "require('./middleware/security')(app);" },
          { type: "same", text: "app.use(express.json());" },
        ],
      },
    ],
  },
  {
    patch: authPatch,
    guard: {
      ok: false,
      added: 1,
      removed: 1,
      violations: [{ path: "server.js", reason: "removal-in-additive-patch", line: "app.get('/admin/users', listUsers);" }],
    },
    diff: [
      {
        path: "server.js",
        lines: [
          { type: "del", text: "app.get('/admin/users', listUsers);" },
          { type: "add", text: "app.get('/admin/users', requireAuth, listUsers);" },
        ],
      },
    ],
  },
];

export function createMockPatches(name = "campuskart"): PatchResponse {
  const fixed = new Set(entries.filter((e) => e.guard.ok).map((e) => e.patch.checkId));
  return {
    patches: entries,
    scoreBefore: toReport(name, new Set()).score,
    scoreAfter: toReport(name, fixed).score,
    status: "partial",
    mock: true,
  };
}

/**
 * New files from approved, guard-passed patches. Modified files are left out: the mock holds only an
 * excerpt of server.js, and handing that back would overwrite the owner's full file.
 */
export function mockDownload(approvedIds: string[]): DownloadResponse {
  return {
    files: entries
      .filter((e) => e.guard.ok && approvedIds.includes(e.patch.id))
      .flatMap((e) => e.patch.edits)
      .flatMap((edit) => (edit.kind === "create" ? [{ path: edit.path, content: edit.content }] : [])),
  };
}
