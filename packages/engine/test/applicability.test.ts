import { describe, expect, it } from "vitest";
import { errorHandler } from "../src/checks/error-handler";
import { firewallRules } from "../src/checks/firewall-rules";
import { healthEndpoint } from "../src/checks/health-endpoint";
import { securityHeaders } from "../src/checks/security-headers";
import { runScan } from "../src/registry";
import type { RepoFile } from "../src/types";
import { serverShape } from "../src/util";

const ctx = (files: RepoFile[]) => ({ repo: { name: "t", files } });
const STATIC: RepoFile[] = [
  { path: "index.html", content: "<h1>hi</h1>" },
  { path: "vercel.json", content: "{}" },
  { path: "README.md", content: "uses express() and helmet" },
];

describe("serverShape", () => {
  it("reads server kinds from source, ignoring docs, tests and vendored code", () => {
    expect(serverShape(STATIC)).toEqual({ node: false, python: false, functions: false, container: false });
    expect(serverShape([{ path: "src/app.js", content: "const app = express();" }]).node).toBe(true);
    expect(serverShape([{ path: "s.js", content: "const app = require('express')();" }]).node).toBe(true);
    expect(serverShape([{ path: "s.mjs", content: "import { createServer } from 'node:http';" }]).node).toBe(true);
    expect(serverShape([{ path: "app.py", content: "app = Flask(__name__)" }]).python).toBe(true);
    expect(serverShape([{ path: "api/health.py", content: "def handler(): pass" }]).functions).toBe(true);
    expect(serverShape([{ path: "app/api/users/route.ts", content: "export function GET() {}" }]).functions).toBe(true);
    expect(serverShape([{ path: "Dockerfile", content: "FROM node" }]).container).toBe(true);
    expect(serverShape([{ path: "test/app.test.js", content: "express()" }]).node).toBe(false);
    expect(serverShape([{ path: "node_modules/x/index.js", content: "express()" }]).node).toBe(false);
  });
});

describe("not-applicable checks", () => {
  it("skips server checks on a static site, with a reason", () => {
    for (const c of [healthEndpoint, errorHandler, securityHeaders, firewallRules]) {
      expect(c.skip!(ctx(STATIC))).toMatch(/\w/);
    }
  });

  it("runs them on an Express app", () => {
    const files = [{ path: "server.js", content: "const app = express();\napp.listen(3000);" }];
    for (const c of [healthEndpoint, errorHandler, securityHeaders, firewallRules]) {
      expect(c.skip!(ctx(files))).toBeNull();
    }
  });

  it("serverless functions get health and headers checks but not firewall or Express error middleware", () => {
    const files = [{ path: "api/users.ts", content: "export default function handler() {}" }];
    expect(healthEndpoint.skip!(ctx(files))).toBeNull();
    expect(securityHeaders.skip!(ctx(files))).toBeNull();
    expect(firewallRules.skip!(ctx(files))).toMatch(/serverless/);
    expect(errorHandler.skip!(ctx(files))).toMatch(/Node/);
  });
});

describe("health-endpoint detection beyond Express app.get", () => {
  const passes = (files: RepoFile[]) => expect(healthEndpoint.detect(ctx(files))).toEqual([]);
  it("finds Flask, FastAPI, routers, Django and file-routed handlers", () => {
    passes([{ path: "app.py", content: '@app.route("/health")\ndef h(): return "ok"' }]);
    passes([{ path: "main.py", content: '@app.get("/healthz")\ndef h(): return {}' }]);
    passes([{ path: "routes.js", content: "router.get('/health', ok);" }]);
    passes([{ path: "urls.py", content: 'urlpatterns = [path("health/", views.health)]' }]);
    passes([{ path: "api/health.py", content: "def handler(): pass" }]);
    passes([{ path: "app/api/health/route.ts", content: "export function GET() {}" }]);
  });
  it("still flags a server with no health route", () => {
    expect(healthEndpoint.detect(ctx([{ path: "server.js", content: "const app = express();\napp.get('/users', h);" }]))).toHaveLength(1);
  });
});

describe("runScan scoring", () => {
  it("leaves skipped checks out of the score and the counts", async () => {
    const r = await runScan(ctx(STATIC), [healthEndpoint, firewallRules]);
    expect(r).toMatchObject({ score: 100, passed: 0, total: 0, skipped: 2 });
    expect(r.results.every((x) => x.passed && x.skipped)).toBe(true);
  });
  it("counts them when they apply", async () => {
    const r = await runScan(ctx([{ path: "server.js", content: "const app = express();" }]), [healthEndpoint]);
    expect(r).toMatchObject({ score: 0, passed: 0, total: 1, skipped: 0 });
  });
});
