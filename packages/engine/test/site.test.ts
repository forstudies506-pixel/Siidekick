import { describe, expect, it } from "vitest";
import { headerRemedy, runSiteScan, siteChecks, type SiteSnapshot } from "../src/site/index";

const NOW = "2026-11-26T00:00:00.000Z";
const snap = (over: Partial<SiteSnapshot> = {}): SiteSnapshot => ({
  requested: "example.com",
  url: "https://example.com/",
  status: 200,
  headers: {},
  setCookies: [],
  html: "<html><head></head><body><h1>hi</h1></body></html>",
  scripts: [],
  httpRedirect: "https",
  tls: { validTo: "2027-06-01T00:00:00.000Z", protocol: "TLSv1.3", authorized: true },
  securityTxt: true,
  sourceMaps: [],
  probeOrigin: "https://siidekick-probe.invalid",
  fetchedAt: NOW,
  ...over,
});
const HARDENED = {
  "strict-transport-security": "max-age=63072000; includeSubDomains",
  "content-security-policy": "default-src 'self'; script-src 'self'; frame-ancestors 'self'",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=()",
};
const run = (id: string, s: SiteSnapshot) => runSiteScan(s, siteChecks.filter((c) => c.id === id)).results[0];
const titles = (id: string, s: SiteSnapshot) => run(id, s).findings.map((f) => f.title);

describe("runSiteScan", () => {
  it("scores a hardened site 100 and names the report after the host", () => {
    const r = runSiteScan(snap({ headers: HARDENED }));
    expect(r.repo).toBe("example.com");
    expect(r.results.filter((x) => !x.passed).map((x) => x.checkId)).toEqual([]);
    expect(r.score).toBe(100);
  });
  it("marks a bare site down and keeps every result report-only", () => {
    const r = runSiteScan(snap());
    expect(r.score).toBeLessThan(80);
    expect(r.results.every((x) => x.mode === "report")).toBe(true);
  });
  it("counts a crashing check as failed", () => {
    const boom = { id: "x", group: "C-security" as const, title: "x", severity: "high" as const, detect: () => { throw new Error("bad"); } };
    expect(runSiteScan(snap(), [boom]).results[0]).toMatchObject({ passed: false, error: "bad" });
  });
});

describe("transport", () => {
  it("flags http pages and missing redirects", () => {
    expect(run("site-https", snap({ url: "http://example.com/" })).findings[0].severity).toBe("critical");
    expect(titles("site-https", snap({ httpRedirect: "no-redirect" }))[0]).toMatch(/redirect/);
  });
  it("skips TLS on http, flags expiry, untrusted certs and old protocols", () => {
    expect(run("site-tls", snap({ url: "http://example.com/" })).skipped).toBeTruthy();
    const soon = run("site-tls", snap({ tls: { validTo: "2026-12-03T00:00:00.000Z", protocol: "TLSv1.1", authorized: false } }));
    expect(soon.findings.map((f) => f.severity).sort()).toEqual(["critical", "high", "high"]);
  });
  it("wants HSTS of at least 180 days", () => {
    expect(titles("site-hsts", snap())[0]).toMatch(/No Strict/);
    expect(run("site-hsts", snap({ headers: { "strict-transport-security": "max-age=300" } })).findings[0].severity).toBe("low");
  });
});

describe("content security policy", () => {
  it("reads the meta tag and flags wildcards, inline and eval", () => {
    const html = `<meta http-equiv="Content-Security-Policy" content="script-src 'self' https: 'unsafe-inline' 'unsafe-eval'">`;
    expect(titles("site-csp", snap({ html }))).toHaveLength(3);
  });
  it("accepts unsafe-inline when a nonce is present", () => {
    expect(titles("site-csp", snap({ headers: { "content-security-policy": "script-src 'nonce-abc' 'unsafe-inline'" } }))).toEqual([]);
  });
  it("frame-ancestors from a meta tag does not stop clickjacking", () => {
    const html = `<meta http-equiv="Content-Security-Policy" content="frame-ancestors 'none'">`;
    expect(titles("site-clickjacking", snap({ html }))).toHaveLength(1);
    expect(titles("site-clickjacking", snap({ headers: { "x-frame-options": "DENY" } }))).toEqual([]);
  });
});

describe("cookies and CORS", () => {
  it("never shows a cookie value and rates session cookies higher", () => {
    const f = run("site-cookies", snap({ setCookies: ["sessionid=s3cr3tvalue; Path=/", "theme=dark; Secure; SameSite=Lax"] })).findings;
    expect(f).toHaveLength(1);
    expect(f[0].severity).toBe("high");
    expect(JSON.stringify(f)).not.toContain("s3cr3tvalue");
  });
  it("critical when the probe origin is reflected with credentials", () => {
    const headers = { "access-control-allow-origin": "https://siidekick-probe.invalid", "access-control-allow-credentials": "true" };
    expect(run("site-cors", snap({ headers })).findings[0].severity).toBe("critical");
    expect(run("site-cors", snap({ headers: { "access-control-allow-origin": "*" } })).passed).toBe(true);
  });
});

describe("page content", () => {
  it("flags mixed content, polyfill.io and unpinned third-party scripts", () => {
    const html = `<script src="http://cdn.x.com/a.js"></script><img src="http://x.com/i.png">
      <script src="https://polyfill.io/v3/polyfill.min.js"></script>
      <script src="https://cdn.jsdelivr.net/a.js"></script><script src="https://cdn.jsdelivr.net/b.js"></script>
      <script src="https://cdn.ok.com/c.js" integrity="sha384-x"></script><script src="/local.js"></script>`;
    expect(run("site-mixed-content", snap({ html })).findings.map((f) => f.severity)).toEqual(["medium", "low"]);
    const sri = run("site-sri", snap({ html })).findings;
    expect(sri.find((f) => f.severity === "critical")?.title).toMatch(/polyfill\.io/);
    expect(sri.map((f) => f.title)).toContain("2 scripts from cdn.jsdelivr.net without integrity");
    expect(sri.some((f) => f.title.includes("cdn.ok.com"))).toBe(false);
  });
  it("flags insecure forms and password fields on http", () => {
    const html = `<form action="http://example.com/login"><input type="password"></form>`;
    expect(run("site-forms", snap({ html })).findings).toHaveLength(1);
    expect(run("site-forms", snap({ url: "http://example.com/", html })).findings).toHaveLength(2);
    expect(run("site-forms", snap()).skipped).toBeTruthy();
  });
  it("flags version leaks", () => {
    const r = titles("site-version-leak", snap({ headers: { server: "nginx/1.18.0", "x-powered-by": "PHP/7.4" }, html: `<meta name="generator" content="WordPress 6.1">` }));
    expect(r).toHaveLength(3);
  });
});

describe("secrets and AI in client code", () => {
  const stripe = "sk_" + "live_" + "a".repeat(24);
  const openai = "sk-" + "proj-" + "b".repeat(40);
  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const service = `${b64({ alg: "HS256" })}.${b64({ role: "service_role", iss: "supabase" })}.${"c".repeat(20)}`;
  const anon = `${b64({ alg: "HS256" })}.${b64({ role: "anon", iss: "supabase" })}.${"c".repeat(20)}`;
  const script = { url: "https://example.com/app.js", content:
    `const k="${stripe}";const o="${openai}";const s="${service}";const a="${anon}";const k2="${stripe}";
     fetch("https://api.openai.com/v1/chat/completions",{body:JSON.stringify({messages:[{role:"system",content:"You are"}]})});
     new OpenAI({dangerouslyAllowBrowser:!0});` };

  it("finds keys once each, redacted, and service_role but not anon JWTs", () => {
    const f = run("site-secrets", snap({ scripts: [script] })).findings;
    const t = f.map((x) => x.title);
    expect(t.filter((x) => /Stripe/.test(x))).toHaveLength(1);
    expect(t.some((x) => /OpenAI/.test(x))).toBe(true);
    expect(t.some((x) => /service_role/.test(x))).toBe(true);
    expect(t.some((x) => /AI SDK/.test(x))).toBe(true);
    expect(JSON.stringify(f)).not.toContain(stripe);
    expect(JSON.stringify(f)).not.toContain(openai);
    expect(f.every((x) => x.file === script.url)).toBe(true);
  });
  it("flags direct model calls and a client-side system prompt", () => {
    expect(titles("site-ai-direct", snap({ scripts: [script] }))).toEqual([
      "The browser calls api.openai.com directly",
      "The system prompt ships in browser code",
    ]);
  });
});

describe("remedies", () => {
  it("writes the fix for the host that answered", () => {
    expect(headerRemedy(snap({ headers: { server: "Vercel" } }), "X-Frame-Options", "DENY")).toContain("vercel.json");
    expect(headerRemedy(snap({ headers: { server: "nginx" } }), "X-Frame-Options", "DENY")).toContain('add_header X-Frame-Options "DENY" always;');
    expect(headerRemedy(snap({ headers: { "x-nf-request-id": "1" } }), "A", "b")).toContain("_headers");
    expect(headerRemedy(snap({ headers: { server: "GitHub.com" } }), "A", "b")).toMatch(/cannot set/);
  });
  it("security.txt and source maps", () => {
    expect(run("site-security-txt", snap({ securityTxt: false })).findings[0].severity).toBe("info");
    expect(run("site-security-txt", snap({ securityTxt: null })).skipped).toBeTruthy();
    expect(run("site-source-maps", snap({ sourceMaps: ["https://example.com/a.js.map"] })).findings).toHaveLength(1);
  });
});
