import { describe, expect, it, beforeEach, afterEach } from "vitest";
import type { SiteSnapshot } from "@siidekick/engine";
import { isPublicAddress, parseSiteUrl, nextHop, safeLookup, takeScanSlot, SiteError } from "../src/site.js";
import { makeRouter } from "../src/router.js";
import { createStore } from "../src/store.js";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

describe("isPublicAddress", () => {
  it.each([
    "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1",
    "::1", "::", "fd00:ec2::254", "fe80::1", "::ffff:127.0.0.1", "::ffff:7f00:1", "::ffff:169.254.169.254",
    "64:ff9b::a9fe:a9fe", "2002:7f00:1::", "2001:db8::1", "not-an-ip",
  ])("blocks %s", (ip) => expect(isPublicAddress(ip)).toBe(false));

  it.each(["8.8.8.8", "1.1.1.1", "2606:4700::1111", "::ffff:8.8.8.8"])("allows %s", (ip) =>
    expect(isPublicAddress(ip)).toBe(true),
  );
});

describe("parseSiteUrl", () => {
  it("adds https to a bare domain and drops the fragment", () => {
    expect(parseSiteUrl("  example.com/path#x ").href).toBe("https://example.com/path");
  });

  it.each([
    "ftp://example.com/",
    "https://user:pw@example.com/",
    "https://example.com:8080/",
    "http://2130706433/",
    "http://127.0.0.1/",
    "http://[::1]/",
    "http://localhost/",
    "http://app.localhost/",
    "http://metadata.google.internal/",
    "http://printer.local/",
    "javascript:alert(1)",
    "https://",
  ])("rejects %s", (u) => expect(() => parseSiteUrl(u)).toThrow(SiteError));
});

describe("nextHop", () => {
  it("re-checks every redirect target", () => {
    const from = new URL("https://example.com/a");
    expect(nextHop("/b", from).href).toBe("https://example.com/b");
    expect(() => nextHop("http://169.254.169.254/latest/meta-data/", from)).toThrow(SiteError);
    expect(() => nextHop("http://localhost:8787/", from)).toThrow(SiteError);
  });
});

describe("safeLookup", () => {
  it("refuses a name that resolves to loopback", async () => {
    const code = await new Promise<string | undefined>((done) =>
      safeLookup("localhost", { all: true }, (err) => done(err?.code)),
    );
    expect(code).toBe("EBLOCKED");
  });
});

describe("takeScanSlot", () => {
  it("allows 20 scans a minute, then refuses until the window moves on", () => {
    for (let i = 0; i < 20; i++) expect(takeScanSlot(1000)).toBe(true);
    expect(takeScanSlot(1000)).toBe(false);
    expect(takeScanSlot(62_000)).toBe(true);
  });
});

describe("POST /api/sites", () => {
  let tmpDir: string;
  let store: ReturnType<typeof createStore>;

  const snap: SiteSnapshot = {
    requested: "https://example.com/",
    url: "https://example.com/",
    status: 200,
    headers: { "content-type": "text/html" },
    setCookies: ["sid=abc; Path=/"],
    html: "<html><body>hi</body></html>",
    scripts: [],
    httpRedirect: "no-redirect",
    tls: { validTo: new Date(Date.now() + 90 * 864e5).toISOString(), protocol: "TLSv1.3", authorized: true },
    securityTxt: false,
    sourceMaps: [],
    fetchedAt: new Date().toISOString(),
  };

  beforeEach(async () => {
    tmpDir = await mkdtemp(join(tmpdir(), "siidekick-site-test-"));
    process.env.STORAGE = "local";
    process.env.DATA_DIR = tmpDir;
    store = createStore();
  });

  afterEach(async () => {
    await rm(tmpDir, { recursive: true, force: true });
    delete process.env.STORAGE;
    delete process.env.DATA_DIR;
  });

  it("scans, stores without the page body, and refuses patches", async () => {
    const router = makeRouter({ store, fetchSite: async () => snap });
    const res = await router.handle({ method: "POST", path: "/api/sites", body: { url: "example.com" } });
    expect(res.status).toBe(201);
    const body = res.body as { id: string; kind: string; report: { score: number; results: Array<{ passed: boolean }> } };
    expect(body.kind).toBe("site");
    expect(body.report.score).toBeLessThan(100);
    expect(body.report.results.some((r) => !r.passed)).toBe(true);

    const rec = await store.get(body.id);
    expect(rec?.kind).toBe("site");
    expect(JSON.stringify(rec)).not.toContain("<html>");

    const got = await router.handle({ method: "GET", path: `/api/scans/${body.id}` });
    expect(got.body).toMatchObject({ kind: "site", site: { finalUrl: "https://example.com/" } });

    const patches = await router.handle({ method: "POST", path: `/api/scans/${body.id}/patches` });
    expect(patches.status).toBe(400);
  });

  it("returns the fetcher's error status", async () => {
    const router = makeRouter({
      store,
      fetchSite: async () => {
        throw new SiteError("that site resolves to a private or reserved address");
      },
    });
    const res = await router.handle({ method: "POST", path: "/api/sites", body: { url: "evil.example" } });
    expect(res).toMatchObject({ status: 400, body: { error: expect.stringContaining("private") } });
  });

  it("rejects a missing url", async () => {
    const router = makeRouter({ store, fetchSite: async () => snap });
    const res = await router.handle({ method: "POST", path: "/api/sites", body: {} });
    expect(res.status).toBe(400);
  });
});
