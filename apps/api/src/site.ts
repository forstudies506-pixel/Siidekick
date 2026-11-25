import http from "node:http";
import https from "node:https";
import type { TLSSocket } from "node:tls";
import { lookup as dnsLookup, type LookupAddress } from "node:dns";
import net from "node:net";
import zlib from "node:zlib";
import { resolve, tags, type SiteSnapshot } from "@siidekick/engine";

/**
 * Passive fetcher for the website scan. It reads what any browser would get from the page the visitor named:
 * the page, its same-origin scripts, the http:// redirect, security.txt and linked source maps. Nothing else is probed.
 * Every hop is checked against private and reserved address space at connect time, so DNS rebinding cannot reach inside.
 */

export class SiteError extends Error {
  constructor(message: string, readonly status = 400) {
    super(message);
  }
}

const PROBE_ORIGIN = "https://siidekick-probe.invalid";
const UA = "Siidekick-SiteScan/1.0 (passive security check)";
const MAX_HTML = 1.5 * 1024 * 1024;
const MAX_SCRIPT = 1024 * 1024;
const MAX_SCRIPTS = 8;
const MAX_MAPS = 4;
const MAX_REDIRECTS = 5;
const HOP_TIMEOUT = 8000;
const BUDGET = 20000;

const blocked = new net.BlockList();
for (const [net4, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
  ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15],
  ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4],
] as const) blocked.addSubnet(net4, prefix, "ipv4");
for (const [net6, prefix] of [
  ["::", 128], ["::1", 128], ["fc00::", 7], ["fe80::", 10], ["fec0::", 10], ["ff00::", 8], ["2001:db8::", 32],
  ["2001::", 32], ["100::", 64], ["64:ff9b:1::", 48],
] as const) blocked.addSubnet(net6, prefix, "ipv6");

/** 16 bytes of an IPv6 address, including the dotted-quad tail form. */
function v6Bytes(ip: string): number[] | null {
  let s = ip.split("%")[0];
  const dotted = s.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (dotted) {
    const q = dotted[1].split(".").map(Number);
    s = s.slice(0, -dotted[1].length) + `${((q[0] << 8) | q[1]).toString(16)}:${((q[2] << 8) | q[3]).toString(16)}`;
  }
  const [head, tail, extra] = s.split("::");
  if (extra !== undefined) return null;
  const h = head ? head.split(":") : [];
  const t = tail !== undefined && tail ? tail.split(":") : [];
  const fill = tail === undefined ? 0 : 8 - h.length - t.length;
  if (fill < 0) return null;
  const groups = [...h, ...Array(fill).fill("0"), ...t];
  if (groups.length !== 8) return null;
  return groups.flatMap((g) => {
    const n = parseInt(g, 16);
    return [(n >> 8) & 255, n & 255];
  });
}

/** IPv4 address carried inside an IPv6 one (mapped, compatible, NAT64, 6to4), or null. */
function embeddedV4(ip: string): string | null {
  const b = v6Bytes(ip);
  if (!b) return null;
  const zero = (from: number, to: number) => b.slice(from, to).every((x) => x === 0);
  const quad = (at: number) => b.slice(at, at + 4).join(".");
  if (zero(0, 10) && b[10] === 255 && b[11] === 255) return quad(12);
  if (zero(0, 12)) return quad(12);
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b && zero(4, 12)) return quad(12);
  if (b[0] === 0x20 && b[1] === 0x02) return quad(2);
  return null;
}

/** True only for addresses on the public internet. */
export function isPublicAddress(ip: string): boolean {
  const family = net.isIP(ip);
  if (family === 4) return !blocked.check(ip, "ipv4");
  if (family === 6) {
    const v4 = embeddedV4(ip);
    if (v4 !== null) return isPublicAddress(v4);
    return !blocked.check(ip, "ipv6");
  }
  return false;
}

type LookupCb = (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void;

/** DNS lookup that refuses the whole name if any answer is private, checked at connect time. */
export function safeLookup(hostname: string, options: { all?: boolean } | number, cb: LookupCb): void {
  dnsLookup(hostname, { all: true }, (err, addrs) => {
    if (err) return cb(err, "");
    if (!addrs.length || addrs.some((a) => !isPublicAddress(a.address))) {
      const e: NodeJS.ErrnoException = new Error(`${hostname} resolves to a private or reserved address`);
      e.code = "EBLOCKED";
      return cb(e, "");
    }
    if (typeof options === "object" && options.all) return cb(null, addrs);
    cb(null, addrs[0].address, addrs[0].family);
  });
}

/** Check a URL the scanner is about to request: public http(s) on a standard port, no credentials. */
export function checkTarget(u: URL): URL {
  if (u.protocol !== "http:" && u.protocol !== "https:") throw new SiteError("only http and https sites can be scanned");
  if (u.username || u.password) throw new SiteError("remove the username and password from the URL");
  if (u.port && u.port !== "80" && u.port !== "443") throw new SiteError("only the standard ports 80 and 443 are scanned");
  const host = u.hostname.replace(/^\[|\]$/g, "");
  if (net.isIP(host)) {
    if (!isPublicAddress(host)) throw new SiteError("that address is private or reserved");
  } else if (!host.includes(".") || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal")) {
    throw new SiteError("use a public domain name");
  }
  return u;
}

/** Parse what the visitor typed; a bare domain becomes https://. */
export function parseSiteUrl(input: string): URL {
  let s = input.trim();
  if (!/^[a-z][a-z0-9+.-]*:/i.test(s)) s = `https://${s}`;
  let u: URL;
  try {
    u = new URL(s);
  } catch {
    throw new SiteError("that is not a valid URL");
  }
  u.hash = "";
  return checkTarget(u);
}

/** Where a redirect leads, re-validated as if the visitor had typed it. */
export function nextHop(location: string, current: URL): URL {
  let u: URL;
  try {
    u = new URL(location, current);
  } catch {
    throw new SiteError("the site sent an unreadable redirect", 502);
  }
  u.hash = "";
  return checkTarget(u);
}

const recent: number[] = [];
/** About 20 scans a minute per instance, so the scanner is never a cheap traffic cannon. */
export function takeScanSlot(now = Date.now()): boolean {
  while (recent.length && now - recent[0] > 60_000) recent.shift();
  if (recent.length >= 20) return false;
  recent.push(now);
  return true;
}

interface Raw {
  url: URL;
  status: number;
  headers: http.IncomingHttpHeaders;
  body: Buffer;
  tls: SiteSnapshot["tls"];
}

function once(url: URL, method: "GET" | "HEAD", extra: Record<string, string>, maxBytes: number, deadline: number): Promise<Raw> {
  const timeout = Math.min(HOP_TIMEOUT, deadline - Date.now());
  if (timeout <= 0) return Promise.reject(new SiteError("the site took too long to answer", 504));
  const mod = url.protocol === "https:" ? https : http;
  return new Promise((done, fail) => {
    const req = mod.request(
      url,
      {
        method,
        agent: false,
        lookup: safeLookup as never,
        // Read certificates that do not validate too: reporting a broken certificate is part of the scan.
        rejectUnauthorized: false,
        headers: { "user-agent": UA, accept: "text/html,application/xhtml+xml,*/*;q=0.8", "accept-encoding": "gzip, deflate, br", ...extra },
      },
      (res) => {
        let tls: SiteSnapshot["tls"] = null;
        const sock = res.socket as TLSSocket;
        if (url.protocol === "https:" && typeof sock.getPeerCertificate === "function") {
          const cert = sock.getPeerCertificate();
          tls = {
            validTo: cert?.valid_to ? new Date(cert.valid_to).toISOString() : "",
            protocol: sock.getProtocol?.() ?? null,
            authorized: sock.authorized === true,
            ...(cert?.issuer?.O ? { issuer: String(cert.issuer.O) } : {}),
          };
        }
        const enc = String(res.headers["content-encoding"] ?? "").toLowerCase();
        const stream =
          enc === "gzip" ? res.pipe(zlib.createGunzip()) :
          enc === "br" ? res.pipe(zlib.createBrotliDecompress()) :
          enc === "deflate" ? res.pipe(zlib.createInflate()) : res;
        const chunks: Buffer[] = [];
        let size = 0;
        const finish = () => done({ url, status: res.statusCode ?? 0, headers: res.headers, body: Buffer.concat(chunks), tls });
        stream.on("data", (c: Buffer) => {
          if (size >= maxBytes) return;
          chunks.push(c.subarray(0, maxBytes - size));
          size += c.length;
          // Enough read: keep what arrived and close the connection.
          if (size >= maxBytes) {
            finish();
            req.destroy();
          }
        });
        stream.on("end", finish);
        stream.on("error", (e) => (size > 0 ? finish() : fail(e)));
      },
    );
    req.setTimeout(timeout, () => req.destroy(new SiteError("the site took too long to answer", 504)));
    req.on("error", fail);
    req.end();
  });
}

async function follow(start: URL, method: "GET" | "HEAD", extra: Record<string, string>, maxBytes: number, deadline: number): Promise<Raw> {
  let url = start;
  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const res = await once(url, method, extra, maxBytes, deadline);
    const loc = res.headers.location;
    if (res.status >= 300 && res.status < 400 && loc) {
      url = nextHop(loc, url);
      continue;
    }
    return res;
  }
  throw new SiteError("the site redirects too many times", 502);
}

function flatHeaders(h: http.IncomingHttpHeaders): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(h)) {
    if (k === "set-cookie" || v === undefined) continue;
    out[k.toLowerCase()] = Array.isArray(v) ? v.join(", ") : v;
  }
  return out;
}

const settle = <T>(p: Promise<T>) => p.then((v) => v, () => null);

/** Fetch everything the site checks read. Throws SiteError with an HTTP status when the site cannot be scanned. */
export async function fetchSite(input: string): Promise<SiteSnapshot> {
  const target = parseSiteUrl(input);
  const deadline = Date.now() + BUDGET;
  const fetchedAt = new Date().toISOString();

  let main: Raw;
  try {
    main = await follow(target, "GET", { origin: PROBE_ORIGIN }, MAX_HTML, deadline);
  } catch (err) {
    if (err instanceof SiteError) throw err;
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "EBLOCKED") throw new SiteError("that site resolves to a private or reserved address");
    if (code === "ENOTFOUND") throw new SiteError("that domain does not exist", 502);
    throw new SiteError("could not reach the site", 502);
  }
  const page = main.url;
  const type = String(main.headers["content-type"] ?? "");
  const html = /html|xml/i.test(type) || type === "" ? main.body.toString("utf8") : "";

  const scriptUrls: URL[] = [];
  const seen = new Set<string>();
  for (const t of tags(html, ["script", "link"])) {
    const ref = t.name === "script" ? t.attrs.src : /\bmodulepreload\b/i.test(t.attrs.rel ?? "") ? t.attrs.href : undefined;
    const u = ref ? resolve(ref, page.href) : null;
    if (!u || u.origin !== page.origin || seen.has(u.href)) continue;
    seen.add(u.href);
    scriptUrls.push(u);
    if (scriptUrls.length >= MAX_SCRIPTS) break;
  }

  const httpUrl = new URL(page.href);
  httpUrl.protocol = "http:";
  httpUrl.pathname = "/";
  httpUrl.search = "";
  const [redirect, securityTxt, ...scriptRes] = await Promise.all([
    page.protocol === "https:" ? settle(follow(httpUrl, "GET", {}, 1, deadline)) : Promise.resolve(undefined),
    settle(follow(new URL("/.well-known/security.txt", page.origin), "GET", {}, 64 * 1024, deadline)),
    ...scriptUrls.map((u) => settle(follow(u, "GET", {}, MAX_SCRIPT, deadline))),
  ]);

  const scripts = scriptRes.flatMap((r, i) => (r && r.status === 200 ? [{ url: scriptUrls[i].href, content: r.body.toString("utf8") }] : []));

  const mapUrls: URL[] = [];
  for (const s of scripts) {
    const m = s.content.slice(-2000).match(/\/\/[#@]\s*sourceMappingURL=(\S+)\s*$/);
    const u = m && !m[1].startsWith("data:") ? resolve(m[1], s.url) : null;
    if (u && u.origin === page.origin && !mapUrls.some((x) => x.href === u.href)) mapUrls.push(u);
    if (mapUrls.length >= MAX_MAPS) break;
  }
  const maps = await Promise.all(mapUrls.map((u) => settle(once(u, "HEAD", {}, 1, deadline))));

  return {
    requested: target.href,
    url: page.href,
    status: main.status,
    headers: flatHeaders(main.headers),
    setCookies: [main.headers["set-cookie"] ?? []].flat(),
    html,
    scripts,
    httpRedirect: redirect === undefined ? null : redirect === null ? "unreachable" : redirect.url.protocol === "https:" ? "https" : "no-redirect",
    tls: main.tls,
    securityTxt: securityTxt === null ? null : securityTxt.status === 200 && /^\s*contact:/im.test(securityTxt.body.toString("utf8")),
    sourceMaps: maps.flatMap((r, i) => (r && r.status === 200 ? [mapUrls[i].href] : [])),
    probeOrigin: PROBE_ORIGIN,
    fetchedAt,
  };
}
