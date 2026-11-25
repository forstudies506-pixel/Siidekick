import type { CheckGroup, Finding, Severity } from "../types.js";
import { JWT, LLM_HOSTS, jwtRole } from "../checks/client-exposed-secrets.js";
import { VENDOR_SECRETS } from "../checks/secrets.js";
import { lineAt, redact } from "../util.js";
import { cookieShape, parseCsp, resolve, tags } from "./html.js";

/** What Siidekick saw when it loaded a public page, read passively. Nothing on the site is executed. */
export interface SiteSnapshot {
  requested: string;
  /** Final URL after redirects. */
  url: string;
  status: number;
  /** Lower-cased header names. */
  headers: Record<string, string>;
  setCookies: string[];
  html: string;
  /** Same-origin scripts the page links, capped by the fetcher. */
  scripts: { url: string; content: string }[];
  /** What http:// did: redirected to https, served the page itself, or could not be reached. */
  httpRedirect: "https" | "no-redirect" | "unreachable" | null;
  tls: { validTo: string; protocol: string | null; authorized: boolean; issuer?: string } | null;
  /** /.well-known/security.txt present; null when not checked. */
  securityTxt: boolean | null;
  /** Source map URLs that answered 200. */
  sourceMaps: string[];
  /** The Origin header sent with the page request, to see whether CORS reflects it. */
  probeOrigin?: string;
  fetchedAt: string;
}

export interface SiteCheck {
  id: string;
  group: CheckGroup;
  title: string;
  severity: Severity;
  /** Reason the check does not apply, or null. */
  skip?(site: SiteSnapshot): string | null;
  detect(site: SiteSnapshot): Finding[];
}

const isHttps = (s: SiteSnapshot) => new URL(s.url).protocol === "https:";
const needHttps = (s: SiteSnapshot) => (isHttps(s) ? null : "the page is not served over HTTPS");
const clip = (v: string, n = 140) => (v.length > n ? `${v.slice(0, n)}…` : v);

type Host = "vercel" | "netlify" | "cloudflare" | "nginx" | "apache" | "express" | "github" | "other";

/** Which host or server answered, read from its response headers, so fixes name the right file. */
export function hostOf(site: SiteSnapshot): Host {
  const h = site.headers;
  const server = (h["server"] ?? "").toLowerCase();
  if (server === "vercel" || h["x-vercel-id"]) return "vercel";
  if (server.includes("netlify") || h["x-nf-request-id"]) return "netlify";
  if (server === "github.com") return "github";
  if (/express/i.test(h["x-powered-by"] ?? "")) return "express";
  if (server.startsWith("nginx")) return "nginx";
  if (server.startsWith("apache")) return "apache";
  if (server === "cloudflare" || h["cf-ray"]) return "cloudflare";
  return "other";
}

/** A copy-ready way to send one response header on the host this site runs on. */
export function headerRemedy(site: SiteSnapshot, name: string, value: string): string {
  const line = `${name}: ${value}`;
  switch (hostOf(site)) {
    case "vercel":
      return `${line}\n\nvercel.json\n${JSON.stringify({ headers: [{ source: "/(.*)", headers: [{ key: name, value }] }] }, null, 2)}`;
    case "netlify":
      return `${line}\n\nnetlify _headers file\n/*\n  ${line}`;
    case "nginx":
      return `${line}\n\nnginx server block\nadd_header ${name} "${value}" always;`;
    case "apache":
      return `${line}\n\nApache (.htaccess or vhost)\nHeader always set ${name} "${value}"`;
    case "express":
      return `${line}\n\nExpress: helmet() sets most of these; or\napp.use((req, res, next) => { res.setHeader("${name}", "${value}"); next(); });`;
    case "cloudflare":
      return `${line}\n\nCloudflare: Rules > Transform Rules > Modify Response Header > Set static\n${name} = ${value}`;
    case "github":
      return `${line}\n\nGitHub Pages cannot set response headers. Put the site behind a CDN such as Cloudflare and set it there.`;
    default:
      return line;
  }
}

const siteHttps: SiteCheck = {
  id: "site-https",
  group: "C-security",
  title: "Served only over HTTPS",
  severity: "critical",
  detect(site) {
    if (!isHttps(site)) {
      return [{
        checkId: "site-https",
        title: "The page is served over plain HTTP",
        severity: "critical",
        file: site.url,
        explanation:
          "Anyone on the same Wi-Fi, ISP or proxy can read and change this page in transit, including passwords typed into it and scripts it loads. Get a free certificate (Let's Encrypt, or your host's built-in HTTPS) and redirect all http:// traffic to https://.",
      }];
    }
    if (site.httpRedirect === "no-redirect") {
      return [{
        checkId: "site-https",
        title: "http:// serves the site instead of redirecting to https://",
        severity: "high",
        file: site.url.replace(/^https:/, "http:"),
        explanation:
          "People who type the bare domain or follow an old link land on an unencrypted copy that an attacker on the network can rewrite. Redirect every http:// request to https:// with a 301, then add HSTS so browsers stop trying http.",
        remedy: hostOf(site) === "nginx"
          ? "server { listen 80; server_name _; return 301 https://$host$request_uri; }"
          : "Turn on your host's \"redirect HTTP to HTTPS\" setting, or return a 301 to https:// for every http:// request.",
      }];
    }
    return [];
  },
};

const DAY = 86_400_000;
const siteTls: SiteCheck = {
  id: "site-tls",
  group: "C-security",
  title: "Valid TLS certificate and modern protocol",
  severity: "high",
  skip: (site) => needHttps(site) ?? (site.tls ? null : "no TLS details were captured"),
  detect(site) {
    const tls = site.tls!;
    const out: Finding[] = [];
    const base = { checkId: "site-tls", file: site.url };
    if (!tls.authorized) {
      out.push({ ...base, title: "Browsers do not trust this certificate", severity: "critical", evidence: tls.issuer ? `issuer: ${tls.issuer}` : undefined,
        explanation: "Visitors see a full-page warning, and those who click through cannot tell your site from an attacker's. Install a certificate from a public authority covering this exact hostname, with its full chain." });
    }
    const left = Math.floor((Date.parse(tls.validTo) - Date.parse(site.fetchedAt)) / DAY);
    if (Number.isFinite(left) && left < 30) {
      out.push({ ...base,
        title: left < 0 ? "The certificate has expired" : `The certificate expires in ${left} day${left === 1 ? "" : "s"}`,
        severity: left < 0 ? "critical" : left < 14 ? "high" : "medium",
        evidence: `valid to ${tls.validTo}`,
        explanation: "When it lapses every visitor gets a security warning and API clients stop connecting. Renew it now and switch on automatic renewal (certbot, or your host's managed certificates)." });
    }
    if (tls.protocol && /^TLSv1(\.1)?$/.test(tls.protocol)) {
      out.push({ ...base, title: `The server negotiated ${tls.protocol}`, severity: "high", evidence: tls.protocol,
        explanation: "TLS 1.0 and 1.1 have known weaknesses and were retired in 2021 (RFC 8996). Allow only TLS 1.2 and 1.3.",
        remedy: hostOf(site) === "nginx" ? "ssl_protocols TLSv1.2 TLSv1.3;" : "Set the minimum TLS version to 1.2 in your host or load balancer settings." });
    }
    return out;
  },
};

const HSTS_MIN = 15_552_000; // 180 days
const siteHsts: SiteCheck = {
  id: "site-hsts",
  group: "C-security",
  title: "Browsers are told to always use HTTPS",
  severity: "medium",
  skip: needHttps,
  detect(site) {
    const v = site.headers["strict-transport-security"];
    const remedy = headerRemedy(site, "Strict-Transport-Security", "max-age=63072000; includeSubDomains");
    if (!v) {
      return [{ checkId: "site-hsts", title: "No Strict-Transport-Security header", severity: "medium", file: site.url, remedy,
        explanation: "Without HSTS, the first request to your domain can go over http:// and be hijacked before your redirect runs (SSL stripping). The header makes browsers go straight to https:// for the time it names." }];
    }
    const age = Number(/max-age\s*=\s*"?(\d+)/i.exec(v)?.[1] ?? 0);
    if (age < HSTS_MIN) {
      return [{ checkId: "site-hsts", title: "HSTS max-age is shorter than 180 days", severity: "low", file: site.url, evidence: clip(v), remedy,
        explanation: "A short max-age expires between visits, so returning visitors lose the protection. Use at least six months; two years is common." }];
    }
    return [];
  },
};

function cspOf(site: SiteSnapshot): { policy: string; source: "header" | "meta" } | null {
  const h = site.headers["content-security-policy"];
  if (h) return { policy: h, source: "header" };
  const meta = tags(site.html, ["meta"]).find((t) => (t.attrs["http-equiv"] ?? "").toLowerCase() === "content-security-policy");
  return meta?.attrs.content ? { policy: meta.attrs.content, source: "meta" } : null;
}

const STARTER_CSP = "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'";
const siteCsp: SiteCheck = {
  id: "site-csp",
  group: "C-security",
  title: "Content Security Policy limits which scripts run",
  severity: "high",
  detect(site) {
    const csp = cspOf(site);
    const remedy = headerRemedy(site, "Content-Security-Policy", STARTER_CSP);
    const base = { checkId: "site-csp", file: site.url };
    if (!csp) {
      const reportOnly = site.headers["content-security-policy-report-only"];
      return [{ ...base, severity: "medium", remedy,
        title: reportOnly ? "CSP is only in report-only mode" : "No Content Security Policy",
        evidence: reportOnly ? clip(reportOnly) : undefined,
        explanation: "A CSP is the browser's last line against cross-site scripting: if an attacker gets markup onto the page, the policy stops their script from running or sending data out. Start from the policy below, run it as Content-Security-Policy-Report-Only for a week, then enforce it." }];
    }
    const dirs = parseCsp(csp.policy);
    const scripts = dirs.get("script-src") ?? dirs.get("default-src");
    const out: Finding[] = [];
    if (!scripts) {
      out.push({ ...base, severity: "medium", title: "CSP does not restrict scripts", evidence: clip(csp.policy), remedy,
        explanation: "The policy has neither script-src nor default-src, so any script can still run. Add script-src." });
      return out;
    }
    const wild = scripts.filter((s) => s === "*" || s === "https:" || s === "http:" || s === "data:");
    if (wild.length) {
      out.push({ ...base, severity: "high", title: `CSP lets scripts load from ${wild.join(", ")}`, evidence: clip(csp.policy),
        explanation: "A scheme or wildcard source lets an attacker load a script from any server they control, which undoes the policy. List the exact hosts your scripts come from." });
    }
    const keyed = scripts.some((s) => /^'(nonce|sha256|sha384|sha512)-/.test(s) || s === "'strict-dynamic'");
    if (scripts.includes("'unsafe-inline'") && !keyed) {
      out.push({ ...base, severity: "medium", title: "CSP allows inline scripts ('unsafe-inline')", evidence: clip(csp.policy),
        explanation: "Most cross-site scripting injects inline script, and 'unsafe-inline' lets it run. Move inline code into files, or give each inline script a nonce or hash." });
    }
    if (scripts.includes("'unsafe-eval'")) {
      out.push({ ...base, severity: "medium", title: "CSP allows eval ('unsafe-eval')", evidence: clip(csp.policy),
        explanation: "eval() turns injected strings into running code. Remove 'unsafe-eval'; most current bundlers do not need it in production." });
    }
    return out;
  },
};

const siteClickjacking: SiteCheck = {
  id: "site-clickjacking",
  group: "C-security",
  title: "Other sites cannot frame this page",
  severity: "medium",
  detect(site) {
    if (site.headers["x-frame-options"]) return [];
    const header = site.headers["content-security-policy"];
    if (header && parseCsp(header).has("frame-ancestors")) return [];
    return [{ checkId: "site-clickjacking", title: "Any site can load this page in a frame", severity: "medium", file: site.url,
      remedy: headerRemedy(site, "Content-Security-Policy", "frame-ancestors 'self'"),
      explanation: "An attacker can show your page invisibly inside theirs and trick visitors into clicking your buttons (clickjacking): approving a payment, changing a setting. frame-ancestors in a CSP header (or X-Frame-Options: DENY) stops it. A <meta> CSP cannot set frame-ancestors." }];
  },
};

const HARDENING: Array<[string, string, string, (v: string) => boolean]> = [
  ["x-content-type-options", "X-Content-Type-Options", "nosniff", (v) => v.toLowerCase().includes("nosniff")],
  ["referrer-policy", "Referrer-Policy", "strict-origin-when-cross-origin", () => true],
  ["permissions-policy", "Permissions-Policy", "camera=(), microphone=(), geolocation=()", () => true],
];
const WHY: Record<string, string> = {
  "x-content-type-options": "Without nosniff, a browser may treat an uploaded text or image file as a script and run it.",
  "referrer-policy": "Without it, full URLs (which can carry tokens, reset links or search terms) leak to every site you link to.",
  "permissions-policy": "It switches off camera, microphone and location for the page and any frame inside it, so injected or third-party code cannot ask for them.",
};
const siteHeaders: SiteCheck = {
  id: "site-headers",
  group: "C-security",
  title: "Basic hardening headers are set",
  severity: "low",
  detect(site) {
    const out: Finding[] = [];
    for (const [key, name, value, ok] of HARDENING) {
      const v = site.headers[key];
      if (v && ok(v)) continue;
      out.push({ checkId: "site-headers", title: `${name} is ${v ? "set incorrectly" : "missing"}`, severity: "low", file: site.url,
        evidence: v ? clip(v) : undefined, remedy: headerRemedy(site, name, value), explanation: WHY[key] });
    }
    return out;
  },
};

const siteVersionLeak: SiteCheck = {
  id: "site-version-leak",
  group: "C-security",
  title: "Server software versions are not advertised",
  severity: "low",
  detect(site) {
    const out: Finding[] = [];
    const base = { checkId: "site-version-leak", severity: "low" as const, file: site.url,
      explanation: "Exact versions let automated scanners, and now AI agents, match your server to published exploits in seconds. Hide them; it costs nothing and removes the easiest lead." };
    const server = site.headers["server"];
    if (server && /\d/.test(server)) out.push({ ...base, title: "Server header names a version", evidence: `Server: ${clip(server, 60)}`,
      remedy: hostOf(site) === "nginx" ? "server_tokens off;" : hostOf(site) === "apache" ? "ServerTokens Prod\nServerSignature Off" : undefined });
    for (const h of ["x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]) {
      const v = site.headers[h];
      if (v) out.push({ ...base, title: `${h} header reveals the stack`, evidence: `${h}: ${clip(v, 60)}`,
        remedy: h === "x-powered-by" && hostOf(site) === "express" ? 'app.disable("x-powered-by"); // or app.use(helmet())' : `Remove the ${h} header in the server config.` });
    }
    const gen = tags(site.html, ["meta"]).find((t) => (t.attrs.name ?? "").toLowerCase() === "generator" && /\d/.test(t.attrs.content ?? ""));
    if (gen) out.push({ ...base, title: "A generator tag names the CMS version", evidence: clip(gen.attrs.content, 60), line: lineAt(site.html, gen.index) });
    return out;
  },
};

const SESSIONISH = /sess|sid|auth|token|jwt|login|remember|csrf|xsrf/i;
const siteCookies: SiteCheck = {
  id: "site-cookies",
  group: "C-security",
  title: "Cookies are Secure, HttpOnly and SameSite",
  severity: "high",
  skip: (site) => (site.setCookies.length ? null : "the page sets no cookies"),
  detect(site) {
    const out: Finding[] = [];
    for (const raw of site.setCookies) {
      const { name, flags } = cookieShape(raw);
      const session = SESSIONISH.test(name);
      const missing: string[] = [];
      if (isHttps(site) && !flags.has("secure")) missing.push("Secure");
      if (session && !flags.has("httponly")) missing.push("HttpOnly");
      if (!flags.has("samesite") || flags.get("samesite") === "none" && !flags.has("secure")) missing.push("SameSite");
      if (!missing.length) continue;
      const severity: Severity = session && missing.some((m) => m !== "SameSite") ? "high" : session ? "medium" : "low";
      out.push({ checkId: "site-cookies", title: `Cookie ${name} is missing ${missing.join(", ")}`, severity, file: site.url,
        evidence: `${name}=… (value not shown)`,
        remedy: `Set-Cookie: ${name}=<value>; Path=/; Secure; HttpOnly; SameSite=Lax`,
        explanation: session
          ? "This looks like a login or session cookie. Without HttpOnly any injected script can steal it and take over the account; without Secure it can travel over plain HTTP; without SameSite other sites can make requests that carry it (CSRF)."
          : "Cookies without these flags can leak over plain HTTP or be sent along with requests from other sites. Add them unless the cookie must be read by scripts." });
    }
    return out;
  },
};

const siteCors: SiteCheck = {
  id: "site-cors",
  group: "C-security",
  title: "Other origins cannot read responses with the user's cookies",
  severity: "high",
  skip: (site) => (site.probeOrigin ? null : "no CORS probe was sent"),
  detect(site) {
    const acao = site.headers["access-control-allow-origin"];
    const creds = (site.headers["access-control-allow-credentials"] ?? "").toLowerCase() === "true";
    if (!acao) return [];
    const base = { checkId: "site-cors", file: site.url, evidence: `Access-Control-Allow-Origin: ${clip(acao, 80)}${creds ? "; Allow-Credentials: true" : ""}` };
    const fix = "Check the Origin against a fixed allow-list of your own front-ends and only then echo it back. Never echo the request's Origin blindly.";
    if (acao === site.probeOrigin && creds) {
      return [{ ...base, severity: "critical", title: "Any website can read responses as the logged-in visitor", remedy: fix,
        explanation: `Siidekick sent Origin: ${site.probeOrigin}, a site that does not exist, and the server allowed it with credentials. Any page a logged-in user visits can call this site with their cookies and read the answers: profile, messages, tokens.` }];
    }
    if (acao === "null" && creds) {
      return [{ ...base, severity: "high", title: "CORS trusts the null origin with credentials", remedy: fix,
        explanation: "Sandboxed frames and local files send Origin: null, so an attacker can produce it on demand and read responses with the user's cookies." }];
    }
    if (acao === site.probeOrigin) {
      return [{ ...base, severity: "low", title: "CORS echoes back any origin", remedy: fix,
        explanation: "Without credentials this only exposes what is already public, but the same code on an authenticated route becomes a full data leak. Use an allow-list." }];
    }
    return [];
  },
};

const ACTIVE = new Set(["script", "iframe", "link", "embed", "object"]);
const siteMixedContent: SiteCheck = {
  id: "site-mixed-content",
  group: "C-security",
  title: "No http:// resources on an https page",
  severity: "medium",
  skip: needHttps,
  detect(site) {
    const out: Finding[] = [];
    const seen = new Set<string>();
    for (const t of tags(site.html, ["script", "iframe", "link", "img", "audio", "video", "source", "embed", "object"])) {
      if (t.name === "link" && !/stylesheet|preload|modulepreload|icon/i.test(t.attrs.rel ?? "")) continue;
      const ref = t.attrs.src ?? t.attrs.href ?? t.attrs.data;
      if (!ref || !/^\s*http:\/\//i.test(ref) || seen.has(ref)) continue;
      seen.add(ref);
      const active = ACTIVE.has(t.name);
      out.push({ checkId: "site-mixed-content", severity: active ? "medium" : "low", file: site.url, line: lineAt(site.html, t.index),
        title: `<${t.name}> loads over plain http`, evidence: clip(ref, 100),
        explanation: active
          ? "Browsers block insecure scripts, frames and styles on an https page, so this part of the site is broken; where it is not blocked, anyone on the network can swap it for their own code. Load it over https://."
          : "Images and media over http can be read or replaced in transit, and browsers mark the page as not fully secure. Load it over https://." });
    }
    return out;
  },
};

/** Hosts known to have served malware to the sites that embedded them. */
const HIJACKED_CDN = /(^|\.)polyfill\.io$/i;
const siteSri: SiteCheck = {
  id: "site-sri",
  group: "C-security",
  title: "Third-party scripts are pinned or trusted",
  severity: "low",
  detect(site) {
    const page = new URL(site.url);
    const byHost = new Map<string, { count: number; index: number }>();
    const out: Finding[] = [];
    for (const t of tags(site.html, ["script"])) {
      const u = t.attrs.src ? resolve(t.attrs.src, site.url) : null;
      if (!u || u.host === page.host) continue;
      if (HIJACKED_CDN.test(u.hostname)) {
        out.push({ checkId: "site-sri", severity: "critical", title: `Loads a script from ${u.hostname}`, file: site.url, line: lineAt(site.html, t.index), evidence: clip(u.href, 100),
          explanation: "The polyfill.io domain changed hands in 2024 and its script was modified to send visitors to scam and malware sites. Remove the tag; modern browsers rarely need the polyfill, and Cloudflare and Fastly run safe mirrors." });
        continue;
      }
      if (t.attrs.integrity) continue;
      const cur = byHost.get(u.host);
      byHost.set(u.host, { count: (cur?.count ?? 0) + 1, index: cur?.index ?? t.index });
    }
    for (const [host, { count, index }] of byHost) {
      out.push({ checkId: "site-sri", severity: "low", file: site.url, line: lineAt(site.html, index),
        title: `${count} script${count === 1 ? "" : "s"} from ${host} without integrity`, evidence: host,
        remedy: '<script src="…" integrity="sha384-…" crossorigin="anonymous"></script>',
        explanation: "Whoever controls that host can change the script and run code on your page, as happened with polyfill.io in 2024. For fixed library files add an integrity hash; for tags that change (analytics, chat widgets) keep the list short and allow only those hosts in your CSP." });
    }
    return out;
  },
};

const siteForms: SiteCheck = {
  id: "site-forms",
  group: "C-security",
  title: "Forms and passwords travel encrypted",
  severity: "high",
  skip: (site) => (tags(site.html, ["form", "input"]).length ? null : "the page has no forms"),
  detect(site) {
    const out: Finding[] = [];
    for (const f of tags(site.html, ["form"])) {
      const action = f.attrs.action ? resolve(f.attrs.action, site.url) : null;
      if (action?.protocol === "http:") {
        out.push({ checkId: "site-forms", severity: "high", title: "A form submits to plain http", file: site.url, line: lineAt(site.html, f.index), evidence: clip(action.href, 100),
          explanation: "What people type into this form, possibly passwords or card details, crosses the network unencrypted. Point the action at https://." });
      }
    }
    const pw = tags(site.html, ["input"]).find((t) => (t.attrs.type ?? "").toLowerCase() === "password");
    if (pw && !isHttps(site)) {
      out.push({ checkId: "site-forms", severity: "critical", title: "A password field on an http page", file: site.url, line: lineAt(site.html, pw.index),
        explanation: "The password is sent in clear text and the page itself can be altered in transit to send it elsewhere. Serve the page over HTTPS." });
    }
    return out;
  },
};

const EXTRA_SECRETS: Array<[string, RegExp]> = [
  ["Anthropic API key", /\bsk-ant-[A-Za-z0-9_-]{32,}/g],
  ["OpenAI API key", /\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}/g],
  ["Groq API key", /\bgsk_[A-Za-z0-9]{40,}/g],
  ["Hugging Face token", /\bhf_[A-Za-z0-9]{30,}/g],
  ["Slack token", /\bxox[abprs]-[A-Za-z0-9-]{10,}/g],
  ["SendGrid key", /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g],
  ["Stripe restricted key", /\brk_live_[0-9a-zA-Z]{16,}/g],
];

function sources(site: SiteSnapshot): { file: string; content: string }[] {
  return [{ file: site.url, content: site.html }, ...site.scripts.map((s) => ({ file: s.url, content: s.content }))];
}

const siteSecrets: SiteCheck = {
  id: "site-secrets",
  group: "C-security",
  title: "No secret keys in the page or its scripts",
  severity: "critical",
  detect(site) {
    const out: Finding[] = [];
    const seen = new Set<string>();
    for (const src of sources(site)) {
      for (const [kind, re] of [...VENDOR_SECRETS, ...EXTRA_SECRETS]) {
        for (const m of src.content.matchAll(re)) {
          if (seen.has(m[0])) continue;
          seen.add(m[0]);
          out.push({ checkId: "site-secrets", severity: "critical", title: `${kind} is public in the site's code`, file: src.file, line: lineAt(src.content, m.index!),
            evidence: kind === "Private key" ? "private key block (not shown)" : redact(m[0]),
            explanation: "Anyone can open this file in their browser and copy the key; bots that crawl for keys find them within minutes. Revoke it with the provider now (a new deploy does not un-leak it), then move the call to a server route that reads the key from an environment variable." });
        }
      }
      for (const m of src.content.matchAll(JWT)) {
        if (seen.has(m[0]) || jwtRole(m[1]) !== "service_role") continue;
        seen.add(m[0]);
        out.push({ checkId: "site-secrets", severity: "critical", title: "Supabase service_role key is public", file: src.file, line: lineAt(src.content, m.index!),
          evidence: "JWT with role service_role (value not shown)",
          explanation: "This key bypasses every row-level security rule: anyone who copies it can read, change or delete all of your data. Rotate it in the Supabase dashboard now; the browser should only ever hold the anon key." });
      }
      const dab = /dangerouslyAllowBrowser\s*:\s*(?:true|!0)/.exec(src.content);
      if (dab && !seen.has(`dab:${src.file}`)) {
        seen.add(`dab:${src.file}`);
        out.push({ checkId: "site-secrets", severity: "high", title: "An AI SDK is allowed to run in the browser", file: src.file, line: lineAt(src.content, dab.index),
          evidence: clip(dab[0]),
          explanation: "dangerouslyAllowBrowser means the model API key is shipped to every visitor. Call the model from a server route instead." });
      }
    }
    return out;
  },
};

const SYSTEM_PROMPT = /["']?role["']?\s*:\s*["']system["']\s*,\s*["']?content["']?\s*:\s*["'`]/;
const siteAiDirect: SiteCheck = {
  id: "site-ai-direct",
  group: "F-ai",
  title: "The browser does not talk to AI models directly",
  severity: "high",
  detect(site) {
    const out: Finding[] = [];
    const hosts = new Set<string>();
    let prompt = false;
    for (const src of sources(site)) {
      for (const m of src.content.matchAll(LLM_HOSTS)) {
        if (hosts.has(m[1])) continue;
        hosts.add(m[1]);
        out.push({ checkId: "site-ai-direct", severity: "high", title: `The browser calls ${m[1]} directly`, file: src.file, line: lineAt(src.content, m.index!), evidence: m[0],
          explanation: "Calling a model API from the page means the key and the full prompt live in the visitor's browser. Anyone can lift the key, or reuse your endpoint to run their own prompts on your bill. Route model calls through your server, which holds the key, checks the user and rate-limits." });
      }
      const p = SYSTEM_PROMPT.exec(src.content);
      if (p && !prompt) {
        prompt = true;
        out.push({ checkId: "site-ai-direct", severity: "medium", title: "The system prompt ships in browser code", file: src.file, line: lineAt(src.content, p.index),
          explanation: "If the browser sends the system prompt, anyone can rewrite it and turn your AI feature into a free general-purpose model, or strip the rules that keep it safe. Keep the system prompt on the server and send only the user's message." });
      }
    }
    return out;
  },
};

const siteSourceMaps: SiteCheck = {
  id: "site-source-maps",
  group: "C-security",
  title: "Original source code is not published",
  severity: "low",
  detect(site) {
    if (!site.sourceMaps.length) return [];
    return [{ checkId: "site-source-maps", severity: "low", file: site.sourceMaps[0],
      title: `${site.sourceMaps.length} source map${site.sourceMaps.length === 1 ? " is" : "s are"} public`, evidence: site.sourceMaps.slice(0, 3).join(", "),
      remedy: "Vite: build.sourcemap = false (or 'hidden'). Next.js: productionBrowserSourceMaps: false. Or upload maps to your error tracker and do not deploy them.",
      explanation: "Source maps rebuild your original code, comments and internal API routes for anyone who asks. That makes finding a weakness much faster, for people and for AI tools alike." }];
  },
};

const siteSecurityTxt: SiteCheck = {
  id: "site-security-txt",
  group: "C-security",
  title: "Researchers know how to report a problem",
  severity: "info",
  skip: (site) => (site.securityTxt === null ? "security.txt was not checked" : null),
  detect(site) {
    if (site.securityTxt) return [];
    const origin = new URL(site.url).origin;
    return [{ checkId: "site-security-txt", severity: "info", title: "No /.well-known/security.txt", file: `${origin}/.well-known/security.txt`,
      remedy: `Contact: mailto:security@${new URL(site.url).hostname}\nExpires: ${new Date(Date.parse(site.fetchedAt) + 365 * DAY).toISOString()}`,
      explanation: "Someone who finds a hole in your site has no listed way to tell you, so the report may go nowhere, or to someone else. security.txt (RFC 9116) is two lines." }];
  },
};

export const siteChecks: SiteCheck[] = [
  siteHttps, siteTls, siteHsts, siteCsp, siteClickjacking, siteCookies, siteCors, siteForms,
  siteSecrets, siteAiDirect, siteMixedContent, siteSri, siteVersionLeak, siteSourceMaps, siteHeaders, siteSecurityTxt,
];
