// Proof of fix: boot the demo shop as it was and as patched, replay the same attacks on both, and keep a
// receipt per attack. Only ever runs the bundled demo, never an uploaded repo.
import { execFile, spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import type { RepoSnapshot } from "./types.js";
import { writeRepo } from "./verify.js";

export type ReplayVerdict = "blocked" | "still-open" | "not-reproduced" | "inconclusive";
export type Probe = { exploited: boolean; detail: string };

export interface AttackReceipt {
  id: string;
  checkId: string;
  title: string;
  request: string;
  kind: "live" | "static";
  before: Probe;
  after: Probe;
  /** A harmless request the patched app must still answer, so "blocked" never means "broken". */
  control?: { label: string; ok: boolean };
  verdict: ReplayVerdict;
}

export interface PathStep {
  attackId: string;
  text: string;
  before: boolean;
  after: boolean;
}

export interface AttackPath {
  id: string;
  title: string;
  impact: "critical" | "high";
  steps: PathStep[];
  openBefore: boolean;
  openAfter: boolean;
  /** Checks whose fix breaks this chain (or would, when the chain is still open). */
  cutBy: string[];
}

export interface ReplayReport {
  available: boolean;
  reason?: string;
  attacks: AttackReceipt[];
  paths: AttackPath[];
  tests?: { ran: boolean; passed: number; failed: number };
  ms: number;
}

type Booted = { base: string; dir: string; stop: () => Promise<void> };
// Loot carries a leaked credential between attacks inside one run. It is never returned or logged.
type Ctx = { base: string; adminToken: string; loot: { email?: string; password?: string; takeover?: boolean } };

const REQUEST_TIMEOUT_MS = 3000;
const BOOT_TIMEOUT_MS = 8000;
const TEST_TIMEOUT_MS = 15000;
const BRUTE_FORCE_TRIES = 8;
const SQLI = "zzz' UNION SELECT id,email,password,0 FROM users --";

async function req(ctx: Ctx, path: string, init: RequestInit = {}): Promise<Response> {
  return fetch(ctx.base + path, { ...init, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
}

function login(ctx: Ctx, email: string, password: string): Promise<Response> {
  return req(ctx, "/login", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
}

type Attack = {
  id: string;
  checkId: string;
  title: string;
  request: string;
  exploit: (ctx: Ctx) => Promise<Probe>;
  control: { label: string; run: (ctx: Ctx) => Promise<boolean> };
};

const attacks: Attack[] = [
  {
    id: "sqli-dump",
    checkId: "sql-string-concat",
    title: "Dump every password through the search box",
    request: `GET /api/products?q=${SQLI}`,
    async exploit(ctx) {
      const res = await req(ctx, `/api/products?q=${encodeURIComponent(SQLI)}`);
      const rows: { name?: unknown; price?: unknown }[] = res.ok ? await res.json().catch(() => []) : [];
      const leaked = Array.isArray(rows) ? rows.filter((r) => typeof r.name === "string" && r.name.includes("@")) : [];
      const passwords = leaked.filter((r) => typeof r.price === "string");
      if (passwords.length > 0) {
        ctx.loot.email = String(passwords[0].name);
        ctx.loot.password = String(passwords[0].price);
        ctx.loot.takeover = (await login(ctx, ctx.loot.email, ctx.loot.password)).status === 200;
      }
      if (leaked.length === 0) return { exploited: false, detail: `${res.status}, no user rows came back` };
      const tail = ctx.loot.takeover ? "; logged in with a leaked password" : "";
      return { exploited: true, detail: `${res.status}, ${leaked.length} emails and ${passwords.length} plaintext passwords leaked${tail}` };
    },
    control: {
      label: "a normal search for “Mug” still returns products",
      async run(ctx) {
        const res = await req(ctx, "/api/products?q=Mug");
        const rows = res.ok ? await res.json().catch(() => []) : [];
        return Array.isArray(rows) && rows.length >= 1;
      },
    },
  },
  {
    id: "admin-open",
    checkId: "auth-on-endpoints",
    title: "Read the user list without logging in",
    request: "GET /admin/users (no Authorization header)",
    async exploit(ctx) {
      const res = await req(ctx, "/admin/users");
      const rows: { email?: unknown }[] = res.ok ? await res.json().catch(() => []) : [];
      const emails = Array.isArray(rows) ? rows.filter((r) => typeof r.email === "string") : [];
      if (!ctx.loot.email && emails.length > 0) ctx.loot.email = String(emails[0].email);
      return emails.length > 0
        ? { exploited: true, detail: `${res.status}, ${emails.length} user emails returned` }
        : { exploited: false, detail: `${res.status}, nothing returned` };
    },
    control: {
      label: "the admin with the right token still gets in",
      async run(ctx) {
        return (await req(ctx, "/admin/users", { headers: { authorization: `Bearer ${ctx.adminToken}` } })).status === 200;
      },
    },
  },
  {
    id: "brute-force",
    checkId: "rate-limit",
    title: "Guess a password with unlimited tries",
    request: `POST /login × ${BRUTE_FORCE_TRIES} wrong passwords`,
    async exploit(ctx) {
      const email = ctx.loot.email ?? "someone@example.com";
      for (let i = 1; i <= BRUTE_FORCE_TRIES; i++) {
        const res = await login(ctx, email, `wrong-guess-${i}`);
        if (res.status === 429) return { exploited: false, detail: `answered 429 from wrong guess ${i} of ${BRUTE_FORCE_TRIES}` };
      }
      return { exploited: true, detail: `${BRUTE_FORCE_TRIES} wrong passwords, none slowed down (all 401)` };
    },
    control: {
      label: "a real customer can still log in",
      async run(ctx) {
        return (await login(ctx, "aarya@campus.edu", "password123")).status === 200;
      },
    },
  },
  {
    id: "cors-read",
    checkId: "open-cors",
    title: "Let any website read your API",
    request: "GET /api/products with Origin: https://evil.example",
    async exploit(ctx) {
      const res = await req(ctx, "/api/products?q=Mug", { headers: { origin: "https://evil.example" } });
      const allow = res.headers.get("access-control-allow-origin");
      const open = allow === "*" || allow === "https://evil.example";
      return open
        ? { exploited: true, detail: `Access-Control-Allow-Origin: ${allow}` }
        : { exploited: false, detail: allow ? `only ${allow} is allowed` : "no CORS header for that origin" };
    },
    control: {
      label: "the shop's own API still answers",
      async run(ctx) {
        return (await req(ctx, "/api/products?q=Mug")).ok;
      },
    },
  },
  {
    id: "clickjack",
    checkId: "security-headers",
    title: "Frame the shop inside another site",
    request: "GET / and check frame headers",
    async exploit(ctx) {
      const res = await req(ctx, "/");
      const xfo = res.headers.get("x-frame-options");
      const csp = res.headers.get("content-security-policy") ?? "";
      const framable = !xfo && !/frame-ancestors/i.test(csp);
      return framable
        ? { exploited: true, detail: "no X-Frame-Options and no frame-ancestors: any site can frame it" }
        : { exploited: false, detail: xfo ? `X-Frame-Options: ${xfo}` : "CSP frame-ancestors set" };
    },
    control: {
      label: "the home page still loads",
      async run(ctx) {
        const res = await req(ctx, "/");
        return res.ok && (await res.text()).includes("CampusKart");
      },
    },
  },
];

const KEY_RE = /\b\w*(?:KEY|SECRET|TOKEN)\w*\s*=\s*["']([^"'\s]{12,})["']/;

/** Static proof for the hardcoded key: no request can show it, so check the files themselves. */
function secretReceipt(before: RepoSnapshot, after: RepoSnapshot): AttackReceipt | null {
  let literal: string | undefined;
  let where = "";
  for (const f of before.files) {
    const m = KEY_RE.exec(f.content);
    if (m) {
      literal = m[1];
      where = f.path;
      break;
    }
  }
  if (!literal) return null;
  const still = after.files.find((f) => f.content.includes(literal));
  const probe = (file: RepoFile | undefined): Probe =>
    file
      ? { exploited: true, detail: `key literal (${literal.length} chars) readable in ${file.path}` }
      : { exploited: false, detail: "key literal is in no file; read from the environment" };
  const beforeProbe = probe(before.files.find((f) => f.path === where));
  const afterProbe = probe(still);
  return {
    id: "secret-read",
    checkId: "secrets-in-repo",
    title: "Copy the payment key from the code",
    request: `read ${where}`,
    kind: "static",
    before: beforeProbe,
    after: afterProbe,
    verdict: afterProbe.exploited ? "still-open" : "blocked",
  };
}
type RepoFile = RepoSnapshot["files"][number];

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      srv.close(() => resolve(port));
    });
  });
}

/** node:sqlite needs a flag before Node 23; only pass it where this Node knows it. */
function nodeArgs(): string[] {
  return process.allowedNodeEnvironmentFlags.has("--experimental-sqlite") ? ["--experimental-sqlite"] : [];
}

// The child gets only what it needs. No AWS credentials or other parent secrets reach the demo app.
function childEnv(port: number, runtimeDir: string, adminToken: string): NodeJS.ProcessEnv {
  return { PORT: String(port), NODE_PATH: runtimeDir, ADMIN_TOKEN: adminToken, NODE_NO_WARNINGS: "1" };
}

async function boot(repo: RepoSnapshot, runtimeDir: string, adminToken: string): Promise<Booted> {
  const dir = await mkdtemp(join(tmpdir(), "siidekick-replay-"));
  await writeRepo(repo, dir);
  const port = await freePort();
  const child = spawn(process.execPath, [...nodeArgs(), "server.js"], {
    cwd: dir,
    env: childEnv(port, runtimeDir, adminToken),
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  child.stderr?.on("data", (d: Buffer) => {
    stderr = (stderr + d.toString()).slice(-400);
  });
  let exited = false;
  child.once("exit", () => {
    exited = true;
  });
  const stop = async () => {
    if (!exited) child.kill("SIGKILL");
    await rm(dir, { recursive: true, force: true });
  };
  const base = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + BOOT_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (exited) {
      await stop();
      throw new Error(`app exited on boot: ${stderr.trim().split("\n").pop() ?? "no output"}`);
    }
    try {
      await fetch(base + "/", { signal: AbortSignal.timeout(500) });
      return { base, dir, stop };
    } catch {
      await new Promise((r) => setTimeout(r, 100));
    }
  }
  await stop();
  throw new Error("app did not answer in time");
}

function runTests(dir: string, runtimeDir: string): Promise<{ ran: boolean; passed: number; failed: number }> {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [...nodeArgs(), "--test", "--test-reporter=tap", "test/"],
      { cwd: dir, env: childEnv(0, runtimeDir, "unused"), timeout: TEST_TIMEOUT_MS },
      (_err, stdout) => {
        const passed = Number(/^# pass (\d+)/m.exec(stdout)?.[1] ?? NaN);
        const failed = Number(/^# fail (\d+)/m.exec(stdout)?.[1] ?? NaN);
        if (Number.isNaN(passed) || Number.isNaN(failed)) return resolve({ ran: false, passed: 0, failed: 0 });
        resolve({ ran: true, passed, failed });
      },
    );
  });
}

async function safe<T>(fn: () => Promise<T>, fallback: (e: Error) => T): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    return fallback(e as Error);
  }
}

type Probed = { probes: Probe[]; controls: (boolean | undefined)[]; takeover: boolean };

// Controls run first, so the brute force cannot lock the real customer's login out of its own check.
async function probeAll(b: Booted, adminToken: string, withControls: boolean): Promise<Probed> {
  const ctx: Ctx = { base: b.base, adminToken, loot: {} };
  const controls: (boolean | undefined)[] = [];
  for (const a of attacks) controls.push(withControls ? await safe(() => a.control.run(ctx), () => false) : undefined);
  const probes: Probe[] = [];
  for (const a of attacks) {
    probes.push(await safe(() => a.exploit(ctx), (e) => ({ exploited: false, detail: `request failed: ${e.name}` })));
  }
  return { probes, controls, takeover: ctx.loot.takeover === true };
}

function verdictOf(before: Probe, after: Probe, control: boolean | undefined): ReplayVerdict {
  if (!before.exploited) return "not-reproduced";
  if (after.exploited) return "still-open";
  if (control === false) return "inconclusive";
  return "blocked";
}

/** Chains of attacks that end in real harm. A path is open while every step in it still works. */
export function attackPaths(receipts: AttackReceipt[], takeover: { before: boolean; after: boolean }): AttackPath[] {
  const byId = new Map(receipts.map((r) => [r.id, r]));
  const step = (attackId: string, text: string): PathStep => {
    const r = byId.get(attackId);
    return { attackId, text, before: r?.before.exploited ?? false, after: r?.after.exploited ?? false };
  };
  const chains: Omit<AttackPath, "openBefore" | "openAfter" | "cutBy">[] = [
    {
      id: "steal-accounts",
      title: "Log in as any customer",
      impact: "critical",
      steps: [
        step("sqli-dump", "Search box leaks every email with its plaintext password"),
        { attackId: "sqli-dump", text: "Use a leaked password to log in as that customer", before: takeover.before, after: takeover.after },
      ],
    },
    {
      id: "guess-accounts",
      title: "Guess your users' passwords",
      impact: "high",
      steps: [
        step("admin-open", "Open /admin/users lists every user's email"),
        step("brute-force", "Try unlimited passwords against each email"),
      ],
    },
  ];
  return chains.map((c) => {
    const checkOf = (s: PathStep) => byId.get(s.attackId)?.checkId ?? s.attackId;
    const broken = c.steps.filter((s) => s.before && !s.after).map(checkOf);
    const cutBy = [...new Set(broken.length > 0 ? broken : c.steps.map(checkOf))];
    return {
      ...c,
      openBefore: c.steps.every((s) => s.before),
      openAfter: c.steps.every((s) => s.after),
      cutBy,
    };
  });
}

/**
 * Boots `before` and `after` side by side from `runtimeDir` (a node_modules folder holding express and lodash),
 * replays every attack on both, and runs the patched app's own tests. Fails soft: when the app cannot boot
 * here, the report says so and carries no receipts.
 */
export async function replayDemo(opts: { before: RepoSnapshot; after: RepoSnapshot; runtimeDir: string }): Promise<ReplayReport> {
  const started = Date.now();
  const adminToken = randomBytes(18).toString("hex");
  const [b, a] = await Promise.allSettled([boot(opts.before, opts.runtimeDir, adminToken), boot(opts.after, opts.runtimeDir, adminToken)]);
  if (b.status === "rejected" || a.status === "rejected") {
    if (b.status === "fulfilled") await b.value.stop();
    if (a.status === "fulfilled") await a.value.stop();
    const err = (b.status === "rejected" ? b.reason : (a as PromiseRejectedResult).reason) as Error;
    return { available: false, reason: `replay unavailable here: ${err.message}`, attacks: [], paths: [], ms: Date.now() - started };
  }
  try {
    const [pb, pa, tests] = await Promise.all([
      probeAll(b.value, adminToken, false),
      probeAll(a.value, adminToken, true),
      runTests(a.value.dir, opts.runtimeDir),
    ]);
    const receipts: AttackReceipt[] = attacks.map((atk, i) => ({
      id: atk.id,
      checkId: atk.checkId,
      title: atk.title,
      request: atk.request,
      kind: "live",
      before: pb.probes[i],
      after: pa.probes[i],
      control: { label: atk.control.label, ok: pa.controls[i] === true },
      verdict: verdictOf(pb.probes[i], pa.probes[i], pa.controls[i]),
    }));
    const secret = secretReceipt(opts.before, opts.after);
    if (secret) receipts.push(secret);
    const paths = attackPaths(receipts, { before: pb.takeover, after: pa.takeover });
    return { available: true, attacks: receipts, paths, tests, ms: Date.now() - started };
  } finally {
    await Promise.all([b.value.stop(), a.value.stop()]);
  }
}
