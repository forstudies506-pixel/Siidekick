import type { Check, CheckContext, Finding, RepoFile, Severity } from "../types.js";
import { lineAt } from "../util.js";

const SKIP = /(^|\/)(node_modules|\.venv|venv|site-packages)\//;
const NPM_REGISTRY = "https://registry.npmjs.org/";
const PYPI = "https://pypi.org/pypi/";
// A slow registry must not hang a Lambda scan; the check then reports an error instead.
const TIMEOUT_MS = 8000;
const CONCURRENCY = 8;
const DEP_SECTIONS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"];
/** Specs that are not resolved from the public registry by name. */
const NON_REGISTRY_SPEC = /^(file:|link:|workspace:|portal:|npm:|git\+|git:|github:|https?:|ssh:)|^[\w.-]+\/[\w.-]+(#.*)?$/;

/**
 * Popular names an AI assistant is most likely to misspell. Kept short on purpose: a near miss of
 * an obscure name is noise. A dependency on this list is never flagged as a near miss.
 */
const POPULAR_NPM = [
  "express", "react", "preact", "react-dom", "next", "lodash", "axios", "moment", "dayjs", "chalk",
  "commander", "dotenv", "cors", "helmet", "mongoose", "sequelize", "prisma", "typeorm", "jsonwebtoken",
  "bcrypt", "bcryptjs", "passport", "nodemailer", "socket.io", "webpack", "vite", "eslint", "prettier",
  "typescript", "jest", "vitest", "mocha", "chai", "cheerio", "puppeteer", "playwright", "redux",
  "zustand", "tailwindcss", "postcss", "autoprefixer", "openai", "langchain", "multer", "morgan",
  "winston", "nodemon", "uuid", "validator", "joi", "yup", "zod", "classnames", "underscore",
  "request", "node-fetch", "cross-env", "rimraf", "body-parser", "cookie-parser", "express-session",
  "express-rate-limit", "graphql", "apollo-server", "firebase", "firebase-admin", "stripe", "twilio",
  "sharp", "jimp", "colors", "color", "tslint", "prism", "debug", "async", "bluebird", "ramda", "immer", "formik", "styled-components",
];
const POPULAR_PYPI = [
  "requests", "numpy", "pandas", "flask", "django", "fastapi", "uvicorn", "pydantic", "sqlalchemy",
  "beautifulsoup4", "selenium", "pillow", "matplotlib", "scipy", "scikit-learn", "tensorflow", "torch",
  "openai", "anthropic", "langchain", "boto3", "pytest", "python-dotenv", "httpx", "aiohttp", "celery",
  "redis", "psycopg2", "pymongo", "jinja2", "werkzeug", "cryptography", "pyjwt", "bcrypt", "gunicorn",
];

interface Dep {
  ecosystem: "npm" | "pypi";
  name: string;
  file: string;
  line: number;
}

function editDistanceIsOne(a: string, b: string): boolean {
  if (a === b || Math.abs(a.length - b.length) > 1) return false;
  let i = 0;
  while (i < a.length && i < b.length && a[i] === b[i]) i++;
  if (a.length === b.length) {
    // one substitution, or one adjacent swap ("lodahs" for "lodash")
    if (a.slice(i + 1) === b.slice(i + 1)) return true;
    return a[i] === b[i + 1] && a[i + 1] === b[i] && a.slice(i + 2) === b.slice(i + 2);
  }
  const [long, short] = a.length > b.length ? [a, b] : [b, a];
  return long.slice(i + 1) === short.slice(i);
}

function nearMiss(name: string, popular: string[]): string | null {
  if (name.length < 5 || popular.includes(name)) return null;
  return popular.find((p) => p.length >= 5 && editDistanceIsOne(name, p)) ?? null;
}

/** PEP 503 normalisation: PyPI treats Foo_Bar, foo-bar and foo.bar as one project. */
function normPy(name: string): string {
  return name.toLowerCase().replace(/[-_.]+/g, "-");
}

function npmDeps(files: RepoFile[]): Dep[] {
  const local = new Set<string>();
  const manifests: { f: RepoFile; json: Record<string, unknown> }[] = [];
  for (const f of files) {
    if (SKIP.test(f.path) || !/(^|\/)package\.json$/.test(f.path)) continue;
    let json: unknown;
    try {
      json = JSON.parse(f.content);
    } catch {
      continue; // a broken manifest is another check's problem
    }
    if (typeof json !== "object" || json === null) continue;
    const rec = json as Record<string, unknown>;
    if (typeof rec.name === "string") local.add(rec.name);
    manifests.push({ f, json: rec });
  }
  const deps: Dep[] = [];
  for (const { f, json } of manifests) {
    for (const section of DEP_SECTIONS) {
      const block = json[section];
      if (typeof block !== "object" || block === null) continue;
      for (const [name, spec] of Object.entries(block as Record<string, unknown>)) {
        // A monorepo depends on its own workspaces by name; those are not on the registry.
        if (typeof spec !== "string" || NON_REGISTRY_SPEC.test(spec.trim()) || local.has(name)) continue;
        const at = f.content.indexOf(`"${name}"`);
        deps.push({ ecosystem: "npm", name, file: f.path, line: at >= 0 ? lineAt(f.content, at) : 1 });
      }
    }
  }
  return deps;
}

function pypiDeps(files: RepoFile[]): Dep[] {
  const deps: Dep[] = [];
  for (const f of files) {
    if (SKIP.test(f.path) || !/(^|\/)requirements[\w.-]*\.txt$/.test(f.path)) continue;
    const lines = f.content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].replace(/#.*/, "").trim();
      if (!line || line.startsWith("-") || /:\/\/|^git\+|@\s*(file|https?):/.test(line)) continue;
      const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)/.exec(line);
      if (m) deps.push({ ecosystem: "pypi", name: normPy(m[1]), file: f.path, line: i + 1 });
    }
  }
  return deps;
}

/** True when an .npmrc points this name (or every name) at a registry other than public npm. */
function privateRegistryFor(name: string, files: RepoFile[]): boolean {
  const scope = name.startsWith("@") ? name.split("/")[0] : null;
  for (const f of files) {
    if (SKIP.test(f.path) || !/(^|\/)\.npmrc$/.test(f.path)) continue;
    for (const raw of f.content.split("\n")) {
      const line = raw.trim();
      if (scope && line.startsWith(`${scope}:registry`)) return true;
      const m = /^registry\s*=\s*(\S+)/.exec(line);
      if (m && !m[1].includes("registry.npmjs.org")) return true;
    }
  }
  return false;
}

async function exists(dep: Dep, fetchFn: typeof fetch): Promise<boolean> {
  const url =
    dep.ecosystem === "npm" ? NPM_REGISTRY + dep.name.replace("/", "%2f") : `${PYPI}${encodeURIComponent(dep.name)}/json`;
  const res = await fetchFn(url, {
    method: "HEAD",
    headers: dep.ecosystem === "npm" ? { Accept: "application/vnd.npm.install-v1+json" } : {},
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  if (res.ok) return true;
  if (res.status === 404) return false;
  // Rate limit, outage, proxy page: we cannot tell, so the check must show as errored, never passed.
  throw new Error(`${dep.ecosystem} registry answered ${res.status} for ${dep.name}`);
}

async function pool<T, R>(items: T[], n: number, fn: (t: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(n, items.length) }, async () => {
      while (next < items.length) {
        const i = next++;
        out[i] = await fn(items[i]);
      }
    }),
  );
  return out;
}

export const hallucinatedPackage: Check = {
  id: "hallucinated-package",
  group: "F-ai",
  title: "Dependencies exist on the public registry",
  severity: "critical",
  mode: "report",

  async detect(ctx: CheckContext): Promise<Finding[]> {
    const { repo } = ctx;
    const all = [...npmDeps(repo.files), ...pypiDeps(repo.files)];
    if (all.length === 0) return [];
    const fetchFn = ctx.fetch ?? fetch;

    // One lookup per unique name: monorepos list the same dependency in many manifests.
    const unique = new Map<string, Dep>();
    for (const d of all) unique.set(`${d.ecosystem}:${d.name}`, d);
    const keys = [...unique.keys()];
    const found = await pool(keys, CONCURRENCY, (k) => exists(unique.get(k)!, fetchFn));
    const published = new Map(keys.map((k, i) => [k, found[i]]));

    const findings: Finding[] = [];
    for (const d of all) {
      const reg = d.ecosystem === "npm" ? "npm" : "PyPI";
      if (!published.get(`${d.ecosystem}:${d.name}`)) {
        // Resolved from the team's own registry, which we cannot see.
        if (d.ecosystem === "npm" && privateRegistryFor(d.name, repo.files)) continue;
        const scoped = d.name.startsWith("@");
        const severity: Severity = scoped ? "medium" : "critical";
        findings.push({
          checkId: "hallucinated-package",
          title: scoped ? `${d.name} is not on public npm` : `${d.name} does not exist on ${reg}`,
          severity,
          file: d.file,
          line: d.line,
          evidence: `${reg} lookup for "${d.name}" returned 404`,
          explanation: scoped
            ? "This scoped package is not published on public npm. If it comes from a private registry, add that registry to .npmrc. If not, the name may be invented, and whoever registers the scope can ship code into this project."
            : "AI coding assistants often invent plausible package names. This one is not published, so anyone can register it and the next install runs their code (slopsquatting). Remove it or replace it with the package you meant.",
        });
        continue;
      }
      const near = nearMiss(d.name, d.ecosystem === "npm" ? POPULAR_NPM : POPULAR_PYPI);
      if (near) {
        findings.push({
          checkId: "hallucinated-package",
          title: `${d.name} looks like a misspelling of ${near}`,
          severity: "high",
          file: d.file,
          line: d.line,
          evidence: `"${d.name}" is one letter away from the popular "${near}"`,
          explanation: `Typosquatted packages copy a popular name with one letter changed and run code on install. Check that ${d.name} is the package you meant; if you wanted ${near}, change the name.`,
        });
      }
    }
    return findings;
  },
};
