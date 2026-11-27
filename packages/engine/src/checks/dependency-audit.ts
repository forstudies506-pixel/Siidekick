import type { Check, CheckContext, Finding, Patch, Severity } from "../types.js";
import { importersOf, lockGraph } from "../deps/graph.js";
import { exploitIntel } from "../deps/intel.js";

const OSV_BATCH = "https://api.osv.dev/v1/querybatch";
const OSV_VULNS = "https://api.osv.dev/v1/vulns/";
// A slow OSV must not hang a Lambda scan; the check then reports an error instead.
const OSV_TIMEOUT_MS = 8000;
// Our own cap per querybatch request; the OSV docs give no limit, so keep each body modest.
const OSV_BATCH_SIZE = 1000;
const DETAIL_CONCURRENCY = 10;
/** How many times a bump target is re-checked against OSV before we stop chasing newer fixes. */
const BUMP_CHASE_ROUNDS = 3;
const DEP_SECTIONS = new Set(["dependencies", "devDependencies", "optionalDependencies"]);

interface Installed {
  /** Lock key, e.g. "node_modules/a" or "node_modules/a/node_modules/b". */
  key: string;
  name: string;
  version: string;
  /** Path segments below node_modules/, e.g. ["a", "b"] — the dependency chain for nested entries. */
  chain: string[];
  /** True when there was no lockfile and `version` is the lowest one the package.json range allows. */
  fromRange?: boolean;
  /** Only needed for development (lockfile dev: true): not shipped to production. */
  dev?: boolean;
}

interface VulnInfo {
  id: string;
  aliases: string[];
  summary?: string;
  severity?: string;
  /** Lowest published fixed version for this advisory; null when none is listed. */
  fixed: string | null;
  /** GitHub advisory severity (database_specific.severity), when OSV has it. */
  ghsa?: Severity;
}

interface AuditResult {
  inst: Installed;
  direct: boolean;
  vulns: VulnInfo[];
  /** Lowest version that fixes every advisory with a published fix; null when none has one. */
  bumpTo: string | null;
  /** CVE in CISA's Known Exploited Vulnerabilities catalog, with the date it was added. */
  kev?: { cve: string; added: string };
  /** Highest EPSS probability among its CVEs (0..1). */
  epss?: { cve: string; epss: number; percentile: number };
  /** Source files that import the package (or, for a transitive one, the direct dependency that brings it in). */
  importedBy: string[];
}

function asRecord(v: unknown): Record<string, unknown> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

function parseVer(v: string): number[] | null {
  const m = /^v?(\d+)\.(\d+)(?:\.(\d+))?/.exec(v.trim());
  return m ? [Number(m[1]), Number(m[2]), Number(m[3] ?? 0)] : null;
}

function cmpVer(a: string, b: string): number {
  const pa = parseVer(a);
  const pb = parseVer(b);
  if (!pa || !pb) return 0; // uncomparable: callers then leave the line alone
  for (let i = 0; i < 3; i++) if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1;
  return 0;
}

function nameFromKey(key: string): string | null {
  const idx = key.lastIndexOf("node_modules/");
  const name = key.slice(idx + "node_modules/".length);
  return name.length > 0 ? name : null;
}

/** LockfileVersion 2/3 `packages` map; "" (root), link entries and versionless entries are skipped. */
function installedPackages(lockContent: string): Installed[] {
  const graph = lockGraph(lockContent);
  if (graph) {
    return [...graph.nodes.values()].map((n) => ({ key: n.key, name: n.name, version: n.version, chain: n.chain, dev: n.dev }));
  }
  const root = asRecord(JSON.parse(lockContent));
  if (!root) throw new Error("package-lock.json is not a JSON object");
  const pkgs = asRecord(root.packages);
  if (!pkgs) return []; // lockfileVersion 1 has no `packages` map: nothing we can audit here
  const out: Installed[] = [];
  for (const [key, raw] of Object.entries(pkgs)) {
    if (key === "" || !key.startsWith("node_modules/")) continue;
    const entry = asRecord(raw);
    if (!entry || entry.link === true) continue;
    if (typeof entry.version !== "string") continue;
    const name = nameFromKey(key);
    if (!name) continue;
    out.push({ key, name, version: entry.version, chain: key.slice("node_modules/".length).split("/node_modules/") });
  }
  return out;
}

/**
 * Without a lockfile, the lowest version each direct dependency's range allows: "^4.17.20" -> 4.17.20.
 * Non-registry specs ("file:", git URLs, "*", "latest") are skipped.
 */
function rangeFloors(pkgContent: string): Installed[] {
  const pkg = asRecord(JSON.parse(pkgContent));
  if (!pkg) throw new Error("package.json is not a JSON object");
  const out: Installed[] = [];
  for (const section of ["dependencies", "devDependencies", "optionalDependencies"]) {
    const deps = asRecord(pkg[section]);
    if (!deps) continue;
    for (const [name, spec] of Object.entries(deps)) {
      const floor = typeof spec === "string" ? /^[\^~>=v\s]*(\d+\.\d+\.\d+)\s*$/.exec(spec)?.[1] : undefined;
      if (floor && !out.some((i) => i.name === name)) out.push({ key: `package.json:${name}`, name, version: floor, chain: [name], fromRange: true });
    }
  }
  return out;
}

function directDepNames(pkgContent: string): Set<string> {
  const pkg = asRecord(JSON.parse(pkgContent));
  if (!pkg) throw new Error("package.json is not a JSON object");
  const names = new Set<string>();
  for (const section of ["dependencies", "devDependencies", "optionalDependencies"]) {
    const deps = asRecord(pkg[section]);
    if (deps) for (const n of Object.keys(deps)) names.add(n);
  }
  return names;
}

function cvssOf(sev: unknown): string | undefined {
  if (!Array.isArray(sev)) return undefined;
  for (const raw of sev) {
    const s = asRecord(raw);
    if (s && typeof s.score === "string") return s.score;
    if (s && typeof s.type === "string") return s.type;
  }
  return undefined;
}

/**
 * The fix that applies to `installed`: the `fixed` event closing the range that contains it
 * (introduced <= installed < fixed). Without such a range, the lowest fixed version above `installed`.
 */
function fixedFor(detail: Record<string, unknown>, name: string, installed: string): string | null {
  let above: string | null = null;
  const affected = Array.isArray(detail.affected) ? detail.affected : [];
  for (const raw of affected) {
    const aff = asRecord(raw);
    if (!aff) continue;
    const pkg = asRecord(aff.package);
    if (pkg && typeof pkg.name === "string" && pkg.name !== name) continue;
    const ranges = Array.isArray(aff.ranges) ? aff.ranges : [];
    for (const rawR of ranges) {
      const range = asRecord(rawR);
      if (!range || !Array.isArray(range.events)) continue;
      let introduced: string | null = null; // null: not inside an affected range right now
      for (const rawE of range.events) {
        const ev = asRecord(rawE);
        if (!ev) continue;
        if (typeof ev.introduced === "string") introduced = ev.introduced;
        if (typeof ev.fixed !== "string") continue;
        const inRange = introduced !== null && (introduced === "0" || cmpVer(introduced, installed) <= 0);
        if (inRange && cmpVer(installed, ev.fixed) < 0) return ev.fixed;
        if (cmpVer(ev.fixed, installed) > 0 && (above === null || cmpVer(ev.fixed, above) < 0)) above = ev.fixed;
        introduced = null;
      }
    }
  }
  return above;
}

async function fetchVuln(fetchFn: typeof fetch, id: string): Promise<Record<string, unknown>> {
  let res: Response;
  try {
    res = await fetchFn(OSV_VULNS + encodeURIComponent(id), { signal: AbortSignal.timeout(OSV_TIMEOUT_MS) });
  } catch (err) {
    throw new Error(`OSV.dev unreachable while fetching ${id}: ${err instanceof Error ? err.message : String(err)}`);
  }
  if (!res.ok) throw new Error(`OSV.dev detail for ${id} failed with HTTP ${res.status}`);
  const rec = asRecord(await res.json());
  if (!rec) throw new Error(`OSV.dev returned a non-object detail for ${id}`);
  return rec;
}

/**
 * One OSV round: querybatch for every package (chunks of OSV_BATCH_SIZE), then each new advisory's
 * details into `details` (each id fetched once, a few at a time). Returns the advisory ids per package.
 */
async function osvLookup(
  fetchFn: typeof fetch,
  pkgs: { name: string; version: string }[],
  details: Map<string, Record<string, unknown>>,
): Promise<string[][]> {
  const results: unknown[] = [];
  for (let start = 0; start < pkgs.length; start += OSV_BATCH_SIZE) {
    const chunk = pkgs.slice(start, start + OSV_BATCH_SIZE);
    let res: Response;
    try {
      res = await fetchFn(OSV_BATCH, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        signal: AbortSignal.timeout(OSV_TIMEOUT_MS),
        body: JSON.stringify({
          queries: chunk.map((i) => ({ package: { name: i.name, ecosystem: "npm" }, version: i.version })),
        }),
      });
    } catch (err) {
      throw new Error(`OSV.dev unreachable: ${err instanceof Error ? err.message : String(err)}`);
    }
    if (!res.ok) throw new Error(`OSV.dev querybatch failed with HTTP ${res.status}`);
    const body = asRecord(await res.json());
    const part = body && Array.isArray(body.results) ? body.results : [];
    if (part.length !== chunk.length) throw new Error("OSV.dev querybatch returned a mismatched result count");
    results.push(...part);
  }

  const idsPer: string[][] = pkgs.map((_, i) => {
    const slot = asRecord(results[i]);
    const ids: string[] = [];
    for (const v of slot && Array.isArray(slot.vulns) ? slot.vulns : []) {
      const rec = asRecord(v);
      const id = typeof v === "string" ? v : rec && typeof rec.id === "string" ? rec.id : null;
      if (id && !ids.includes(id)) ids.push(id);
    }
    return ids;
  });

  const unique = [...new Set(idsPer.flat())].filter((id) => !details.has(id));
  let next = 0;
  const worker = async () => {
    while (next < unique.length) {
      const id = unique[next++];
      details.set(id, await fetchVuln(fetchFn, id));
    }
  };
  await Promise.all(Array.from({ length: Math.min(DETAIL_CONCURRENCY, unique.length) }, worker));
  return idsPer;
}

/**
 * Ask OSV for every installed package, then fetch each advisory's details.
 * Unreachable OSV throws: the check must show as errored, never as passed.
 * Without a lockfile it audits package.json range floors instead. Returns null (no network call)
 * when there is nothing versioned to audit.
 */
async function audit(ctx: CheckContext): Promise<AuditResult[] | null> {
  const lockFile = ctx.repo.files.find((f) => f.path === "package-lock.json");
  const pkgFile = ctx.repo.files.find((f) => f.path === "package.json");
  if (!lockFile && !pkgFile) return null;
  if (!pkgFile) throw new Error("package-lock.json found but package.json is missing; cannot classify direct dependencies");
  const installed = lockFile ? installedPackages(lockFile.content) : rangeFloors(pkgFile.content);
  if (installed.length === 0) return null;
  const direct = directDepNames(pkgFile.content);
  const fetchFn = ctx.fetch ?? fetch;

  const details = new Map<string, Record<string, unknown>>();
  const idsPer = await osvLookup(fetchFn, installed, details);

  const out: AuditResult[] = [];
  installed.forEach((inst, i) => {
    if (idsPer[i].length === 0) return;
    const vulns: VulnInfo[] = idsPer[i].map((id) => {
      const detail = details.get(id)!;
      return {
        id: typeof detail.id === "string" ? detail.id : id,
        aliases: Array.isArray(detail.aliases) ? detail.aliases.filter((a): a is string => typeof a === "string") : [],
        summary: typeof detail.summary === "string" ? detail.summary : undefined,
        severity: cvssOf(detail.severity),
        fixed: fixedFor(detail, inst.name, inst.version),
        ghsa: ghsaSeverity(detail),
      };
    });
    const isDirect = direct.has(inst.name);
    out.push({ inst, direct: isDirect, vulns, bumpTo: bumpTarget(vulns), importedBy: importersOf(ctx.repo.files, isDirect ? inst.name : inst.chain[0] ?? inst.name) });
  });

  // A fix version can sit inside a newer advisory's range (lodash 4.18.0 → fixed again in 4.18.1),
  // so ask OSV about each direct bump target and move past it, a few rounds at most.
  for (let round = 0; round < BUMP_CHASE_ROUNDS; round++) {
    const pending = out.filter((r) => r.direct && r.bumpTo !== null);
    if (pending.length === 0) break;
    const ids = await osvLookup(fetchFn, pending.map((r) => ({ name: r.inst.name, version: r.bumpTo! })), details);
    let moved = false;
    pending.forEach((r, i) => {
      const base = r.bumpTo!;
      for (const id of ids[i]) {
        const fix = fixedFor(details.get(id)!, r.inst.name, base);
        if (fix !== null && cmpVer(fix, r.bumpTo!) > 0) {
          r.bumpTo = fix;
          moved = true;
        }
      }
    });
    if (!moved) break;
  }

  // Exploit intelligence: is any CVE known to be exploited (CISA KEV), how likely is it (EPSS)?
  const cves = out.flatMap((r) => r.vulns.flatMap((v) => v.aliases.filter((a) => a.startsWith("CVE-"))));
  if (cves.length) {
    const intel = await exploitIntel(fetchFn, cves);
    for (const r of out) {
      for (const cve of r.vulns.flatMap((v) => v.aliases.filter((a) => a.startsWith("CVE-")))) {
        if (intel.kev.has(cve) && !r.kev) r.kev = { cve, added: intel.kev.get(cve)! };
        const e = intel.epss.get(cve);
        if (e && (!r.epss || e.epss > r.epss.epss)) r.epss = { cve, ...e };
      }
    }
  }
  return out.sort((a, b) => priority(b) - priority(a));
}

const SEV_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const RANK_SEV: Severity[] = ["info", "low", "medium", "high", "critical"];

function ghsaSeverity(detail: Record<string, unknown>): Severity | undefined {
  const ds = asRecord(detail.database_specific);
  const s = typeof ds?.severity === "string" ? ds.severity.toUpperCase() : "";
  return s === "CRITICAL" ? "critical" : s === "HIGH" ? "high" : s === "MODERATE" || s === "MEDIUM" ? "medium" : s === "LOW" ? "low" : undefined;
}

/**
 * Severity of the finding: the worst advisory (GitHub severity, else high), raised to critical when
 * the CVE is known to be exploited, lowered one step when the package is only used in development.
 */
function findingSeverity(r: AuditResult): Severity {
  let rank = Math.max(...r.vulns.map((v) => (v.ghsa ? SEV_RANK[v.ghsa] : SEV_RANK.high)));
  if (r.kev || (r.epss && r.epss.epss >= 0.5)) rank = SEV_RANK.critical;
  else if (r.inst.dev) rank = Math.max(SEV_RANK.low, rank - 1);
  return RANK_SEV[rank];
}

/** Ordering score: exploited first, then likely-exploited, severity, used in code, shipped. */
function priority(r: AuditResult): number {
  return (r.kev ? 1000 : 0) + Math.round((r.epss?.epss ?? 0) * 100) + SEV_RANK[findingSeverity(r)] * 20 + (r.importedBy.length ? 10 : 0) + (r.inst.dev ? 0 : 5);
}

function sameMajor(a: string, b: string): boolean {
  const pa = parseVer(a);
  const pb = parseVer(b);
  return !!pa && !!pb && pa[0] === pb[0] && (pa[0] !== 0 || pa[1] === pb[1]);
}

function priorityNote(r: AuditResult): string {
  const parts: string[] = [];
  if (r.kev) parts.push(`${r.kev.cve} is on CISA's Known Exploited Vulnerabilities list${r.kev.added ? ` (added ${r.kev.added})` : ""}: attackers are using it now, so fix this first.`);
  if (r.epss) parts.push(`EPSS gives ${r.epss.cve} a ${(r.epss.epss * 100).toFixed(1)}% chance of exploitation in the next 30 days (higher than ${Math.round(r.epss.percentile * 100)}% of all CVEs).`);
  if (r.inst.dev) parts.push("It is a development-only dependency, so it does not ship to production, but it runs on developer machines and in CI.");
  else if (r.importedBy.length) parts.push(`Your code loads ${r.direct ? "it" : r.inst.chain[0]} in ${r.importedBy.slice(0, 3).join(", ")}${r.importedBy.length > 3 ? ` and ${r.importedBy.length - 3} more` : ""}.`);
  else if (!r.inst.fromRange) parts.push(`No source file imports ${r.direct ? "it" : r.inst.chain[0]} directly; it may be used by a build tool or be unused.`);
  return parts.length ? parts.join(" ") + " " : "";
}

/**
 * The version to bump a direct dependency to. Each advisory contributes its own lowest fixed
 * version; the highest of those fixes every listed advisory at once (for the common single-advisory
 * case that is simply the lowest fixed version).
 */
function bumpTarget(vulns: VulnInfo[]): string | null {
  let best: string | null = null;
  for (const v of vulns) {
    if (v.fixed === null) continue;
    if (best === null || cmpVer(v.fixed, best) > 0) best = v.fixed;
  }
  return best;
}

function scopeLabel(r: AuditResult): string {
  if (r.direct) return "direct dependency";
  if (r.inst.chain.length > 1) return `transitive via ${r.inst.chain.join(" → ")}`;
  return "transitive (hoisted to the top level; the lockfile does not record its parent)";
}

function toFinding(r: AuditResult): Finding {
  const idList = r.vulns
    .map((v) => {
      const cve = v.aliases.find((a) => a.startsWith("CVE-"));
      return cve ? `${v.id} / ${cve}` : v.id;
    })
    .join(", ");
  const summary = r.vulns.find((v) => v.summary)?.summary;
  const severity = r.vulns.find((v) => v.severity)?.severity;
  const transitiveFix = !r.direct && r.bumpTo !== null
    ? (sameMajor(r.inst.version, r.bumpTo)
        ? `The fix adds an npm override that pins ${r.inst.name} to ^${r.bumpTo} everywhere in the tree. `
        : `${r.bumpTo} is a new major version of ${r.inst.name}, so upgrade ${r.inst.chain[0]} to a release that depends on it instead of forcing it. `)
    : "";
  const evidence =
    r.bumpTo !== null
      ? `${r.inst.name}@${r.inst.version} → fixed in ${r.bumpTo} (${idList}) — ${scopeLabel(r)}`
      : `${r.inst.name}@${r.inst.version} → no fixed version published yet (${idList}) — ${scopeLabel(r)}`;
  return {
    checkId: "dependency-audit",
    title: `${r.kev ? "Actively exploited dependency" : "Vulnerable dependency"}: ${r.inst.name}`,
    severity: findingSeverity(r),
    file: r.inst.fromRange ? "package.json" : "package-lock.json",
    evidence,
    explanation:
      `${summary ?? "A published security advisory affects this package"}${severity ? ` (${severity})` : ""}. ` +
      (r.direct
        ? "It is a direct dependency, so the fix is a version bump in package.json. "
        : "It is pulled in transitively; updating the parent package is the usual fix. ") +
      transitiveFix +
      priorityNote(r) +
      (r.inst.fromRange
        ? "No package-lock.json was found, so this checks the lowest version package.json allows; commit a lockfile so the exact installed versions can be audited. "
        : "") +
      "Removing the vulnerable version reduces the risk of exploitation; it does not guarantee the app is safe.",
  };
}

interface DepEntry {
  name: string;
  /** Offsets of the version string's text, between its quotes. */
  start: number;
  end: number;
  value: string;
}

/**
 * Every "name": "version" pair directly inside dependencies/devDependencies/optionalDependencies,
 * with the offsets of its value. Offsets, not lines, so one-line objects like
 * "dependencies": { "a": "1.0.0", "b": "2.0.0" } work too. Strings are tracked so braces in values do not count.
 */
function depEntries(content: string): DepEntry[] {
  const out: DepEntry[] = [];
  const stack: (string | null)[] = []; // per open bracket: the key it belongs to (objects at depth 1 only)
  let lastKey: string | null = null;
  let pendingKey: string | null = null; // a string in a dep section, waiting for its ':'
  let expectValue: string | null = null; // the key whose ':' was just seen
  for (let i = 0; i < content.length; i++) {
    const ch = content[i];
    if (ch === '"') {
      let j = i + 1;
      let str = "";
      let esc = false;
      for (; j < content.length; j++) {
        const c = content[j];
        if (esc) esc = false;
        else if (c === "\\") esc = true;
        else if (c === '"') break;
        str += c;
      }
      const inDeps = stack.length === 2 && stack[1] !== null && DEP_SECTIONS.has(stack[1]);
      if (inDeps && expectValue !== null) out.push({ name: expectValue, start: i + 1, end: j, value: str });
      else if (inDeps) pendingKey = str;
      if (stack.length === 1) lastKey = str;
      expectValue = null;
      i = j;
      continue;
    }
    if (ch === ":") {
      expectValue = pendingKey;
      pendingKey = null;
      continue;
    }
    if (ch === " " || ch === "\t" || ch === "\n" || ch === "\r") continue;
    pendingKey = null;
    expectValue = null;
    if (ch === "{" || ch === "[") stack.push(stack.length === 1 ? lastKey : null);
    else if (ch === "}" || ch === "]") stack.pop();
  }
  return out;
}

/**
 * Add entries to package.json's "overrides" with the fewest changed lines. A new "overrides" block goes
 * after the last top-level property, which gains a trailing comma (the one owner line that changes).
 * Inside an existing block, entries are inserted after its opening line. Names already overridden are left alone.
 */
function addOverrides(content: string, add: Map<string, string>): { text: string; removed?: string } | null {
  let pkg: Record<string, unknown>;
  try {
    pkg = JSON.parse(content) as Record<string, unknown>;
  } catch {
    return null;
  }
  const existing = asRecord(pkg.overrides);
  const todo = [...add].filter(([n]) => !(existing && n in existing));
  if (todo.length === 0) return null;
  const nl = content.includes("\r\n") ? "\r\n" : "\n";
  const lines = content.split(/\r?\n/);
  const indent = /^(\s+)"/.exec(lines.find((l) => /^\s+"/.test(l)) ?? "")?.[1] ?? "  ";
  const entry = (n: string, v: string, comma: boolean) => `${indent}${indent}${JSON.stringify(n)}: ${JSON.stringify("^" + v)}${comma ? "," : ""}`;

  if (existing) {
    const at = lines.findIndex((l) => /^\s*"overrides"\s*:\s*\{\s*$/.test(l));
    if (at < 0) return null; // one-line or unusual formatting: leave it to the owner
    const nonEmpty = Object.keys(existing).length > 0;
    const block = todo.map(([n, v], i) => entry(n, v, nonEmpty || i < todo.length - 1));
    lines.splice(at + 1, 0, ...block);
    return { text: lines.join(nl) };
  }
  // The root object's closing brace and the last line with content before it.
  let close = lines.length - 1;
  while (close >= 0 && lines[close].trim() === "") close--;
  if (close < 0 || lines[close].trim() !== "}") return null;
  let last = close - 1;
  while (last >= 0 && lines[last].trim() === "") last--;
  if (last < 0) return null;
  const removed = lines[last].trim();
  const needsComma = !/[,{]\s*$/.test(lines[last]);
  if (needsComma) lines[last] = lines[last].replace(/\s*$/, ",");
  const block = [`${indent}"overrides": {`, ...todo.map(([n, v], i) => entry(n, v, i < todo.length - 1)), `${indent}}`];
  lines.splice(last + 1, 0, ...block);
  return { text: lines.join(nl), removed: needsComma ? removed : undefined };
}

/** The trimmed text of the line holding offset `at` (trim also drops a CRLF's \r). */
function lineAround(content: string, at: number): string {
  const from = content.lastIndexOf("\n", at - 1) + 1;
  const to = content.indexOf("\n", at);
  return content.slice(from, to === -1 ? content.length : to).trim();
}

export const dependencyAudit: Check = {
  id: "dependency-audit",
  group: "C-security",
  title: "Dependency vulnerability audit",
  severity: "high",
  mode: "auto",

  async detect(ctx): Promise<Finding[]> {
    const results = await audit(ctx);
    return results === null ? [] : results.map(toFinding);
  },

  async fix(ctx): Promise<Patch | null> {
    // Recompute everything from ctx.repo: which packages are vulnerable and which lines exist now.
    const results = await audit(ctx);
    if (!results) return null;
    const pkgFile = ctx.repo.files.find((f) => f.path === "package.json");
    if (!pkgFile) return null;

    const content = pkgFile.content;
    const entries = depEntries(content); // peerDependencies, scripts, overrides …: not versions we own
    const edits: { start: number; end: number; text: string }[] = [];
    const bumps: string[] = [];
    const seen = new Set<string>();
    for (const r of results) {
      if (!r.direct || !r.bumpTo || seen.has(r.inst.name)) continue; // transitive deps are not ours to bump
      const e = entries.find((x) => x.name === r.inst.name);
      if (!e) continue;
      seen.add(r.inst.name);
      const current = /^[\^~>=v\s]*(\d+\.\d+\.\d+)/.exec(e.value)?.[1]; // "^4.17.20" -> 4.17.20
      if (!current || cmpVer(current, r.bumpTo) >= 0) continue; // already patched (or uncomparable): leave it alone
      edits.push({ start: e.start, end: e.end, text: `^${r.bumpTo}` });
      bumps.push(`${r.inst.name} → ^${r.bumpTo}`);
    }
    // One allowed removal per changed line: two bumps on a one-line object still remove that line once.
    const removals = [...new Set(edits.map((e) => lineAround(content, e.start)))];
    let after = content;
    for (const e of [...edits].sort((a, b) => b.start - a.start)) after = after.slice(0, e.start) + e.text + after.slice(e.end);

    // Transitive packages: an npm override, only within the same major version so the parent keeps working.
    const overrides = new Map<string, string>();
    for (const r of results) {
      if (r.direct || !r.bumpTo || r.inst.fromRange || !sameMajor(r.inst.version, r.bumpTo)) continue;
      const prev = overrides.get(r.inst.name);
      if (!prev || cmpVer(r.bumpTo, prev) > 0) overrides.set(r.inst.name, r.bumpTo);
    }
    const added = overrides.size ? addOverrides(after, overrides) : null;
    if (added) {
      after = added.text;
      if (added.removed) removals.push(added.removed);
    }
    if (after === content) return null;
    const pinned = [...overrides].map(([n, v]) => `${n} → ^${v}`);
    const parts = [
      bumps.length ? `bump ${bumps.length} direct dependenc${bumps.length === 1 ? "y" : "ies"}` : "",
      added ? `pin ${overrides.size} transitive dependenc${overrides.size === 1 ? "y" : "ies"}` : "",
    ].filter(Boolean);

    return {
      id: "dependency-audit-1",
      checkId: "dependency-audit",
      title: `${parts.join(" and ").replace(/^./, (c) => c.toUpperCase())} to patched versions`,
      class: "minimal-edit",
      reason:
        (bumps.length ? `Declared ranges currently admit known-vulnerable versions (${bumps.join(", ")}). ` : "") +
        (added ? `npm overrides force patched versions of packages your dependencies pull in (${pinned.join(", ")}), staying within each package's major version. ` : "") +
        "The change is verified only after npm install + tests pass (CI or the isolated verify build), because the lockfile only refreshes then; " +
        "risk reduced once a patched version is actually installed.",
      edits: [{ kind: "modify", path: "package.json", before: content, after }],
      allowedRemovals: removals, // the original text of each changed line
    };
  },
};
