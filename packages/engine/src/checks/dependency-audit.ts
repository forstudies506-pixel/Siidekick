import type { Check, CheckContext, Finding, Patch } from "../types.js";

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
}

interface VulnInfo {
  id: string;
  aliases: string[];
  summary?: string;
  severity?: string;
  /** Lowest published fixed version for this advisory; null when none is listed. */
  fixed: string | null;
}

interface AuditResult {
  inst: Installed;
  direct: boolean;
  vulns: VulnInfo[];
  /** Lowest version that fixes every advisory with a published fix; null when none has one. */
  bumpTo: string | null;
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

/**
 * Node's resolution over the lockfile's flat `packages` map: from the package at `fromKey`, which
 * entry does `require(name)` load? Nearest node_modules/<name> walking up, then the top level.
 */
function resolveKey(pkgs: Record<string, unknown>, fromKey: string, name: string): string | null {
  let base = fromKey;
  for (;;) {
    const candidate = base === "" ? `node_modules/${name}` : `${base}/node_modules/${name}`;
    if (candidate in pkgs) return candidate;
    if (base === "") return null;
    const idx = base.lastIndexOf("/node_modules/");
    base = idx === -1 ? "" : base.slice(0, idx);
  }
}

/**
 * Shortest dependency path from the app to every lock entry, as package names: a breadth-first walk of
 * each entry's declared dependencies. Hoisting flattens node_modules, so the folder path alone cannot say
 * who pulled a package in; the `dependencies` fields can.
 */
export function dependencyChains(pkgs: Record<string, unknown>): Map<string, string[]> {
  const chains = new Map<string, string[]>();
  const depNames = (key: string): string[] => {
    const e = asRecord(pkgs[key]);
    if (!e) return [];
    const names: string[] = [];
    for (const section of ["dependencies", "optionalDependencies", ...(key === "" ? ["devDependencies"] : [])]) {
      const d = asRecord(e[section]);
      if (d) names.push(...Object.keys(d));
    }
    return names;
  };
  const queue: Array<{ key: string; chain: string[] }> = [{ key: "", chain: [] }];
  const seen = new Set<string>([""]);
  while (queue.length > 0) {
    const { key, chain } = queue.shift()!;
    for (const name of depNames(key)) {
      let target = resolveKey(pkgs, key, name);
      if (!target) continue;
      const linked = asRecord(pkgs[target]);
      if (linked?.link === true && typeof linked.resolved === "string") target = linked.resolved;
      if (seen.has(target)) continue;
      seen.add(target);
      const next = [...chain, name];
      chains.set(target, next);
      queue.push({ key: target, chain: next });
    }
  }
  return chains;
}

/** LockfileVersion 2/3 `packages` map; "" (root), link entries and versionless entries are skipped. */
function installedPackages(lockContent: string): Installed[] {
  const root = asRecord(JSON.parse(lockContent));
  if (!root) throw new Error("package-lock.json is not a JSON object");
  const pkgs = asRecord(root.packages);
  if (!pkgs) return []; // lockfileVersion 1 has no `packages` map: nothing we can audit here
  const chains = dependencyChains(pkgs);
  const out: Installed[] = [];
  for (const [key, raw] of Object.entries(pkgs)) {
    if (key === "" || !key.startsWith("node_modules/")) continue;
    const entry = asRecord(raw);
    if (!entry || entry.link === true) continue;
    if (typeof entry.version !== "string") continue;
    const name = nameFromKey(key);
    if (!name) continue;
    const folderChain = key.slice("node_modules/".length).split("/node_modules/");
    out.push({ key, name, version: entry.version, chain: chains.get(key) ?? folderChain });
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
      };
    });
    out.push({ inst, direct: direct.has(inst.name), vulns, bumpTo: bumpTarget(vulns) });
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
  return out;
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
  if (r.direct && r.inst.chain.length <= 1) return "direct dependency";
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
  const evidence =
    r.bumpTo !== null
      ? `${r.inst.name}@${r.inst.version} → fixed in ${r.bumpTo} (${idList}) — ${scopeLabel(r)}`
      : `${r.inst.name}@${r.inst.version} → no fixed version published yet (${idList}) — ${scopeLabel(r)}`;
  return {
    checkId: "dependency-audit",
    title: `Vulnerable dependency: ${r.inst.name}`,
    severity: "high",
    file: r.inst.fromRange ? "package.json" : "package-lock.json",
    evidence,
    chain: r.inst.chain,
    advisories: r.vulns.map((v) => ({ id: v.id, aliases: v.aliases, summary: v.summary, severity: v.severity, fixed: v.fixed })),
    explanation:
      `${summary ?? "A published security advisory affects this package"}${severity ? ` (${severity})` : ""}. ` +
      (r.direct
        ? "It is a direct dependency, so the fix is a version bump in package.json. "
        : `It is pulled in transitively${r.inst.chain.length > 1 ? ` by ${r.inst.chain[0]}` : ""}; updating ${r.inst.chain.length > 1 ? r.inst.chain[0] : "the parent package"} (the direct dependency that brings it in) is the usual fix. `) +
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
    if (edits.length === 0) return null;
    // One allowed removal per changed line: two bumps on a one-line object still remove that line once.
    const removals = [...new Set(edits.map((e) => lineAround(content, e.start)))];
    let after = content;
    for (const e of [...edits].sort((a, b) => b.start - a.start)) after = after.slice(0, e.start) + e.text + after.slice(e.end);
    if (after === content) return null;

    return {
      id: "dependency-audit-1",
      checkId: "dependency-audit",
      title: `Bump ${edits.length} vulnerable direct dependenc${edits.length === 1 ? "y" : "ies"} to patched versions`,
      class: "minimal-edit",
      reason:
        `Declared ranges currently admit known-vulnerable versions (${bumps.join(", ")}). ` +
        "The bump is verified only after npm install + tests pass in CI, because the lockfile only refreshes then; " +
        "risk reduced once a patched version is actually installed.",
      edits: [{ kind: "modify", path: "package.json", before: content, after }],
      allowedRemovals: removals, // the original text of each changed line
    };
  },
};
