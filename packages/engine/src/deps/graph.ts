import type { RepoFile, RepoSnapshot } from "../types.js";

/**
 * The installed dependency tree from package-lock.json (lockfile v2/v3), resolved the way Node does:
 * a package's dependency is looked up in its own node_modules first, then in each parent folder's.
 * This gives every installed package the chain that brought it in, even when npm hoisted it to the
 * top level, and the data for a CycloneDX SBOM.
 */

export interface LockNode {
  /** Lock key, e.g. "node_modules/body-parser/node_modules/qs". */
  key: string;
  name: string;
  version: string;
  /** Only needed by devDependencies: not shipped to production. */
  dev: boolean;
  optional: boolean;
  /** Names on the shortest path from the project, ending in this package: ["express", "body-parser", "qs"]. */
  chain: string[];
  /** Keys of the packages this one depends on. */
  requires: string[];
  integrity?: string;
  resolved?: string;
  license?: string;
  hasInstallScript: boolean;
}

export interface LockGraph {
  root: { name: string; version: string; requires: string[] };
  nodes: Map<string, LockNode>;
}

function rec(v: unknown): Record<string, unknown> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

function nameOf(key: string): string {
  return key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length);
}

/** Where Node finds `dep` when required from the package at `fromKey` ("" for the project). */
export function resolveKey(pkgs: Record<string, unknown>, fromKey: string, dep: string): string | null {
  let base = fromKey;
  for (;;) {
    const k = (base ? base + "/" : "") + "node_modules/" + dep;
    if (k in pkgs) return k;
    if (!base) return null;
    const i = base.lastIndexOf("/node_modules/");
    base = i >= 0 ? base.slice(0, i) : "";
  }
}

export function lockGraph(lockContent: string): LockGraph | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(lockContent);
  } catch {
    return null;
  }
  const lock = rec(parsed);
  const pkgs = rec(lock?.packages);
  if (!lock || !pkgs) return null; // lockfile v1 has no packages map
  const rootEntry = rec(pkgs[""]) ?? {};
  const depNames = (e: Record<string, unknown>, isRoot: boolean) =>
    [...new Set([
      ...Object.keys(rec(e.dependencies) ?? {}),
      ...Object.keys(rec(e.optionalDependencies) ?? {}),
      ...Object.keys(rec(e.peerDependencies) ?? {}),
      ...(isRoot ? Object.keys(rec(e.devDependencies) ?? {}) : []),
    ])];

  const nodes = new Map<string, LockNode>();
  for (const [key, raw] of Object.entries(pkgs)) {
    const e = rec(raw);
    if (!key || !key.startsWith("node_modules/") || !e || e.link === true || typeof e.version !== "string") continue;
    nodes.set(key, {
      key,
      name: nameOf(key),
      version: e.version,
      dev: e.dev === true,
      optional: e.optional === true,
      chain: [],
      requires: depNames(e, false).map((d) => resolveKey(pkgs, key, d)).filter((k): k is string => k !== null && k !== key),
      integrity: typeof e.integrity === "string" ? e.integrity : undefined,
      resolved: typeof e.resolved === "string" ? e.resolved : undefined,
      license: typeof e.license === "string" ? e.license : undefined,
      hasInstallScript: e.hasInstallScript === true,
    });
  }
  const rootRequires = depNames(rootEntry, true).map((d) => resolveKey(pkgs, "", d)).filter((k): k is string => k !== null);

  // Shortest chain from the project to each package (breadth-first).
  const queue: string[] = [];
  for (const k of rootRequires) {
    const n = nodes.get(k);
    if (n && n.chain.length === 0) {
      n.chain = [n.name];
      queue.push(k);
    }
  }
  while (queue.length) {
    const cur = nodes.get(queue.shift()!)!;
    for (const k of cur.requires) {
      const n = nodes.get(k);
      if (n && n.chain.length === 0) {
        n.chain = [...cur.chain, n.name];
        queue.push(k);
      }
    }
  }
  // Unreachable entries (extraneous) keep their folder nesting as the best guess.
  for (const n of nodes.values()) if (n.chain.length === 0) n.chain = n.key.slice("node_modules/".length).split("/node_modules/");

  return {
    root: { name: typeof lock.name === "string" ? lock.name : "project", version: typeof lock.version === "string" ? lock.version : "0.0.0", requires: rootRequires },
    nodes,
  };
}

/** Source files that import `pkg` (require, import, dynamic import, subpath imports). */
export function importersOf(files: RepoFile[], pkg: string): string[] {
  const esc = pkg.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp(`(?:require\\s*\\(\\s*|from\\s+|import\\s*\\(\\s*|import\\s+)["'\`]${esc}(?:/[^"'\`]*)?["'\`]`);
  return files
    .filter((f) => /\.(c|m)?(j|t)sx?$/.test(f.path) && !/(^|\/)(node_modules|dist|build|coverage)\//.test(f.path) && re.test(f.content))
    .map((f) => f.path);
}

// ---------------------------------------------------------------------------------------------
// CycloneDX 1.5 SBOM

function purl(name: string, version: string): string {
  const [scope, bare] = name.startsWith("@") ? name.split("/") : [null, name];
  return `pkg:npm/${scope ? encodeURIComponent(scope) + "/" : ""}${encodeURIComponent(bare)}@${encodeURIComponent(version)}`;
}

/** sha512-<base64> integrity → CycloneDX hash entry. */
function hashOf(integrity: string | undefined): { alg: string; content: string }[] {
  const m = /^(sha512|sha384|sha256|sha1)-(.+)$/.exec(integrity ?? "");
  if (!m) return [];
  const alg = { sha512: "SHA-512", sha384: "SHA-384", sha256: "SHA-256", sha1: "SHA-1" }[m[1] as "sha512"];
  return [{ alg, content: Buffer.from(m[2], "base64").toString("hex") }];
}

/** A CycloneDX 1.5 JSON SBOM for the repo's npm lockfile, or null without one. */
export function cycloneDx(repo: RepoSnapshot, now = new Date()): Record<string, unknown> | null {
  const lockFile = repo.files.find((f) => f.path === "package-lock.json");
  const graph = lockFile ? lockGraph(lockFile.content) : null;
  if (!graph) return null;
  const ref = (n: LockNode) => purl(n.name, n.version);
  const rootRef = purl(graph.root.name, graph.root.version);
  const components = [...graph.nodes.values()].map((n) => ({
    type: "library",
    "bom-ref": ref(n),
    name: n.name,
    version: n.version,
    purl: ref(n),
    scope: n.dev ? "excluded" : n.optional ? "optional" : "required",
    ...(n.license ? { licenses: [{ license: { id: n.license } }] } : {}),
    ...(hashOf(n.integrity).length ? { hashes: hashOf(n.integrity) } : {}),
    ...(n.resolved ? { externalReferences: [{ type: "distribution", url: n.resolved }] } : {}),
  }));
  const seen = new Set<string>();
  const unique = components.filter((c) => (seen.has(c["bom-ref"]) ? false : (seen.add(c["bom-ref"]), true)));
  const byKey = graph.nodes;
  const deps = new Map<string, Set<string>>();
  deps.set(rootRef, new Set(graph.root.requires.map((k) => ref(byKey.get(k)!)).filter(Boolean)));
  for (const n of byKey.values()) {
    const set = deps.get(ref(n)) ?? new Set<string>();
    for (const k of n.requires) if (byKey.has(k)) set.add(ref(byKey.get(k)!));
    deps.set(ref(n), set);
  }
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: now.toISOString(),
      tools: { components: [{ type: "application", name: "Siidekick", version: "0.2.0" }] },
      component: { type: "application", "bom-ref": rootRef, name: graph.root.name, version: graph.root.version, purl: rootRef },
    },
    components: unique,
    dependencies: [...deps.entries()].map(([r, d]) => ({ ref: r, dependsOn: [...d].sort() })),
  };
}
