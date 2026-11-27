import type { Check, Finding, RepoFile } from "../types.js";
import { lineAt } from "../util.js";

/**
 * How dependencies get into the build, beyond known CVEs (dependency-audit) and made-up names
 * (hallucinated-package): unpinned or plain-HTTP sources, missing integrity hashes, install-time
 * scripts and missing lockfiles.
 */

const MANIFEST = /(^|\/)package\.json$/;
const SKIP = /(^|\/)node_modules\//;
const REGISTRY_HOSTS = /^https:\/\/(registry\.npmjs\.org|registry\.yarnpkg\.com|npm\.pkg\.github\.com|registry\.npmmirror\.com)\//;
const LIFECYCLE = ["preinstall", "install", "postinstall", "prepare"];

function json(content: string): Record<string, unknown> | null {
  try {
    const v = JSON.parse(content);
    return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function at(file: RepoFile, needle: string): number {
  const i = file.content.indexOf(needle);
  return i >= 0 ? lineAt(file.content, i) : 1;
}

function supplyFindings(files: RepoFile[]): Finding[] {
  const out: Finding[] = [];
  const id = "supply-chain";
  const privateRegistry = files.some((f) => /(^|\/)\.npmrc$/.test(f.path) && /registry\s*=/.test(f.content));

  for (const file of files) {
    if (SKIP.test(file.path)) continue;

    if (MANIFEST.test(file.path)) {
      const pkg = json(file.content);
      if (!pkg) continue;
      const dir = file.path.slice(0, file.path.length - "package.json".length);
      let depCount = 0;
      for (const section of ["dependencies", "devDependencies", "optionalDependencies"]) {
        const deps = pkg[section] as Record<string, unknown> | undefined;
        for (const [name, specRaw] of Object.entries(deps ?? {})) {
          depCount++;
          const spec = String(specRaw);
          if (/^(git\+)?http:\/\//.test(spec)) {
            out.push({ checkId: id, title: `Dependency downloaded over plain HTTP: ${name}`, severity: "high", file: file.path, line: at(file, `"${name}"`), evidence: `${name}: ${spec}`, explanation: "Anyone on the network path can swap the package for their own code during install.", remedy: "Use the npm registry or an https:// URL with an integrity hash." });
          } else if (/^(git(\+ssh|\+https)?:|github:|gitlab:|bitbucket:|[\w.-]+\/[\w.-]+(#.*)?$)/.test(spec) && !/#[0-9a-f]{40}$/.test(spec)) {
            out.push({ checkId: id, title: `Git dependency not pinned to a commit: ${name}`, severity: "medium", file: file.path, line: at(file, `"${name}"`), evidence: `${name}: ${spec}`, explanation: "A branch or tag can be moved, so the next install can pull different code than the one you reviewed.", remedy: `Pin the full commit: "${name}": "${spec.split("#")[0]}#<40-character sha>", or publish it to a registry.` });
          } else if (spec === "*" || spec === "latest" || spec === "") {
            out.push({ checkId: id, title: `Dependency accepts any version: ${name}`, severity: "medium", file: file.path, line: at(file, `"${name}"`), evidence: `${name}: "${spec}"`, explanation: "Any future release, including a hijacked one, is installed without review.", remedy: "Use a caret range on a known version, e.g. ^1.4.2, and commit the lockfile." });
          }
        }
      }
      const scripts = (pkg.scripts ?? {}) as Record<string, unknown>;
      for (const hook of LIFECYCLE) {
        const s = typeof scripts[hook] === "string" ? (scripts[hook] as string) : "";
        if (/(curl|wget|Invoke-WebRequest|iwr)\b[^|]*\|\s*(ba)?sh|node\s+-e|eval\s*\(|base64\s+-d/.test(s)) {
          out.push({ checkId: id, title: `Install script downloads or runs code (${hook})`, severity: "high", file: file.path, line: at(file, `"${hook}"`), evidence: `${hook}: ${s.slice(0, 100)}`, explanation: "This runs on every developer's machine and every CI build during npm install.", remedy: "Move the step into an explicit build script and verify anything it downloads." });
        }
      }
      const hasLock = ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock"].some((l) => files.some((f) => f.path === dir + l));
      const isWorkspaceChild = dir !== "" && files.some((f) => f.path === "package-lock.json" || f.path === "pnpm-lock.yaml" || f.path === "yarn.lock");
      if (depCount > 0 && !hasLock && !isWorkspaceChild) {
        out.push({ checkId: id, title: "No lockfile committed", severity: "medium", file: file.path, line: 1, explanation: "Without a lockfile every install resolves versions again, so builds differ and a malicious new release of any dependency gets in automatically.", remedy: "Run npm install once and commit package-lock.json; install with npm ci in CI." });
      }
    }

    if (/(^|\/)(package-lock|npm-shrinkwrap)\.json$/.test(file.path)) {
      const lock = json(file.content);
      const pkgs = (lock?.packages ?? {}) as Record<string, Record<string, unknown>>;
      const scripts: string[] = [];
      const noIntegrity: string[] = [];
      for (const [key, entry] of Object.entries(pkgs)) {
        if (!key || entry.link === true) continue;
        const name = key.slice(key.lastIndexOf("node_modules/") + "node_modules/".length);
        const resolved = typeof entry.resolved === "string" ? entry.resolved : "";
        if (entry.hasInstallScript === true) scripts.push(name);
        if (resolved.startsWith("http://")) {
          out.push({ checkId: id, title: `Package resolved over plain HTTP: ${name}`, severity: "high", file: file.path, line: at(file, resolved), evidence: resolved, explanation: "The lockfile tells npm to download this package without TLS.", remedy: "Reinstall from an https registry and commit the new lockfile." });
        } else if (resolved && !REGISTRY_HOSTS.test(resolved) && /^https:/.test(resolved) && !privateRegistry) {
          out.push({ checkId: id, title: `Package resolved from an unexpected host: ${name}`, severity: "medium", file: file.path, line: at(file, resolved), evidence: resolved.slice(0, 120), explanation: "A lockfile entry pointing outside the npm registry can be a sign of a tampered lockfile or dependency confusion.", remedy: "Check who added this entry; reinstall the package from the registry." });
        }
        if (resolved && /^https:/.test(resolved) && !entry.integrity) noIntegrity.push(name);
      }
      if (noIntegrity.length) {
        out.push({ checkId: id, title: `${noIntegrity.length} lockfile entr${noIntegrity.length === 1 ? "y has" : "ies have"} no integrity hash`, severity: "medium", file: file.path, line: 1, evidence: noIntegrity.slice(0, 8).join(", "), explanation: "Without an integrity hash npm cannot detect a package that changed after you locked it.", remedy: "Delete node_modules and run npm install to regenerate the hashes." });
      }
      if (scripts.length) {
        out.push({ checkId: id, title: `${scripts.length} installed package${scripts.length === 1 ? " runs" : "s run"} code at install time`, severity: "low", file: file.path, line: 1, evidence: scripts.slice(0, 12).join(", ") + (scripts.length > 12 ? " …" : ""), explanation: "Install scripts run with your user's rights on every install. Most are legitimate (native builds), but this is how most npm malware runs.", remedy: "Install with npm ci --ignore-scripts in CI and allow only the packages that need scripts (npm approve-scripts on npm 11+)." });
      }
    }

    if (/(^|\/)requirements[\w.-]*\.txt$/.test(file.path)) {
      file.content.split("\n").forEach((raw, i) => {
        const l = raw.replace(/#.*/, "").trim();
        if (/^--extra-index-url\b/.test(l)) {
          out.push({ checkId: id, title: "Extra package index (dependency confusion risk)", severity: "medium", file: file.path, line: i + 1, evidence: l.replace(/\/\/[^@/]+@/, "//***@"), explanation: "pip picks the highest version across all indexes, so a public package with your private package's name wins.", remedy: "Use --index-url for a single index that proxies PyPI, and pin hashes with --require-hashes." });
        } else if (l && !l.startsWith("-") && /^[A-Za-z0-9][\w.-]*(\[[^\]]*\])?\s*$/.test(l)) {
          out.push({ checkId: id, title: `Python dependency not pinned: ${l}`, severity: "low", file: file.path, line: i + 1, evidence: l, explanation: "Each install can pull a newer release, including a compromised one.", remedy: `Pin it: ${l}==<version> (pip-compile can generate the pins with hashes).` });
        }
      });
    }
  }
  return out;
}

export const supplyChain: Check = {
  id: "supply-chain",
  group: "C-security",
  title: "Dependency supply chain",
  severity: "medium",
  mode: "report",
  skip: ({ repo }) => (repo.files.some((f) => !SKIP.test(f.path) && (MANIFEST.test(f.path) || /requirements[\w.-]*\.txt$/.test(f.path))) ? null : "no package.json or requirements.txt"),
  detect: ({ repo }) => supplyFindings(repo.files),
};
