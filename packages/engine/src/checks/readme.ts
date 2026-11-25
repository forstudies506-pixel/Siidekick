import type { Check, FileEdit, Finding, Patch } from "../types.js";

const MIN_README_CHARS = 200;
const README_PATH = "README.md";
const PKG_PATH = "package.json";
const ENV_EXAMPLE_PATH = ".env.example";

const ENV_LINE = /^([A-Za-z_][A-Za-z0-9_]*)\s*=/gm;

function pkgOf(files: { path: string; content: string }[]): Record<string, unknown> {
  const f = files.find((x) => x.path === PKG_PATH);
  if (!f) return {};
  try { return JSON.parse(f.content); } catch { return {}; }
}

function envNames(files: { path: string; content: string }[]): string[] {
  const f = files.find((x) => x.path === ENV_EXAMPLE_PATH);
  if (!f) return [];
  const names: string[] = [];
  for (const m of f.content.matchAll(ENV_LINE)) names.push(m[1]);
  return names;
}

function readmeBody(pkg: Record<string, unknown>, env: string[]): string {
  const name = typeof pkg.name === "string" ? pkg.name : "app";
  const description = typeof pkg.description === "string" ? pkg.description : "";
  const scripts = pkg.scripts && typeof pkg.scripts === "object" ? pkg.scripts as Record<string, string> : {};
  const scriptLines = Object.entries(scripts).map(([k, v]) => `- \`npm run ${k}\`: ${v}`).join("\n") || "none";
  const envBlock = env.length ? "\n## Environment\n\n" + env.map((n) => `${n}=`).join("\n") + "\n" : "";
  return `# ${name}\n\n${description}\n\n## Scripts\n\n${scriptLines}\n${envBlock}\n## Run\n\nnpm install\nnpm run start\n`;
}

export const readme: Check = {
  id: "readme",
  group: "A-delivery",
  title: "README present",
  severity: "low",
  mode: "auto",

  detect({ repo }): Finding[] {
    const readme = repo.files.find((f) => f.path === README_PATH);
    if (!readme || readme.content.length < MIN_README_CHARS) {
      return [{
        checkId: "readme",
        title: "README.md missing or too short",
        severity: "low",
        file: README_PATH,
        explanation: "A README tells operators what the app does, how to run it, and which environment variables it needs.",
      }];
    }
    return [];
  },

  fix({ repo }): Patch | null {
    const readme = repo.files.find((f) => f.path === README_PATH);
    if (readme && readme.content.length >= MIN_README_CHARS) return null;
    const pkg = pkgOf(repo.files);
    const env = envNames(repo.files);
    return {
      id: "readme-1",
      checkId: "readme",
      title: "Add README.md",
      class: "additive",
      reason: "Every repo needs a README describing purpose, setup, and required env vars.",
      edits: [{ kind: "create", path: README_PATH, content: readmeBody(pkg, env) }],
    };
  },
};
