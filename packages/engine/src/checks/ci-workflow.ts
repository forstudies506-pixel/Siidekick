import type { Check, Finding, Patch } from "../types.js";

const WORKFLOW_DIR = ".github/workflows/";
const WORKFLOW_PATH = ".github/workflows/siidekick.yml";

/** Node for CI: the project's own pin (.nvmrc / .node-version, then engines.node), else 22, the version Siidekick verifies on. */
function nodeSetup(files: { path: string; content: string }[]): string {
  for (const name of [".nvmrc", ".node-version"]) {
    if (files.some((f) => f.path === name)) return `node-version-file: ${name}`;
  }
  const pkg = files.find((f) => f.path === "package.json");
  if (pkg) {
    try {
      const engines = (JSON.parse(pkg.content) as { engines?: { node?: unknown } }).engines;
      const want = typeof engines?.node === "string" ? engines.node.trim() : "";
      // setup-node takes a semver range; keep it only when it is plain enough to quote safely.
      if (want && /^[\w.^~<>=*| -]+$/.test(want)) return `node-version: "${want}"`;
    } catch {
      // unreadable package.json: fall through to the default
    }
  }
  return "node-version: 22";
}

/** The workflow, built for this repo. Passes Siidekick's own ci-security check: read-only token, first-party actions. */
function workflowYml(files: { path: string; content: string }[]): string {
  const hasLock = files.some((f) => f.path === "package-lock.json" || f.path === "npm-shrinkwrap.json");
  return `name: Siidekick

on:
  push:
    branches: [main]
  pull_request:

# Least privilege: the token can read the repo and nothing else.
permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-node@v5
        with:
          ${nodeSetup(files)}
      - run: ${hasLock ? "npm ci --ignore-scripts" : "npm install --ignore-scripts"}
      - run: npm test --if-present
      - run: npm audit --audit-level=high || true
`;
}

function hasWorkflow(files: { path: string; content: string }[]): boolean {
  return files.some((f) => f.path.startsWith(WORKFLOW_DIR) && f.path.endsWith(".yml"));
}

export const ciWorkflow: Check = {
  id: "ci-workflow",
  group: "A-delivery",
  title: "CI workflow",
  severity: "medium",
  mode: "auto",

  detect({ repo }): Finding[] {
    if (hasWorkflow(repo.files)) return [];
    return [{
      checkId: "ci-workflow",
      title: "No GitHub Actions workflow",
      severity: "medium",
      file: WORKFLOW_PATH,
      explanation: "No CI workflow means tests and audits do not run on push or pull requests.",
    }];
  },

  fix({ repo }): Patch | null {
    if (hasWorkflow(repo.files)) return null;
    return {
      id: "ci-workflow-1",
      checkId: "ci-workflow",
      title: "Add siidekick CI workflow",
      class: "additive",
      reason: "Runs install, tests, and a high-severity audit on every push and pull request, on the Node version the project asks for, with a read-only token.",
      edits: [{ kind: "create", path: WORKFLOW_PATH, content: workflowYml(repo.files) }],
    };
  },
};
