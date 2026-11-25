import type { Check, FileEdit, Finding, Patch } from "../types.js";

const WORKFLOW_DIR = ".github/workflows/";
const WORKFLOW_PATH = ".github/workflows/siidekick.yml";

const YML = `name: Siidekick

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 20
      - run: npm ci
      - run: npm test --if-present
      - run: npm audit --audit-level=high || true
`;

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
      reason: "Runs install, tests, and high-level audit on every push and pull request.",
      edits: [{ kind: "create", path: WORKFLOW_PATH, content: YML }],
    };
  },
};
