# Rules every worker follows

- Repo: npm-workspaces monorepo, Node 20+, TypeScript strict, ESM (`.js` suffix on relative imports in TS). Tests: Vitest (`*.test.ts` in `test/`). Validation: zod.
- **All dependencies are already installed. Do NOT run `npm install` or edit any `package.json` / `package-lock.json`.** Need a package? Write it in your final report instead.
- **Only edit files inside the directories your brief owns.** Read anything else.
- Shared contract: `packages/engine/src/types.ts`. Read it, never edit it. Reference check to copy: `packages/engine/src/checks/secrets.ts` + `packages/engine/test/secrets.test.ts`.
- Do NOT run git commit, push, branch or reset. Do NOT post to GitHub. The lead reviews and commits.
- No real secrets anywhere. Fake keys must not match real vendor formats (no `sk_live_`, `AKIA…`, `ghp_`), so GitHub push protection does not block the commit.
- Never claim "unhackable" or "100% secure". Say "risk reduced".
- Comments explain why, not what. No placeholder TODO code; finish what you start or list it as not done.
- Finish by running your tests and print a report: files changed, test command + result, what is not done.
