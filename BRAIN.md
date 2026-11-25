# BRAIN.md: map of the repo

Read this instead of searching. Fix any line you find wrong.

## What it is
Siidekick: scans a web repo, explains risks, proposes add-only patches, a diff guard blocks deletions of owner code, owner approves, rescan scores it. Spec: `docs/ROADMAP.md`. Build plan: `docs/PLAN.md`. Team rules: `AGENTS.md`. Current state: `HANDOFF.md`.

## Layout
| Path | What | Status |
|---|---|---|
| `packages/engine/` | `@siidekick/engine`: checks, diff guard, scanner, CLI | core + 1 check tested |
| `packages/engine/src/types.ts` | shared contract (Check, Finding, Patch, GuardResult, ScanReport). Change via board only | done |
| `packages/engine/src/diffGuard.ts` | `renderDiff` (LCS), `lineDiff`, `guardPatch` (additive: 0 removals; minimal-edit: only `allowedRemovals`; caps +400/−5; rejects overwrite/missing/stale `before`) | tested |
| `packages/engine/src/apply.ts` | `applyPatch` (throws `GuardRejected`), returns new in-memory snapshot | done |
| `packages/engine/src/registry.ts` | `registry = [...securityChecks, ...deliveryChecks]`, `runScan` (weighted score: crit 5, high 3, med 2, low 1, info .5; crashed detector = failed) | done |
| `packages/engine/src/checks/security.ts` | barrel for security checks (opencode) | 1 check |
| `packages/engine/src/checks/delivery.ts` | barrel for delivery checks (kilo) | empty |
| `packages/engine/src/checks/secrets.ts` | `secrets-in-repo`: reference pattern for every check | tested |
| `packages/engine/src/loadRepo.ts` | read a dir into a snapshot (skips node_modules/.git/dist, >512 KB, binary) | done |
| `packages/engine/src/cli.ts` | `siidekick scan <dir> [--json]`, `siidekick fix <dir> [--out <dir>]` | done |
| `packages/engine/src/util.ts` | `redact`, `lineAt`, `CODE_EXT` | done |
| `demo/vulnerable-app/` | CampusKart Express app with 8 planted flaws (`FLAWS.md`), node:test tests | brief only |
| `apps/api/` | pure router + Lambda + local node:http (port 8787), storage `STORAGE=local\|dynamo` | brief only |
| `apps/web/` | Vite + React: landing `/`, dashboard `/app`, mock adapter | brief only |
| `infra/` | AWS SAM template (HttpApi, Lambda arm64, DynamoDB, S3 + CloudFront OAC) | brief only |
| `docs/workstreams/` | worker briefs + `COMMON.md` rules | done |

## Pipeline
`loadRepo` → `runScan(ctx, registry)` → per failing check `fix(ctx)` → `guardPatch` → `applyPatch` (sequential; fixers recompute from `ctx.repo`) → rescan. Status: `rescan-clean` unless tests ran → `verified` (label where they ran).

## Commands (repo root)
```bash
npm test                      # all workspaces
npm run test -w @siidekick/engine
npm run scan:demo             # scan demo app with the CLI
npx tsx packages/engine/src/cli.ts fix demo/vulnerable-app --out /tmp/fixed
npm run dev -w @siidekick/api # API on :8787
npm run dev -w @siidekick/web # web on :5173 (VITE_MOCK=1 for mock data)
```

## API contract
`GET /api/health` · `POST /api/scans {name, files[]}` (≤500 files, ≤2 MB) · `POST /api/scans/demo` · `GET /api/scans/:id` · `POST /api/scans/:id/patches` · `POST /api/scans/:id/patches/:patchId/approve` · `GET /api/scans/:id/download`. Details: `docs/workstreams/WS-api-infra.md`.

## Design (web)
Dark graphite + amber, soft neo-brutalism, editorial. OKLCH tokens. Schibsted Grotesk + JetBrains Mono. Amber = add/action, red = blocked/deleted, green = passed only.

## Agents and board
Team table and CLI commands: `AGENTS.md`. Board: GitHub Issues #1 (board), #2 (needs from humans), one issue per workstream.

## Stack
npm workspaces, Node ≥20, TypeScript 7, Vitest, zod, tsx, esbuild. AWS free tier only; Bedrock off (costs money).
