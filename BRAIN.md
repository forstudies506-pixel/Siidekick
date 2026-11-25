# BRAIN.md: map of the repo

Read this instead of searching. Fix any line you find wrong.

## What it is
Siidekick: scans a web repo, explains risks, proposes template patches (additive, or minimal-edit with listed removals), a diff guard blocks deletion of owner code, owner approves, rescan scores it. The CLI can also test each patch and roll it back. Spec: `docs/ROADMAP.md`. Build plan: `docs/PLAN.md`. Team rules: `AGENTS.md`. Current state: `HANDOFF.md`.

## Layout
| Path | What | Status |
|---|---|---|
| `packages/engine/` | `@siidekick/engine`: checks, diff guard, scanner, CLI | 15 checks, tested (108 tests) |
| `packages/engine/src/types.ts` | shared contract (Check, Finding, Patch, GuardResult, ScanReport). Change via board only | done |
| `packages/engine/src/diffGuard.ts` | `renderDiff` (LCS), `lineDiff`, `guardPatch` (additive: 0 removals; minimal-edit: only `allowedRemovals`; caps +400/−5; rejects overwrite/missing/stale `before`) | tested |
| `packages/engine/src/apply.ts` | `applyPatch` (throws `GuardRejected`), returns new in-memory snapshot | done |
| `packages/engine/src/registry.ts` | `registry = [...securityChecks, ...deliveryChecks]`, `runScan` (weighted score: crit 5, high 3, med 2, low 1, info .5; crashed detector = failed) | done |
| `packages/engine/src/checks/security.ts` | barrel: secrets-in-repo, security-headers, rate-limit, open-cors, auth-on-endpoints, sql-string-concat (report-only), dependency-audit (OSV) | tested |
| `packages/engine/src/checks/delivery.ts` | barrel: readme, ci-workflow, health-endpoint, error-handler, ui-heavy-animation, input-validation, firewall-rules, incident-playbook | tested |
| `packages/engine/src/checks/secrets.ts` | `secrets-in-repo`: reference pattern for every check; `secretValues()` for masking | tested |
| `packages/engine/src/checks/dependency-audit.ts` | OSV querybatch (names+versions only, 8 s, chunks of 1000, no pagination); range floors when no lockfile; `depEntries` offset scan bumps inline or multi-line deps; bump target re-checked ≤3 rounds | tested |
| `packages/engine/src/unifiedDiff.ts` | `unifiedFileDiff` (git-style), `patchArtifacts` → `.siidekick/<id>.patch` + `SIIDEKICK_LOG.md`, secrets masked | tested |
| `packages/engine/src/verify.ts` | `verifyPatches`: test-and-rollback with `npm test`, optional `Regenerate` hook. Local CLI only | tested |
| `packages/engine/src/loadRepo.ts` | read a dir into a snapshot (skips node_modules/.git/dist/.siidekick, >512 KB, binary) | done |
| `packages/engine/src/cli.ts` | `siidekick scan <dir> [--json]`, `siidekick fix <dir> [--out <dir>] [--verify]` (`--verify` needs `--out`) | done |
| `packages/engine/src/util.ts` | `redact`, `lineAt`, `CODE_EXT`, `DOC_EXT` (docs never pass a code check) | done |
| `demo/vulnerable-app/` | CampusKart Express app with 8 planted flaws (`FLAWS.md`), node:test tests | done, 3 → 77 after fix (CLI and API) |
| `apps/api/` | pure router + Lambda + local node:http (port 8787), storage `STORAGE=local\|dynamo` (Dynamo records gzipped, 413 past the 400 KB item limit); download includes the patch log; `/patches/:id/check` replays an edited patch through the guard | tested (20 tests) |
| `apps/api/src/github.ts` | public GitHub URL → codeload tarball, size/file caps, no redirects, in-memory tar parse, no code run | tested |
| `apps/web/` | Vite + React: landing `/`, dashboard `/app` (`?demo=1` auto-scans) on the real API; `VITE_MOCK=1` forces the mock adapter | done, Claude only |
| `apps/web/src/zip.ts` | store-only ZIP writer for the approved-patch download | done |
| `apps/web/src/i18n/hi.ts` | Hindi titles and reasons per check; needs a native speaker check (#2) | done, unchecked |
| `infra/` | AWS SAM template (HttpApi, Lambda arm64, DynamoDB, S3 + CloudFront OAC) | prepared, not deployed |
| `docs/workstreams/` | worker briefs + `COMMON.md` rules | done |
| `docs/pitch/` | `PITCH.md`, `DEMO_SCRIPT.md`, `SUBMISSION.md` | drafts |
| `scripts/deploy.sh` | `sam deploy` with a placeholder domain, reads `SiteUrl`, redeploys for CORS, syncs web to S3 | not run |
| `scripts/bundle-demo.ts` | bundles the demo app into `apps/api/src/demoRepo.generated.json` | done |

## Pipeline
`loadRepo` → `runScan(ctx, registry)` → per failing check `fix(ctx)` → `guardPatch` → `applyPatch` (sequential; fixers recompute from `ctx.repo`) → rescan → `patchArtifacts` (patch files + log). CLI `--verify`: `verifyPatches` writes the copy, runs `npm test` after each patch, rolls back failures. Status: `rescan-clean`/`rescan-partial`, or `verified` where tests ran.

## Commands (repo root)
```bash
npm test                      # all workspaces
npm run test -w @siidekick/engine
npm run scan:demo             # scan demo app with the CLI
npx tsx packages/engine/src/cli.ts fix demo/vulnerable-app --out /tmp/fixed --verify
npm run build -w packages/engine  # after engine changes; the API imports engine dist
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
