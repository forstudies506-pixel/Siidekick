# BRAIN.md: map of the repo

Read this instead of searching. Fix any line you find wrong.

## What it is
Siidekick: scans a web repo, explains risks, proposes template patches (additive, or minimal-edit with listed removals), a diff guard blocks deletion of owner code, owner approves, rescan scores it. The CLI can also test each patch and roll it back. Spec: `docs/ROADMAP.md`. Build plan: `docs/PLAN.md`. Team rules: `AGENTS.md`. Current state: `HANDOFF.md`.

## Layout
| Path | What | Status |
|---|---|---|
| `packages/engine/` | `@siidekick/engine`: checks, diff guard, scanner, CLI | 19 repo + 16 site checks, tested (169 tests) |
| `packages/engine/src/types.ts` | shared contract (Check, Finding, Patch, GuardResult, ScanReport). Change via board only | done |
| `packages/engine/src/diffGuard.ts` | `renderDiff` (LCS), `lineDiff`, `guardPatch` (additive: 0 removals; minimal-edit: only `allowedRemovals`; caps +400/−5; rejects overwrite/missing/stale `before`) | tested |
| `packages/engine/src/apply.ts` | `applyPatch` (throws `GuardRejected`), returns new in-memory snapshot | done |
| `packages/engine/src/registry.ts` | `registry = [...securityChecks, ...deliveryChecks, ...aiChecks]`, `runScan` (weighted score: crit 5, high 3, med 2, low 1, info .5; crashed detector = failed) | done |
| `packages/engine/src/checks/security.ts` | barrel: secrets-in-repo, security-headers, rate-limit, open-cors, auth-on-endpoints, sql-string-concat (report-only), dependency-audit (OSV) | tested |
| `packages/engine/src/checks/delivery.ts` | barrel: readme, ci-workflow, health-endpoint, error-handler, ui-heavy-animation, input-validation, firewall-rules, incident-playbook | tested |
| `packages/engine/src/checks/ai.ts` | barrel (Claude): hallucinated-package (npm/PyPI existence, report-only), client-exposed-secrets (server keys in browser code), baas-open-rules (Firebase/RTDB/Supabase RLS; fixes Firebase to require sign-in), jwt-misuse (decode w/o verify, alg none, literal/fallback secret, expiry off; fixes expiry) | tested |
| `packages/engine/src/checks/secrets.ts` | `secrets-in-repo`: reference pattern for every check; `secretValues()` for masking | tested |
| `packages/engine/src/checks/dependency-audit.ts` | OSV querybatch (names+versions only, 8 s, chunks of 1000, no pagination); range floors when no lockfile; `depEntries` offset scan bumps inline or multi-line deps; bump target re-checked ≤3 rounds | tested |
| `packages/engine/src/unifiedDiff.ts` | `unifiedFileDiff` (git-style), `patchArtifacts` → `.siidekick/<id>.patch` + `SIIDEKICK_LOG.md`, secrets masked | tested |
| `packages/engine/src/verify.ts` | `verifyPatches`: test-and-rollback with `npm test`, optional `Regenerate` hook. Local CLI only | tested |
| `packages/engine/src/replay.ts` | `replayDemo`: writes before/after copies of the demo to a temp dir, boots each with `node` on a free port (minimal env, `runtimeDir` supplies express/lodash), fires 5 live attacks + 1 source check with control checks, runs the after copy's tests with `node --test`; `attackPaths` chains receipts into paths. Demo shop only | tested |
| `packages/engine/src/loadRepo.ts` | read a dir into a snapshot (skips node_modules/.git/dist/.siidekick, >512 KB, binary) | done |
| `packages/engine/src/cli.ts` | `siidekick scan <dir> [--json]`, `siidekick fix <dir> [--out <dir>] [--verify] [--prove]` (`--verify` needs `--out`; `--prove` only on an unchanged `demo/vulnerable-app`, runs `replayDemo`) | tested |
| `packages/engine/src/site/` | `checks.ts`: 16 passive site checks over a `SiteSnapshot` (TLS, headers, cookies, forms, scripts, source maps, security.txt, AI keys in the browser); report-only | tested |
| `packages/engine/src/util.ts` | `redact`, `lineAt`, `CODE_EXT`, `DOC_EXT` (docs never pass a code check), `serverShape()` (which server kinds a repo holds; drives `skip`), exported `VENDOR` / `TEST_FILE` / `PY_SERVER` path and source patterns | done |
| `demo/vulnerable-app/` | CampusKart Express app with 12 planted flaws (`FLAWS.md`; 9–12 in files `server.js` never loads), node:test tests | done, 2 → 59 after fix (CLI) |
| `apps/api/` | pure router + Lambda + local node:http (port 8787), storage `STORAGE=local\|dynamo\|upstash` (Dynamo and Upstash records gzipped, 413 past the size cap; health reports `storage`); download includes the patch log; `/patches/:id/check` replays an edited patch through the guard; `/prove` runs the attack replay on demo records only (`demo: true`); scan fetches go through `cachedOsvFetch` (OSV answers reused 10 min); `build` also copies the demo JSON and builds `dist/runtime/node_modules` for the replay | tested (77 tests) |
| `apps/api/src/site.ts` | passive fetcher for `POST /api/sites`: SSRF guard at connect time, ≤5 redirects, 1.5 MB HTML, 1 MB per script, 8 s per hop, 20 s budget, 20 scans/min per instance (429); body not stored | tested |
| `apps/api/src/vercel.ts` | Vercel adapter for the same router; `STORAGE=upstash` when `UPSTASH_REDIS_REST_URL`/`_TOKEN` are set, else `DATA_DIR=/tmp/siidekick` (per instance) | live |
| `apps/api/src/github.ts` | public GitHub URL → codeload tarball, size/file caps, no redirects, in-memory tar parse, no code run | tested |
| `apps/web/` | Vite + React: landing `/`, dashboard `/app` as a 4-step flow (`?scan=<id>&step=connect\|findings\|fixes\|verify`, `?demo=1` auto-scans) on the real API; `api/client.ts` `live()` maps `ApiUnavailable` to an offline state; `VITE_MOCK=1` forces the mock adapter; any address that is not a GitHub repo goes to `POST /api/sites`; landing check list comes from `GET /api/checks`; findings export (JSON/Markdown), share link, search, filters, keys (`/`, `1`–`4`, `f p n a`, Esc) | done, Claude only |
| `apps/web/src/zip.ts` | store-only ZIP writer for the approved-patch download | done |
| `apps/web/src/i18n/hi.ts` | Hindi titles and reasons per check; needs a native speaker check (#2) | done, unchecked |
| `infra/` | AWS SAM template (HttpApi, Lambda arm64, DynamoDB, S3 + CloudFront OAC) | prepared, not deployed |
| `docs/workstreams/` | worker briefs + `COMMON.md` rules | done |
| `docs/pitch/` | `PITCH.md`, `DEMO_SCRIPT.md`, `SUBMISSION.md` | final, TODO(team): video link, names |
| `docs/API.md` | HTTP API reference | done |
| `scripts/deploy.sh` | `sam deploy` with a placeholder domain, reads `SiteUrl`, redeploys for CORS, syncs web to S3 | not run |
| `scripts/deploy-vercel.sh` | Build Output API v3 deploy (`--prod` for siidekick.ashforge.cv): bundles the API with the AWS SDK, copies the express/lodash runtime to `api.func/runtime`, nodejs22.x, maxDuration 60 | run, live |
| `scripts/bundle-demo.ts` | bundles the demo app into `apps/api/src/demoRepo.generated.json` | done |

## Pipeline
`loadRepo` → `runScan(ctx, registry)` → per failing check `fix(ctx)` → `guardPatch` → `applyPatch` (sequential; fixers recompute from `ctx.repo`) → rescan → `patchArtifacts` (patch files + log). CLI `--verify`: `verifyPatches` writes the copy, runs `npm test` after each patch, rolls back failures. Status: `rescan-clean`/`rescan-partial`, or `verified` where tests ran. Demo only: `/prove` → `approvedSnapshot` → `replayDemo` (attack before and after, control checks, tests) → `attackPaths`.

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
`GET /api/health` · `GET /api/checks` · `POST /api/sites {url}` · `POST /api/scans/github {url}` · `POST /api/scans {name, files[]}` (≤500 files, ≤2 MB) · `POST /api/scans/demo` · `GET /api/scans/:id` (stored scan, for reload) · `POST /api/scans/:id/patches` · `POST /api/scans/:id/patches/:patchId/approve` · `POST /api/scans/:id/patches/:patchId/check` · `POST /api/scans/:id/prove` (demo only) · `GET /api/scans/:id/download`. Details: `docs/API.md`.

## Design (web)
Dark graphite + amber, soft neo-brutalism, editorial. OKLCH tokens. Schibsted Grotesk + JetBrains Mono. Amber = add/action, red = blocked/deleted, green = passed only.

## Agents and board
Team table and CLI commands: `AGENTS.md`. Board: GitHub Issues #1 (board), #2 (needs from humans), one issue per workstream.

## Stack
npm workspaces, Node ≥20, TypeScript 7, Vitest, zod, tsx, esbuild. AWS free tier only; Bedrock off (costs money).
