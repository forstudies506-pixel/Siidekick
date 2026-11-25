# HANDOFF.md

_Updated 2026-11-25._ Read `BRAIN.md`, `AGENTS.md`, then this.

## Done (tested)
- Engine: 15 checks, diff guard, applier, CLI. `fix --out <dir> --verify` runs the owner's `npm test` after each patch and rolls back any patch that breaks it (local CLI only).
- Audit trail: every approved patch is saved as `.siidekick/<id>.patch` (`git apply -R` reverts it), plus `SIIDEKICK_LOG.md`. Secrets are masked in patch files.
- Doc files (`.md`, `.txt` …) no longer count as passing a code check; `input-validation` passes only when routes call `validate()`.
- API: scan, demo scan, patches, approve, download (includes the patch log). `scripts/deploy.sh` deploys twice so CORS gets the real CloudFront domain.
- New checks: `auth-on-endpoints` (adds `auth.js` bearer-token guard on `/admin`), `sql-string-concat` (report-only, shows the `?` rewrite), `dependency-audit` (OSV, names + versions only, bumps `package.json` with an OSV re-check of the target, 3 rounds max; querybatch pagination not handled).
- Verified: 111 engine + 25 API tests. Demo app 3 → 77 via the CLI (`--verify`: 12 kept, 0 rolled back, tests pass) and the API (12 patches, all guards OK). lodash 4.17.15 → ^4.18.1. Remaining fails: `sql-string-concat` (report-only), `input-validation` (owner wires `validate()`), `ui-heavy-animation` (report-only).

- Phase 2: **Proof of fix.** `packages/engine/src/replay.ts` boots the demo shop twice (as scanned, as patched) on free localhost ports, fires 5 live attacks at both (SQLi password dump, unauthenticated admin list, brute force, open CORS, framing) plus 1 source check (hardcoded payment key), each with a control check that real customers still get through, then chains them into 2 attack paths and marks the open one "fix this one first". `POST /api/scans/:id/prove` runs it only for records created by `/api/scans/demo` (`demo: true`); the child gets a minimal env (no AWS creds) and the `express`/`lodash` runtime from `apps/api/dist/runtime` (dev falls back to the root `node_modules`). Dashboard shows a Proof panel with paths and receipts. Checked in a browser at desktop and 375 px: 5/6 blocked, 1/2 paths closed, 4/4 tests, replay in a few seconds. Also run once with only the bundled `apps/api/dist/runtime` (no workspace `node_modules`): boots, 4/4 tests.
- Phase 3: **Fast approve.** `cachedOsvFetch` in `apps/api/src/router.ts` reuses an identical OSV.dev answer for 10 min (max 500 entries, OK responses only, other hosts untouched), so a rescan after approve no longer re-queries OSV. Measured locally: approve went from ~4.8 s to ~4 ms. The dashboard disables the other approve buttons while one is pending. Cache is per Lambda instance, so a cold instance still pays one OSV round trip.
- Phase 1 (222cf59): dashboard on the real API (demo, GitHub URL, folder), हिन्दी toggle, tamper check (`/patches/:id/check`), zip download. Checked in a browser: zip opens, holds patched files + `.siidekick/*.patch` + log. Hardening: line diff trims shared ends, `/check` caps lines², Dynamo records gzipped (413 when too big), HttpApi throttled 5 rps / burst 20.

## Not done
- AWS: template prepared (`sam validate --lint` passes), not yet deployed.
- Hindi copy not checked by a native speaker.
- Replay on Lambda is unverified: Node 22 runtime, writing the two shop copies to `/tmp`, spawning `node` children.

## Open decision
- GitHub scans hard-reject repos over 500 files or 2 MB with "repo too large". Fine for the target users' small sites; a bigger repo could instead scan only the first N code files with a warning. Left strict for now.

## Next
1. `scripts/deploy.sh` once AWS access is confirmed (#2).
2. P1 items in `docs/PLAN.md`: GitHub Action, badge, landing polish.
3. Record the demo video (`docs/pitch/DEMO_SCRIPT.md`) and submit by Nov 29 (`docs/pitch/SUBMISSION.md`).

## Blocked on humans (#2)
AWS Educate account (which services are allowed is unconfirmed; use the existing LabRole). Bedrock: no. Still needed: the official rules link, the team leader and members, and pilot sites.
