# HANDOFF.md

_Updated 2026-11-25._ Read `BRAIN.md`, `AGENTS.md`, then this.

## Done (tested)
- Engine: 15 checks, diff guard, applier, CLI. `fix --out <dir> --verify` runs the owner's `npm test` after each patch and rolls back any patch that breaks it (local CLI only).
- Audit trail: every approved patch is saved as `.siidekick/<id>.patch` (`git apply -R` reverts it), plus `SIIDEKICK_LOG.md`. Secrets are masked in patch files.
- Doc files (`.md`, `.txt` …) no longer count as passing a code check; `input-validation` passes only when routes call `validate()`.
- API: scan, demo scan, patches, approve, download (includes the patch log). `scripts/deploy.sh` deploys twice so CORS gets the real CloudFront domain.
- New checks: `auth-on-endpoints` (adds `auth.js` bearer-token guard on `/admin`), `sql-string-concat` (report-only, shows the `?` rewrite), `dependency-audit` (OSV, names + versions only, bumps `package.json` with an OSV re-check of the target, 3 rounds max; querybatch pagination not handled).
- Verified: 109 engine + 20 API tests. Demo app 3 → 77 via the CLI (`--verify`: 12 kept, 0 rolled back, tests pass) and the API (12 patches, all guards OK). lodash 4.17.15 → ^4.18.1. Remaining fails: `sql-string-concat` (report-only), `input-validation` (owner wires `validate()`), `ui-heavy-animation` (report-only).

- Phase 1 (222cf59): dashboard on the real API (demo, GitHub URL, folder), हिन्दी toggle, tamper check (`/patches/:id/check`), zip download. Checked in a browser: zip opens, holds patched files + `.siidekick/*.patch` + log. Hardening: line diff trims shared ends, `/check` caps lines², Dynamo records gzipped (413 when too big), HttpApi throttled 5 rps / burst 20.

## Not done
- AWS: template prepared (`sam validate --lint` passes), not yet deployed.
- Hindi copy not checked by a native speaker.

## Open decision
- GitHub scans hard-reject repos over 500 files or 2 MB with "repo too large". Fine for the target users' small sites; a bigger repo could instead scan only the first N code files with a warning. Left strict for now.

## Next
1. `scripts/deploy.sh` once AWS access is confirmed (#2).
2. P1 items in `docs/PLAN.md`: GitHub Action, badge, landing polish.
3. Record the demo video (`docs/pitch/DEMO_SCRIPT.md`) and submit by Nov 29 (`docs/pitch/SUBMISSION.md`).

## Blocked on humans (#2)
AWS Educate account (which services are allowed is unconfirmed; use the existing LabRole). Bedrock: no. Still needed: the official rules link, the team leader and members, and pilot sites.
