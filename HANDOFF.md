# HANDOFF.md

_Updated 2026-11-25._ Read `BRAIN.md`, `AGENTS.md`, then this.

## Done (tested)
- Engine: 15 checks, diff guard, applier, CLI. `fix --out <dir> --verify` runs the owner's `npm test` after each patch and rolls back any patch that breaks it (local CLI only).
- Audit trail: every approved patch is saved as `.siidekick/<id>.patch` (`git apply -R` reverts it), plus `SIIDEKICK_LOG.md`. Secrets are masked in patch files.
- Doc files (`.md`, `.txt` …) no longer count as passing a code check; `input-validation` passes only when routes call `validate()`.
- API: scan, demo scan, patches, approve, download (includes the patch log). `scripts/deploy.sh` deploys twice so CORS gets the real CloudFront domain.
- New checks: `auth-on-endpoints` (adds `auth.js` bearer-token guard on `/admin`), `sql-string-concat` (report-only, shows the `?` rewrite), `dependency-audit` (OSV, names + versions only, bumps `package.json` with an OSV re-check of the target, 3 rounds max; querybatch pagination not handled).
- Verified: 108 engine + 8 API tests. Demo app 3 → 77 via the CLI (`--verify`: 12 kept, 0 rolled back, tests pass) and the API (12 patches, all guards OK). lodash 4.17.15 → ^4.18.1. Remaining fails: `sql-string-concat` (report-only), `input-validation` (owner wires `validate()`), `ui-heavy-animation` (report-only).

## Not done
- The web UI has a scaffold only (landing page and dashboard on a mock adapter). Claude designs it; it is not delegated.
- AWS: template prepared, not yet deployed.

## Next
1. Web UI: dashboard on the real API.
2. `scripts/deploy.sh` once AWS access is confirmed (#2).
3. Record the demo video (`docs/pitch/DEMO_SCRIPT.md`) and submit by Nov 29 (`docs/pitch/SUBMISSION.md`).

## Blocked on humans (#2)
AWS Educate account (which services are allowed is unconfirmed; use the existing LabRole). Bedrock: no. Still needed: the official rules link, the team leader and members, and pilot sites.
