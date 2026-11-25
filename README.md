# Siidekick

Siidekick scans a small team's website repo, explains each security and reliability risk in plain words, and proposes small patches that **add** code (two narrow exceptions: a hardcoded key line is swapped for an environment variable, and a vulnerable version in `package.json` is bumped to the first fixed one). A diff guard rejects any patch that would delete other owner code. The owner approves each patch, then a rescan shows the score change.

**We never replace your code.** It reduces risk; it does not make anything "unhackable".

Built for the Campus to Cloud Hackathon (AWS, Techfest 2026-27).

## Run it
```bash
npm install
npm test
npm run scan:demo                                      # scan the planted-flaw demo app
npx tsx packages/engine/src/cli.ts fix demo/vulnerable-app --out /tmp/fixed
```
`fix` is a dry run by default; `--out` writes a patched copy and leaves the original untouched.

## Layout
- `packages/engine`: checks, diff guard, scanner, CLI
- `apps/api`: HTTP API (AWS Lambda + local server)
- `apps/web`: landing page and dashboard
- `demo/vulnerable-app`: demo shop with planted flaws
- `infra`: AWS SAM template (Lambda, API Gateway, DynamoDB, S3, CloudFront)

Add `--verify` (with `--out`) to run your own `npm test` after each patch; a patch that breaks your tests is rolled back. Every applied patch is saved as `.siidekick/<id>.patch` and listed in `SIIDEKICK_LOG.md` with its reason and a `git apply -R` revert command. Secrets are masked in those files.

## Status
- Implemented and tested: 19 checks (secrets, security headers, rate limit, open CORS, auth on admin routes, string-built SQL, dependency audit, input validation, firewall rules, incident playbook, README, CI, health endpoint, error handler, heavy UI animation, plus AI-era: hallucinated packages, server keys in browser code, open Firebase/Supabase rules, JWT misuse), diff guard, test-and-rollback, patch log, CLI, HTTP API. On the demo app the score goes from 2 to 59 via the CLI (14 patches, all guards OK). 3 checks are left for the owner: rewrite the SQL with `?` placeholders (report-only, the rewrite is shown), wire `validate()` into the route, and the login animation (report-only).
- Dependency audit: sends only package names and versions to [OSV](https://osv.dev) (8 s timeout). Without a lockfile it audits the lowest version each `package.json` range allows. The bump target is re-checked against OSV up to 3 times so it does not land in a newer advisory. A bump is proven only after you run `npm install` and your tests.
- Implemented and tested locally: web dashboard on the real API (demo shop, public GitHub URL or folder upload → findings with a हिन्दी toggle → diff and guard verdict → tamper check → approve → score → zip download). `npm run dev` in `apps/api` and `apps/web`, then open `/app?demo=1`.
- Proof of fix, implemented and tested locally (demo shop only): after you approve fixes, the server boots two copies of the demo shop on localhost, one as scanned and one with your approved patches, fires five live attacks at both, plus a sixth check that reads the code for a hardcoded payment key. Each blocked attack comes with a check that a normal customer request still works. Attacks are chained into paths (for example: leaked passwords → log in as any customer), and the open path is marked "fix this one first". On the demo with all 12 patches approved: 5 of 6 attacks blocked, 1 of 2 paths closed, the shop's own tests pass 4/4. The SQL injection stays open on purpose, because no safe automatic patch exists, and the report says so. Uploaded and GitHub code is never run: the replay refuses every scan except the bundled demo.
- Not yet run: the AWS deploy (template and `scripts/deploy.sh` are ready). See `HANDOFF.md`.

## Docs
[ROADMAP](docs/ROADMAP.md) (full spec) · [IDEA](docs/IDEA.md) (pitch) · [PLAN](docs/PLAN.md) (3-day finish plan) · [BRAIN](BRAIN.md) (repo map) · [AGENTS](AGENTS.md) (team rules) · [HANDOFF](HANDOFF.md) (current state)
