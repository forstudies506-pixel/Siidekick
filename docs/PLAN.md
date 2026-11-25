# Siidekick: product + hackathon plan

Source of truth for the product is `docs/ROADMAP.md`. This file is the build plan for the hackathon (submit by 2026-11-29, hard deadline 2026-11-30 23:59 IST).

## Product in one line
Scan a small team's web repo → explain each risk in plain words → propose small **add-only** template patches → a **diff guard** rejects any patch that deletes owner code → owner approves → rescan shows the score change. Never "unhackable"; always "risk reduced".

## Hackathon slice (what the demo must show)
1. Open the site (S3 + CloudFront). Landing explains the promise: "We never replace your code."
2. Click "Scan the demo shop" → Lambda scans `demo/vulnerable-app` (8 planted flaws) → score ~30.
3. Generate fixes → each patch shows its diff and the guard verdict; one patch is blocked to prove the guard.
4. Approve → rescan → score ~85+, status "rescan clean — tests not run". Locally, `siidekick fix --out` + `npm test` in the demo proves the owner's tests still pass ("verified (local)").

## Judging map
- Bharat impact (30): Indian student founders, college clubs/fest sites, small shops, NGOs; free; plain-language explanations.
- AWS build (25): Lambda + API Gateway HTTP API + DynamoDB + S3 + CloudFront via SAM; Cognito later; Bedrock optional (costs money, off by default).
- Innovation (25): diff guard enforced in code; deterministic patches, AI only explains.
- Demo (20): the 4 steps above, under 3 minutes.

## Checks in the slice (12)
Security (C): `secrets-in-repo` (done), `dependency-audit`, `security-headers`, `open-cors`, `rate-limit`, `sql-string-concat` (report), `auth-on-endpoints`.
Delivery/monitoring/UI (A/B/E): `readme`, `ci-workflow`, `health-endpoint`, `error-handler`, `ui-heavy-animation` (report).

## Timeline
| Day | Work |
|---|---|
| Nov 25 | Engine core + secrets check (done). Parallel: demo app, security checks, delivery checks, API + SAM, web. |
| Nov 26 | Integrate, deploy to AWS (needs AWS access, issue #2). |
| Nov 27 | Polish dashboard, local "verified" run, optional AI explanations, pilot on 1–2 real sites. |
| Nov 28 | Demo video, slides, README screenshots. |
| Nov 29 | Submit (team leader only). |

## Open risks
- AWS access type unknown (Builder ID alone cannot deploy). No `aws`/`sam` CLI installed yet.
- OSV lookups need internet; demo wifi may fail → cache OSV results for the demo repo.
- Free agent output quality varies → every diff is reviewed and tested before commit.
