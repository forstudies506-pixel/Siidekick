# Siidekick

Siidekick scans a small team's website repo, explains each security and reliability risk in plain words, and proposes small **add-only** patches. A diff guard rejects any patch that would delete the owner's code. The owner approves each patch, then a rescan shows the score change.

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

## Status
- Implemented and tested: engine core, diff guard, `secrets-in-repo` check, CLI.
- In progress: 11 more checks, demo app, API, web, AWS deploy. See `HANDOFF.md`.

## Docs
[ROADMAP](docs/ROADMAP.md) (full spec) · [PLAN](docs/PLAN.md) (hackathon plan) · [BRAIN](BRAIN.md) (repo map) · [AGENTS](AGENTS.md) (team rules) · [HANDOFF](HANDOFF.md) (current state)
