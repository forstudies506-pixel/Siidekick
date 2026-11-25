# HANDOFF.md

_Updated 2026-11-25._ Read `BRAIN.md`, `AGENTS.md`, then this.

## Done
- Monorepo scaffold, deps installed (`npm install` at root).
- Engine core: contract, diff guard, applier, registry, CLI, `secrets-in-repo`. 13 tests pass. Thin slice verified: scan → fix → guard OK → rescan clean.
- Board: issues #1 (board), #2 (needs from humans). Workstream briefs in `docs/workstreams/`.

## In progress (free agents, see AGENTS.md table)
WS-demo + WS-engine-delivery (kilo), WS-engine-security (opencode lead), WS-api-infra (opencode developer), WS-web-landing (copilot). Check the workstream issues for status.

## Next
1. Review each worker diff (Sonnet reviewer), run tests, commit, push, comment on #1.
2. Integrate: `npm run scan:demo` should find all 8 flaws in FLAWS.md; `fix --out` then `npm test` in the fixed copy passes.
3. Deploy with SAM once AWS access is confirmed (#2).
4. Demo video + submission by Nov 29.

## Blocked on humans (#2)
AWS: Educate account (unconfirmed which services; likely no IAM role creation → use existing LabRole). Bedrock: no. Still needed: official rules link, team leader/members, pilot sites.
