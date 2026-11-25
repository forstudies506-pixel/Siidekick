# Siidekick: 3-day finish plan

The pitch is in [IDEA.md](IDEA.md). The full spec is in [ROADMAP.md](ROADMAP.md). Submit by **2026-11-29**; the hard deadline is 2026-11-30 23:59 IST.

**Goal:** top 35 of 1000+, top 10 if possible. Every item below exists because it moves one judging weight (Bharat 30, AWS 25, Innovation 25, Demo 20). Anything that doesn't move a weight is cut.

## Where we stand (2026-11-25)
**Tested:**
- engine: 15 checks, diff guard, test-and-rollback, patch log
- CLI and HTTP API
- the demo goes 3 → 77 with 12 patches
- 109 engine tests and 20 API tests
- dashboard on the real API, GitHub URL scan, tamper check, हिन्दी toggle, zip download
- research docs in `docs/research/`

**Missing:**
- an AWS deploy
- a real-site pilot
- the video

## P0: without these we are not top 35
| # | Item | Weight | Owner | Done when |
|---|---|---|---|---|
| 1 | Dashboard on the real API: demo / folder upload / GitHub URL → findings → diff + guard verdict → approve → score → download | Demo, Innovation | Claude | The full flow works in a browser at phone and desktop widths against the local API |
| 2 | **Tamper check:** `POST /api/scans/:id/patches/:patchId/check` runs the real `guardPatch` on an edited patch | Innovation | Claude | The UI's "tamper" button shows the server rejecting a deleted owner line |
| 3 | Scan a public GitHub repo URL (codeload tarball, size/file caps, no code executed) | Bharat, Demo | opencode developer | API test on a fixture tarball; a manual run on a team-owned repo |
| 4 | AWS deploy via `scripts/deploy.sh` (LabRole) | AWS | Claude + human | A live CloudFront URL serves the dashboard and the API |
| 5 | Research docs in `docs/research/`: Bharat context, competitors, check rationale, every claim with a source link | Bharat, Innovation | Sonnet researcher, checked by Claude | Each claim links a source we opened |
| 6 | Pitch, submission and demo-script numbers match reality (15 checks, 3 → 77, 12 patches) | Demo | copilot | No stale number left (`grep` for 12 checks, ~30, ~85) |
| 7 | Demo video under 3 min | Demo | human voice, Claude script | Uploaded link in SUBMISSION.md |

## P1: the gap between top 35 and top 10
| # | Item | Weight | Owner |
|---|---|---|---|
| 8 | हिन्दी / English toggle on findings (Claude writes the Hindi; a human native speaker checks it) | Bharat | Claude |
| 9 | Landing page that tells the story in one scroll, linking straight into the demo | Demo | Claude |
| 10 | Pilot: scan 3–5 team-owned or permission-given repos and record before/after in `docs/research/PILOT.md`. No names published without consent | Bharat | humans supply repos (#2), Claude runs |
| 11 | `siidekick-guard` GitHub Action: runs the scan on a PR and fails it on new critical findings | Innovation | opencode lead |
| 12 | Score badge SVG endpoint (`GET /api/scans/:id/badge.svg`) | Demo | kilo |

## P2: only if P0 and P1 are green
- `sql-string-concat` as a minimal-edit patch (the rewrite already exists)
- shareable read-only report link
- OSV pagination

## Cleanup (runs alongside, kilo)
- Move the duplicated `callArgs` scanner from `checks/auth-on-endpoints.ts` and `checks/sql-string-concat.ts` into `util.ts`.
- Remove unused exports and files found by a dead-code pass, without restructuring.
- Drop stale `docs/workstreams/*` briefs once their work has landed.

## Schedule
| Day | Phase | Work |
|---|---|---|
| Nov 25 | 1. Plan + dispatch | Write these docs; dispatch items 3, 5, 6 and the cleanup; run `sam validate` / `sam build`; Claude builds item 2 and starts item 1 |
| Nov 26 | 2. Product | Item 1 is done end to end; merge items 3, 5, 6; **AWS cutoff: end of day.** If SAM deploy is blocked on Educate, fall back to a console deploy (Lambda function URL + S3 static site using LabRole). If that is blocked too, use a local demo plus the video |
| Nov 27 | 3. Polish + proof | Items 8–12; pilot runs; Sonnet review of all agent diffs; full test run |
| Nov 28 | 4. Ship | Record the video (human), take README screenshots, final docs, freeze `main` |
| Nov 29 | 5. Submit | Team leader submits from `docs/pitch/SUBMISSION.md` |

## Rules for the finish
- Say "risk reduced", never "secure" or "unhackable". No invented statistics, users, or traction.
- Never run uploaded code on the server. Test-and-rollback stays in the local CLI.
- One owner per file set (see `AGENTS.md`). Each agent diff goes through a Sonnet review, then the lead runs the tests, then it is committed.
- Commit and push per phase, after `git fetch` and reading teammates' commits.

## Open risks
- **AWS Educate:** unknown whether CloudFormation/SAM is allowed with LabRole. Human check asked on #2; fallbacks above.
- **OSV needs internet:** cache the demo repo's OSV results for a stage with bad wifi.
- **GitHub rate limits:** codeload tarballs need no token, but large repos hit the caps. Show a clear message.
