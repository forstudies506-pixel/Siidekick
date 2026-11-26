# Engineering log

What was built for Siidekick, in order, from the git history on `main`. Every entry names its commit, so `git show <hash>` gives the full change.

- **Owner:** the repo owner (git author `ashvyagni`), working with AI coding agents (Claude Code as lead, plus the free agents listed in `AGENTS.md`). The owner set the direction and decided scope; agents wrote most of the code.
- **Claude commits:** two commits are authored as Claude and are marked here.
- **Phase numbers:** these follow the commit messages. Root `HANDOFF.md` groups phases 7–9 differently.
- **How it was checked:** filled in only where a commit message or `HANDOFF.md` recorded it. "—" means no check was recorded. Nothing is interpolated.

For the current state and what is left, read [`TEAM_HANDOFF.md`](TEAM_HANDOFF.md).

## 2026-11-25: engine, API, proof of fix, AI-era checks

| Commit | What landed | How it was checked |
|---|---|---|
| `86b2246` (Claude) | Roadmap and a 32-check registry plan (`docs/ROADMAP.md`). | Planning only. |
| `3e2e48d` | Monorepo scaffold (npm workspaces: engine, api, web, demo). Built the diff guard, patch applier, check registry, CLI, the `secrets-in-repo` check and the team docs. The diff guard is an LCS line diff that refuses any patch removing owner lines. | 13 tests. |
| `f9ea788` | API router: scan, patches, approve, download. Planted-flaw demo shop (`demo/vulnerable-app`). AWS SAM template. Delivery and security-header checks. | — |
| `5a5d586` | New checks: `auth-on-endpoints`, `sql-string-concat` (report-only), `dependency-audit` (OSV.dev), `input-validation`, `firewall-rules`, `incident-playbook`. `fix --verify` runs the owner's `npm test` after each patch and rolls back any patch that breaks it. Patch log (`.siidekick/<id>.patch` + `SIIDEKICK_LOG.md`). `scripts/deploy.sh`. | 108 engine + 8 API tests. Demo shop 3 → 77 with 12 patches at this point. |
| `a576190` | `docs/IDEA.md` and the 3-day `docs/PLAN.md`. | Docs. |
| `222cf59` | **Phase 1.** Dashboard wired to the real API (demo, GitHub URL, folder upload). GitHub tarball scan. Tamper check (`/patches/:id/check`). हिन्दी toggle. Zip download. Hardening: DynamoDB records gzipped (413 when too big), HttpApi throttled. | Browser: zip opens and holds patched files, patch files and log. |
| `e6f3b95` | Docs refresh. | Docs. |
| `8bf4a16` | **Phase 2: proof of fix.** `replay.ts` boots the demo shop twice (as scanned, as patched) on localhost. It fires 5 live attacks and 1 source check at both copies, each with a control request, then chains the results into attack paths. `POST /api/scans/:id/prove`, demo records only. | Browser at desktop and 375 px: 5/6 blocked, 1/2 paths closed, 4/4 demo tests. |
| `15b7562` | **Phase 3: fast approve.** `cachedOsvFetch` reuses identical OSV.dev answers for 10 minutes. | Measured locally: approve ~4.8 s → ~4 ms. |
| `956c5ec` (Claude) | `tools/siidekick-py`: a standalone Python scanner. Nothing in the app imports it. | — |
| `4de8a6a` | **Phase 4: AI-era checks** (group F): `hallucinated-package`, `client-exposed-secrets`, `baas-open-rules`, `jwt-misuse`. Demo flaws 9–12 added. | 137 engine + 26 API tests. Demo shop 2 → 59, 14 patches, all guards OK. |
| `4331cb1` | **Phase 5a.** Checks that do not fit a repo (no server, serverless only, Python) are skipped with a reason and left out of the score (`serverShape()`). | — |
| `313b6bb` | **Phase 5b.** Real scans only: no canned results anywhere. GitHub repos over the size caps are scanned in part, with a warning. | — |

## 2026-11-26: guided app, website scan, live deploy, durable storage

| Commit | What landed | How it was checked |
|---|---|---|
| `c8d787d` | **Phase 6: guided dashboard.** `/app` is a 4-step flow (Connect → Findings → Fixes → Verify & ship). Scan id and step live in the URL, so reload and back keep state. Approve returns the rescan-measured score. | 145 engine + 28 API + 4 demo tests. Browser: this repo 20 → 42 after 6 approvals; demo shop at 375 px; zip download. |
| `4cfdd7f` | **Phase 7: engine gaps.** | — |
| `eeac2bf` | **Phase 8: any live website.** `POST /api/sites` reads a public site passively and runs 16 site checks. SSRF guard at connect time, size and time caps, rate limit. | — |
| `4e2246b` | One scan box: the landing page takes a site URL or a GitHub URL. | — |
| `8cd29bb` | `GET /api/checks`: the check list comes from the engine registry. | — |
| `a661d6c` | **Phase 9: landing redesign.** Dark graphite + amber, editorial layout. | — |
| `4833f39` | CLI `fix --prove`: attack replay on the demo shop from the terminal. | Run: 2 → 59, 5/6 blocked, 1/2 paths closed, 4/4 tests. |
| `8823366` | Web reads the check list from the API. Adds JSON/Markdown export, share link, search, filters and keyboard shortcuts. | — |
| `fe2e1e5` | Vercel deploy (`scripts/deploy-vercel.sh`, Build Output API v3). | Live at https://siidekick.ashforge.cv. 169 engine + 71 API + 4 demo tests at this stage. |
| `432a317` | `docs/API.md` and pitch docs (`docs/pitch/`). | Docs. |
| `d44543a` | Live results. | — |
| `75acea0` | `STORAGE=upstash` (REST). Built, not used live. | Unit tests with a fake Upstash. |
| `9dcce5d` | `STORAGE=redis`: free 30 MB Redis Cloud through Vercel's integration. Records gzipped, 7-day expiry, 1 MB cap. | 83 API tests. Live `/api/health` reports `"storage":"redis"`; a demo scan read back 200 eight times in a row. |

## Where it ended (2026-11-26)

| Area | State |
|---|---|
| Tests | `npm test` from the root: engine 169/169, API 83/83, demo shop 4/4. |
| Live | https://siidekick.ashforge.cv on Vercel. `/api/health` returns `{"ok":true,"checks":19,"storage":"redis"}`. |
| Checks | 19 repo checks and 16 site checks. |
| Demo shop | 2 → 59 with 14 guard-passed patches; 13/19 passing. Replay: 5 of 6 attacks blocked, 1 of 2 attack paths closed. |
| AWS | SAM template prepared and lint-clean. Not deployed. |
