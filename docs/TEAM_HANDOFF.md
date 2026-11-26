# Team handoff

Start here if you are picking up Siidekick. This file covers:

- what the app does today and how it works
- what is done
- what is left, step by step

Each kind of fact has one home:

| For | Read |
|---|---|
| Numbers | This file. If another doc disagrees, this file wins. |
| History | [`ENGINEERING_LOG.md`](ENGINEERING_LOG.md) |
| Running dev log for AI agent sessions | Root [`HANDOFF.md`](../HANDOFF.md) |
| Repo map | [`BRAIN.md`](../BRAIN.md) |
| Endpoints | [`API.md`](API.md) |

_Updated 2026-11-26. Deadline: 2026-11-30 23:59 IST. The plan is to submit on **Nov 29**._

---

## 1. What Siidekick does today

Siidekick finds the security holes that AI-assisted attackers look for first, and the ones AI-written code tends to ship. It explains each one in plain words and fixes what it safely can. It is built for small shops, student teams and colleges that have no security engineer.

Try it live at **https://siidekick.ashforge.cv**:

- **Scan any website.** Paste a URL. Siidekick reads the site passively, the way a browser does, and runs 16 checks:
  - TLS and HSTS
  - CSP, clickjacking and other headers
  - cookies
  - CORS
  - forms
  - secrets and AI keys in page scripts
  - mixed content
  - SRI
  - version leaks
  - exposed source maps
  - `security.txt`

  No attack traffic is sent.
- **Scan any public GitHub repo.** Paste a repo URL. Siidekick reads the code and runs 19 checks:
  - leaked secrets
  - missing auth on admin routes
  - rate limiting
  - security headers
  - CORS
  - SQL built from strings
  - vulnerable dependencies (via OSV.dev)
  - input validation

  It also runs four **AI-era checks**:
  - hallucinated (non-existent) packages
  - server keys shipped to the browser
  - open Firebase or Supabase rules
  - JWTs that are decoded but never verified
- **Get add-only fixes.** Each fixable finding comes with a patch. A diff guard refuses any patch that deletes or rewrites the owner's code. Nothing lands until the owner approves it.
- **Measured, not promised.** Each approval rescans the patched copy and shows the new score.
- **Proof of fix** (demo shop only). Siidekick boots the shop twice, as scanned and as patched. It fires the same live attacks at both copies, each paired with a control request showing real users still get through.
- **Take it home.** The owner gets:
  - a zip of the patched files
  - one `.patch` file per fix, each revertable with `git apply -R`
  - a `SIIDEKICK_LOG.md`
  - a JSON or Markdown report
  - a share link
- **CLI.** The same engine runs locally: `scan`, `fix --verify` and `fix --prove`. `--verify` runs the owner's tests after each patch and rolls back any patch that breaks them.
- **Hindi.** A हिन्दी toggle covers check titles and reasons. A native speaker has not reviewed it yet.

## 2. Numbers (single source of truth)

| What | Value | How to re-check |
|---|---|---|
| Repo checks | 19 | `curl -s https://siidekick.ashforge.cv/api/checks` |
| Site checks | 16 | same |
| Tests | engine 169, API 83, demo shop 4, all passing | `npm test` from the repo root |
| Demo shop score | 2 → 59 after approving all 14 patches; 13/19 checks pass | `/app?demo=1`, approve all fixes |
| Attack replay | 5 of 6 attacks blocked; 1 of 2 attack paths closed | "Verify & ship" step, or `fix --prove` |
| Scan record lifetime | 7 days (free 30 MB Redis) | `/api/health` shows `"storage":"redis"` |

Some numbers in other files are older (15 checks, 3 → 77, 12 patches, 111 tests); they come from before the AI-era checks. Use the numbers above.

## 3. How it works

```
  website URL ──► apps/api/src/site.ts ──► passive fetch (SSRF guard, caps) ──► 16 site checks ──► report
                                                                              (packages/engine/src/site/checks.ts)

  GitHub URL / folder / demo
        │
        ▼
  loadRepo ──► runScan(ctx, registry) ──► report + score
                     │                                   score weights: critical 5, high 3,
                     ▼                                   medium 2, low 1, info 0.5
           for each failing check: check.fix(ctx)
                     │
                     ▼
               guardPatch  ── refuses deletes / rewrites / overwrites / stale edits
                     │
                     ▼
               applyPatch ──► rescan ──► measured score
                     │
                     ├──► /download: patched files + .siidekick/<id>.patch + SIIDEKICK_LOG.md (secrets masked)
                     └──► /prove (demo shop only): replay.ts boots before + after, fires attacks, chains attack paths
```

### Engine (`packages/engine`)

- **Checks.** Every check is one object with an `id`, a `severity` and three functions:
  - `run(ctx)`: pass or fail, with evidence
  - optional `fix(ctx)`: returns file edits
  - optional `skip(ctx)`: for repos the check does not fit, such as a serverless-only or Python repo; skipped checks are left out of the score
- **Where checks live.** Repo checks are in `src/checks/`, AI-era checks in `src/checks/ai.ts`, site checks in `src/site/checks.ts`. All are registered in the registry.
- **Diff guard** (`diffGuard.ts`). An LCS line diff.
  - An additive patch may remove **0** lines.
  - A minimal-edit patch may remove only the lines it declares.
  - Size caps apply. Any patch that overwrites a file or works from a stale "before" is refused.
- **Replay** (`replay.ts`). It copies the demo shop twice, as scanned and as patched, and starts both on free localhost ports. It then sends:
  - SQL injection
  - an unauthenticated admin request
  - brute force
  - an open-CORS read
  - framing
  - a check for a hardcoded payment key in the source

  Each attack has a control request. It runs only on the bundled demo, never on uploaded code.

### API (`apps/api`)

- **One router, three hosts.** `src/router.ts` (`makeRouter`) is served by `local.ts` (node:http, port 8787), `lambda.ts` (AWS) and `vercel.ts` (live).
- **Endpoints.** Listed in [`API.md`](API.md).
- **Storage** (`src/store.ts`), picked by `STORAGE`:

  | `STORAGE` | Backend | Notes |
  |---|---|---|
  | unset | local files | The default. |
  | `redis` | Redis | Live uses this. |
  | `upstash` | Upstash | Built, unused. |
  | `dynamo` | DynamoDB | The AWS build. |

  Records are gzipped and expire after 7 days.
- **OSV cache.** `cachedOsvFetch` keeps OSV.dev answers for 10 minutes, so approve is fast.

### Web (`apps/web`)

- **Stack.** Vite + React.
- **Pages.**
  - `/` is the landing page with one scan box.
  - `/app` is the 4-step flow: Connect → Findings → Fixes → Verify & ship.
- **State.** The scan id and step live in the URL.
- **Check list.** Read from `GET /api/checks`. Nothing about the checks is hardcoded in the UI.

### Deploy

| Target | State | How |
|---|---|---|
| Vercel | **Live** | `bash scripts/deploy-vercel.sh --prod` on the owner's account. |
| AWS SAM | **Prepared, not deployed** | `infra/template.yaml` (HttpApi, Lambda arm64, DynamoDB, S3 + CloudFront, existing `LabRole`) and `scripts/deploy.sh`. |

## 4. Done

| Item | Label |
|---|---|
| Website scan, 16 checks, SSRF guard, rate limit | live, tested |
| GitHub repo scan, folder upload, demo shop, 19 checks | live, tested |
| Add-only patches, diff guard, approve with rescan | live, tested |
| Tamper check on an edited patch (`/patches/:id/check`) | live, tested |
| Attack replay with attack paths (demo shop) | live, tested |
| Zip download, patch files, log, JSON/Markdown export, share link | live, tested |
| Search, filters, keyboard shortcuts, हिन्दी toggle | live (Hindi not reviewed) |
| Durable scan records (Redis, 7 days) | live, tested |
| CLI `scan`, `fix --verify`, `fix --prove` | tested locally |
| AWS SAM build (`sam validate --lint` passes) | prepared, not deployed |
| Pitch docs: `docs/pitch/SUBMISSION.md`, `docs/pitch/DEMO_SCRIPT.md` | written; video link and team names missing |

## 5. Expected failures: do not "fix" these

The demo shop (`demo/vulnerable-app`) is **deliberately vulnerable**. After all 14 patches, these six checks still fail on purpose:

| Check | Why it still fails |
|---|---|
| `sql-string-concat` | Report-only. No safe automatic rewrite exists. This is the SQL injection the replay still lands, and the demo script says so. |
| `jwt-misuse` | The owner must add token verification. |
| `input-validation` | The owner must wire `validate()` into the routes. |
| `client-exposed-secrets` | The owner must move the key server-side. |
| `hallucinated-package` | Report-only. |
| `ui-heavy-animation` | Report-only. |

If you change the demo shop or any check's `fix()`, the pitch numbers in section 2 change. Re-run them, then update this file, `docs/pitch/SUBMISSION.md`, `docs/pitch/DEMO_SCRIPT.md` and the README in the same commit.

## 6. What is left, in order

Put your name in the **Owner** column on issue #1 before you start. Items 1–3 must be done before submission. The rest are nice to have.

| # | Task | Owner |
|---|---|---|
| 1 | Record the demo video | ____ |
| 2 | Fill the submission fields and submit | ____ (team leader) |
| 3 | AWS deploy, or confirm the fallback | ____ |
| 4 | Hindi review | ____ (native speaker) |
| 5 | Answer issue #2 | ____ |
| 6 | README screenshots | ____ |
| 7 | P1: `siidekick-guard` GitHub Action | ____ |
| 8 | P1: score badge | ____ |
| 9 | Pilot scans | ____ |

### 1. Record the demo video (humans only)

1. Follow [`docs/pitch/DEMO_SCRIPT.md`](pitch/DEMO_SCRIPT.md). It is 3 minutes, recorded on https://siidekick.ashforge.cv.
2. Open the site once a minute before you record, so the server is warm.
3. For the website scan, use a site the team owns or has permission to show.
4. For the repo part, use "Scan the demo shop". The replay only works there.
5. Upload the video unlisted (YouTube or Drive) and paste the link into `docs/pitch/SUBMISSION.md` → "Demo video link".
6. **Do not put a scan link (`/app?scan=…`) in the video description or the submission.** Scan records expire after 7 days, and late judges would get a 404. Link `https://siidekick.ashforge.cv/app?demo=1` instead: it creates a fresh demo scan every time.

**Done when:** the video link is in `SUBMISSION.md` and plays logged out.

### 2. Fill the submission fields and submit

1. In `docs/pitch/SUBMISSION.md`, replace both `TODO(team)` fields: video link and team names.
2. The team leader submits from that file by **Nov 29**. The hard deadline is Nov 30 23:59 IST.
3. The official rules link is still missing (issue #2). Check that the submission form's fields match `SUBMISSION.md` before submitting.

**Done when:** it is submitted and a confirmation screenshot is posted on issue #1.

### 3. AWS deploy, or confirm the fallback

This needs the team's AWS Educate / Learner Lab account. `docs/PLAN.md` set the AWS cutoff at the end of Nov 26, so this is already late. Decide quickly.

1. Start a Learner Lab session. Copy its AWS CLI credentials into `~/.aws/credentials`, on your machine only. **Never commit them, paste them in an issue, or put them in a script.**
2. Check the login: `aws sts get-caller-identity`.
3. Install the AWS SAM CLI. Then, from the repo root, run:

   ```bash
   npm install && bash scripts/deploy.sh
   ```

   The script:
   - builds everything
   - reads the account id and uses `arn:aws:iam::<account>:role/LabRole`
   - deploys twice, so CORS gets the real CloudFront domain
   - syncs the web app to S3

   See [`infra/README.md`](../infra/README.md).
4. Open the CloudFront URL it prints. Check that:
   - a website scan works
   - a demo scan works
   - approve works
   - download works
5. Try "Replay the attacks" on Lambda. This has never been checked: it needs `/tmp` writes and `node` child processes. If it fails, say so in `SUBMISSION.md` under honest limits. Do not hide it.
6. If it works, update these to say AWS is live, with the URL:
   - `docs/pitch/SUBMISSION.md` → "What is live"
   - `docs/pitch/DEMO_SCRIPT.md` at 2:45
   - `README.md`
   - this file
   - root `HANDOFF.md`

**If SAM is blocked on Educate,** fall back as `PLAN.md` says:

1. Do a console deploy: a Lambda function URL plus an S3 static site, using `LabRole`.
2. If that is blocked too, keep Vercel live and the video. `SUBMISSION.md` already says the AWS build is "prepared, not deployed", which is true.

**Done when:** AWS is live and the docs say so, or a decision to stay on Vercel is posted on issue #1.

### 4. Hindi review (needs a native speaker)

1. Read `apps/web/src/i18n/hi.ts`, which holds Hindi titles and reasons per check (`checkHi`, keyed by check id) and the dashboard labels (`ui`).
2. Fix wording that reads as machine-translated. Tech words people already say in English (API key, server) can stay in English.
3. Change only the Hindi text. Keep every key exactly as it is: the keys are check ids from the engine. No test covers this file, so check it in the app with the हिन्दी toggle on `/app?demo=1`.

**Done when:** a native speaker has signed off on issue #1.

### 5. Answer issue #2 ("needs from human")

Still open:

- the official rules link
- the team leader and members
- pilot sites or repos, with permission
- whether the AWS account allows CloudFormation/SAM

### 6. README screenshots (optional, nice for judges)

Take 2–3 screenshots of the live site and add them to `README.md`:

- the landing page
- Findings
- the Proof panel

Save them under `docs/img/`.

### 7. P1: `siidekick-guard` GitHub Action (optional)

A GitHub Action that runs the scan on a pull request and fails it on new critical findings. Put it in `action/`, which does not exist yet. Use `@siidekick/engine` directly; do not call the live API.

### 8. P1: score badge (optional)

`GET /api/scans/:id/badge.svg`. Records expire after 7 days, so a badge in someone's README would break. Prefer generating the badge from the Action (item 7).

### 9. Pilot (optional, needs consent)

1. Scan 3–5 repos the team owns, or has written permission to scan.
2. Record before and after scores in `docs/research/PILOT.md`.
3. Publish no names without consent.

## 7. Things only the repo owner can do

- **Live site.** A Vercel redeploy of https://siidekick.ashforge.cv. It runs on the owner's Vercel account and domain. To get your change live, push to `main` and ask the owner on issue #1.
- **Redis.** Live storage settings are Vercel environment variables on the owner's account. Never ask for them in an issue or chat.
- **Repo settings.** Owner and admin settings on GitHub.

## 8. Run it locally

Needs Node ≥ 20 and npm.

```bash
npm install
npm test                                   # engine + API + demo shop
```

```bash
npm run build -w @siidekick/engine         # needed before the dev server: it imports the engine's dist/, which is not in git
npm run dev -w @siidekick/api              # API on :8787, local file storage
npm run dev -w @siidekick/web              # web on :5173, proxies /api to :8787
```

CLI:

```bash
npm run scan:demo
npx tsx packages/engine/src/cli.ts scan <dir> --json
npx tsx packages/engine/src/cli.ts fix demo/vulnerable-app --out /tmp/fixed --verify --prove
```

**Gotchas:**

- **Port 8787 already taken.** Run `PORT=8790 npm run dev -w @siidekick/api` with `SIIDEKICK_API=http://localhost:8790 npm run dev -w @siidekick/web`.
- **Engine changes.** After changing `packages/engine`, rebuild it before running the dev API. Tests do not need the rebuild, because they import the engine's `src/`.
- **Fake `.env` on purpose.** `tools/siidekick-py/demo/vulnerable-shop/.env` is committed with fake values as a planted flaw. Leave it.
- **`tools/siidekick-py`.** A separate Python scanner. Nothing in the app uses it.

## 9. Rules for working on `main`

From [`AGENTS.md`](../AGENTS.md). They apply to people too.

- **Before every push,** run `git fetch origin && git log --oneline --stat HEAD..origin/main`, then rebase or merge. Never force-push `main`.
- **Commits.** Small commits straight to `main`. Run `npm test` first. Never skip, weaken or delete a test to make it pass.
- **The repo is public.** No real keys, tokens, `.env` files, emails or credentials. Test fixtures build fake keys at runtime; never write them as literals.
- **Website scans stay passive.** No attack traffic against sites we do not own.
- **Replay runs only the bundled demo shop.** Never run uploaded code on the server.
- **Claims.** No invented numbers, users or traction. Say "risk reduced", never "secure" or "unhackable".
- **Board.** GitHub Issues: #1 is the board, #2 is "needs from human", #3–#8 are workstreams.
