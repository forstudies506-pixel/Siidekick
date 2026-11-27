# Siidekick

**Find the hole before an AI does.** Siidekick scans your source code (a GitHub repo or a project folder) for the security mistakes AI-assisted attackers look for first, and the ones AI-written code tends to ship. It explains each one in plain words and proposes small fixes that **add** code. Nothing lands until the owner approves it.

It reduces risk. It does not make anything "unhackable".

Built for the Campus to Cloud Hackathon (AWS, Techfest 2026-27) for small shops, student teams and colleges with no security engineer.

**Live on AWS:** https://d1ulntgja5qae0.cloudfront.net · **Demo in one click:** https://d1ulntgja5qae0.cloudfront.net/app?demo=1 · Mirror: https://siidekick.ashforge.cv

## What you can do

- **Scan a public GitHub repo, a folder, or the demo shop.** It looks for:
  - leaked secrets, unprotected admin routes, rate limiting
  - headers, CORS, SQL built from strings, input validation
  - vulnerable dependencies (via [OSV](https://osv.dev); only package names and versions are sent)
  - **AI-era mistakes:**
    - hallucinated packages
    - server keys in browser code
    - open Firebase or Supabase rules
    - JWTs decoded but never verified
- **Approve add-only fixes.** Each patch shows its diff and the diff guard's verdict. The guard refuses any patch that deletes or rewrites owner code. Two narrow exceptions are declared:
  - a hardcoded key line is swapped for an environment variable
  - a vulnerable version in `package.json` is bumped
- **See it measured.** Each approval rescans the patched copy. On the demo shop, "Verify & ship" boots the shop as scanned and as patched. It fires the same live attacks at both copies, each with a control request showing real users still get through.
- **Take it home.** You can download:
  - a zip of the patched files
  - one `.patch` per fix (`git apply -R` reverts it)
  - `SIIDEKICK_LOG.md`
  - a JSON or Markdown report
  - a share link
- **Use the हिन्दी toggle** for check titles and reasons.
- **Ask the AI, in your language** (AWS build): Amazon Bedrock explains any finding in English, Hindi, Bengali, Marathi, Tamil, Telugu, Gujarati or Kannada. An evidence check rejects any answer that names a CVE or version the scan did not find.
- **See how a bad package gets in**: the dependency path from `package-lock.json`, e.g. `your app → express → body-parser`.
- **Prove the fix** (AWS build): Step Functions runs your original and fixed code in a throwaway CodeBuild container (npm install, your tests, an independent npm audit). "Verified" only when tests pass and the flagged packages are gone. A fix that breaks your tests is caught as a regression.
- **Open a pull request** with the fixes and the verification evidence (GitHub scans; your token is used once, never stored).
- **Keep watching every pull request** with the [Siidekick GitHub Action](action/README.md): findings as annotations on the changed lines plus a job summary. The CI workflow Siidekick adds includes it.
- **See an attack fail:** on the demo shop, the replay fires a fake Razorpay payment at the app before and after the fix (accepted, then rejected with 400), with a correctly signed payment as the control.

The full list of checks comes from the engine: `curl -s https://siidekick.ashforge.cv/api/checks`.

## Run it locally

Needs Node ≥ 20.

```bash
npm install
npm test                                   # engine + API + demo shop tests
```

```bash
npm run build -w @siidekick/engine         # once, and after engine changes: the dev API imports the built engine
npm run dev -w @siidekick/api              # http://localhost:8787
npm run dev -w @siidekick/web              # http://localhost:5173 → open /app or /app?demo=1
```

CLI:

```bash
npm run scan:demo
npx tsx packages/engine/src/cli.ts fix demo/vulnerable-app --out /tmp/fixed --verify --prove
```

- `fix` is a dry run unless you pass `--out`, which writes a patched copy and leaves the original untouched.
- `--verify` runs your `npm test` after each patch and rolls back any patch that breaks it.
- `--prove` runs the attack replay. It works on the demo shop only.

## How it works

```
loadRepo → runScan (checks) → check.fix() → diff guard → apply → rescan → patch log / replay
```

| Part | What it does |
|---|---|
| `packages/engine` | Checks, diff guard, scanner, attack replay and CLI. |
| `apps/api` | One router served by a local server, AWS Lambda and Vercel. |
| `apps/web` | Vite + React: the landing page and the 4-step `/app`. |
| `demo/vulnerable-app` | A shop with planted flaws, vulnerable on purpose. |
| `infra` | AWS SAM: CloudFront, S3, API Gateway, Lambda, DynamoDB, Bedrock, Step Functions, CodeBuild, CloudWatch. |

The full walkthrough is in [docs/TEAM_HANDOFF.md](docs/TEAM_HANDOFF.md#3-how-it-works).

## Deploy

| Target | State |
|---|---|
| AWS | `bash scripts/deploy.sh` on a Free Tier account: CloudFront, S3, API Gateway, Lambda, DynamoDB, Bedrock, Step Functions, CodeBuild, CloudWatch, IAM. Step-by-step in [infra/README.md](infra/README.md); the why in [docs/BUILD_SUMMARY.md](docs/BUILD_SUMMARY.md). |
| Vercel | Mirror via `bash scripts/deploy-vercel.sh --prod` (scan engine only, no Bedrock or CodeBuild). |

## Honest limits

- The attack replay runs only on the bundled demo shop. Uploaded or GitHub code is never run.
- SQL built from strings is reported with the `?` rewrite shown, not auto-fixed.
- A dependency bump counts as proven only after you run `npm install` and your tests.
- Scan links expire after 7 days.
- The Hindi copy has not been reviewed by a native speaker yet.

## Docs

| Doc | What it covers |
|---|---|
| [TEAM_HANDOFF](docs/TEAM_HANDOFF.md) | **Start here:** what works, current numbers, what's left. |
| [ENGINEERING_LOG](docs/ENGINEERING_LOG.md) | What was built, commit by commit. |
| [API](docs/API.md) | HTTP endpoints. |
| [BRAIN](BRAIN.md) | Repo map. |
| [AGENTS](AGENTS.md) | Team rules. |
| [HANDOFF](HANDOFF.md) | Dev log for agent sessions. |
| [PLAN](docs/PLAN.md) | The 3-day finish plan. |
| [ROADMAP](docs/ROADMAP.md) | Full spec. |
| [Pitch](docs/pitch/) | Submission and demo script. |
