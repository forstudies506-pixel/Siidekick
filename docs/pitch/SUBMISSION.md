# Hackathon Submission

## Title

Siidekick

## One-line pitch

Find the hole before an AI does: scan any website or GitHub repo, get plain-language findings, approve add-only fixes, and watch the same attacks fail against the patched app.

## 150-word description

Attack tooling is now point-and-click, and AI-written code repeats the same mistakes. Siidekick is built for the small shops, student teams and colleges that face both without a security engineer.

Paste a website address and Siidekick reads it passively, the way any browser does: TLS, headers, cookies, forms, scripts, and AI keys called from the browser. Paste a GitHub repo and it reads the code for leaked secrets, open endpoints, hallucinated packages, open Firebase or Supabase rules and unverified login tokens.

Each finding comes with an add-only patch. A diff guard refuses any patch that deletes or rewrites owner code, and nothing lands until the owner approves it. The approved fixes are rescanned, and on the demo shop Siidekick boots the app before and after and fires the same attacks at both, with a control request proving real users still get through.

## What is live

- Web app: https://siidekick.ashforge.cv (Vercel). Scan any site or public GitHub repo; no sample data.
- AWS build in the repo: Lambda + API Gateway + DynamoDB + S3/CloudFront via AWS SAM (`infra/template.yaml`). Not deployed yet; it needs the team's Learner Lab credentials.
- CLI: `siidekick scan <dir>`, `siidekick fix <dir> --out <dir> --verify`, and `fix --prove` for the attack replay on the demo shop.

Honest limits: scan records are kept 7 days on a free 30 MB Redis database, so old share links expire. The attack replay runs only on the bundled demo shop, never on uploaded code. SQL built from strings is reported, not auto-fixed.

## Tech stack

- TypeScript, Node.js 22
- React 19 and Vite
- Vitest
- Vercel (live), AWS SAM (prepared)

## AWS services (prepared build)

- AWS Lambda
- Amazon API Gateway HTTP API
- Amazon DynamoDB (records expire after seven days)
- Amazon S3
- Amazon CloudFront
- AWS IAM: the Learner Lab's existing LabRole. No Bedrock or other paid model service.

## Repo link

https://github.com/forstudies506-pixel/Siidekick

## Demo video link

TODO(team)

## Team names

TODO(team)
