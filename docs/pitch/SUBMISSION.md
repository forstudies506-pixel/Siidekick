# Hackathon Submission

## Title

Siidekick

## One-line pitch

Cybersecurity for everyone: scan your GitHub repo, get findings explained in your own language, approve add-only fixes, and see each fix proven in an isolated AWS build before you merge it.

## 150-word description

Attack tooling is now point-and-click, and AI-written code repeats the same mistakes. Siidekick is built for the small shops, student teams and colleges that face both without a security engineer.

Paste a GitHub repo (or upload a folder) and Siidekick reads the code for leaked secrets, open endpoints, vulnerable dependencies and how they get in, hallucinated packages, open Firebase or Supabase rules and unverified login tokens. Amazon Bedrock explains each finding in the owner's language.

Each finding comes with an add-only patch. A diff guard refuses any patch that deletes or rewrites owner code, and nothing lands until the owner approves it. The approved fixes then run in a throwaway AWS CodeBuild container, original and fixed side by side: install, the project's own tests, and an independent npm audit. A fix is marked verified only when the tests pass and the flagged packages are gone, and Siidekick can open a pull request carrying that evidence.

## What is live

- **AWS (submission URL):** https://d1ulntgja5qae0.cloudfront.net (Sydney, ap-southeast-2). Demo in one click: https://d1ulntgja5qae0.cloudfront.net/app?demo=1
- Mirror on Vercel: https://siidekick.ashforge.cv (scan engine only; no Bedrock or CodeBuild there).
- CLI: `siidekick scan <dir>`, `siidekick fix <dir> --out <dir> --verify`, `fix --prove`.

Honest limits: the verification build needs internet access for `npm install` (it gets no credentials, a 15-minute cap and a role scoped to its own files). AI explanations are checked against the scan evidence but are still AI; the scanner text stays the source of truth. Records and job files expire after 7 days.

## Tech stack

- TypeScript, Node.js 22, React 19, Vite, Vitest (307 automated tests)
- AWS SAM (one template, one deploy script)

## AWS services (live build)

Full reasoning in `docs/BUILD_SUMMARY.md`.

- **Amazon CloudFront + Amazon S3**: the site on one HTTPS domain with security headers. The S3 bucket is private behind Origin Access Control.
- **Amazon API Gateway (HTTP API) + AWS Lambda**: the scan engine (36 checks), diff guard and job starts, throttled.
- **Amazon DynamoDB**: scan records with a 7-day TTL.
- **Amazon Bedrock (Amazon Nova Lite)**: explains findings in 8 Indian languages; every answer is checked against the scan evidence so it cannot invent a CVE or version.
- **AWS Step Functions + AWS CodeBuild**: verified fixes. Before and after copies each get npm install, the project's own tests and an independent npm audit in a throwaway build; a Lambda applies the trust rule.
- **Amazon S3 (artefacts)**: encrypted job inputs, outputs and verdicts, expiring after 7 days.
- **Amazon CloudWatch**: log groups, an audit trail, alarms and one dashboard for the whole pipeline.
- **AWS IAM**: a least-privilege role per component; the untrusted build's role reaches only its own job files.

## Repo link

https://github.com/forstudies506-pixel/Siidekick

## Demo video link

TODO(team)

## Team

**Schrödinger's Code**, a part of Echelon Systems Architecture.

TODO(team): member names
