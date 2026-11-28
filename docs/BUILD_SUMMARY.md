# Siidekick: build summary

Team **Schrödinger's Code** · Live: https://d1ulntgja5qae0.cloudfront.net · Code: https://github.com/forstudies506-pixel/Siidekick

**Catch the breach before it ships. Making Cybersecurity accessible to all.** Siidekick finds the security holes in a small team's source code (Node.js repos first), explains each one in the owner's own language, proposes small fixes that only add code, and proves each fix in an isolated AWS build before anyone merges it.

## The AWS architecture

```
Browser ──► CloudFront ──► S3 (React site, private, Origin Access Control)
               │
               └─ /api/* ──► API Gateway (HTTP API, throttled) ──► Lambda "siidekick-api" (Node 22, arm64)
                                                                      │  scan engine (39 checks, OSV.dev), 2 GB
                                                                      ├─► DynamoDB: scan records (gzipped, 7-day TTL)
                                                                      ├─► S3 scans/<id>.json.gz: records too big for one item
                                                                      ├─► Amazon Bedrock (Amazon Nova): explanations in 8 Indian languages
                                                                      └─► S3 jobs/<id>/source.zip ─► Step Functions "siidekick-verify"
                                                                                                        │
                                                                     CodeBuild "siidekick-verify" ◄─────┤ 1. isolated build
                                                                     (before + after: npm install,      │
                                                                      npm test, npm audit)              │
                                                                                                        ▼
                                                                     Lambda "siidekick-evaluate" ── 2. trust rule ─► S3 verdict.json
CloudWatch: log groups (14 days), audit trail, 2 alarms ─► SNS email, one dashboard for the whole pipeline
IAM: one least-privilege role per component
```

Everything is one AWS SAM template (`infra/template.yaml`) and one command (`bash scripts/deploy.sh`).

## AWS services and why each one

| Service | What it does in Siidekick | Why this service |
|---|---|---|
| **Amazon CloudFront** | Serves the site and routes `/api/*` to the API on one HTTPS domain, with HSTS, CSP and frame-blocking headers on every response. | One origin means no CORS to get wrong. A security tool has to pass its own checks. |
| **Amazon S3** | Private bucket for the site (only CloudFront can read it), and an encrypted artefacts bucket for verification jobs (source zips, build output, verdicts) and for scan records too big for one DynamoDB item (`scans/`). Both prefixes expire after 7 days. | Cheap and durable, with no practical size limit, so large repos work. Lifecycle rules delete repo copies automatically, so nothing lingers. |
| **Amazon API Gateway (HTTP API)** | Public API, throttled to 5 requests/s (burst 20). | The cheapest API Gateway type. Throttling caps the cost of an unauthenticated public tool. |
| **AWS Lambda** | `siidekick-api` (2 GB, arm64, Node 22) runs the scan engine, the diff guard, Bedrock calls and job starts. `siidekick-evaluate` applies the trust rule after each build. | Scans are short and bursty, so pay-per-request fits. arm64 is cheaper per GB-second; 2 GB gives enough CPU to scan a 2,800-file repo in about 11 s. |
| **Amazon DynamoDB** | Scan records, gzipped, with a 7-day TTL. A record bigger than one item (about 380 KB gzipped) is stored in S3 and DynamoDB keeps a pointer. | On-demand pricing costs nothing when idle. TTL deletes old scans without a cron job. |
| **Amazon Bedrock (Amazon Nova Lite)** | Explains any finding in English, Hindi, Bengali, Marathi, Tamil, Telugu, Gujarati or Kannada: what could happen, what to do, the options and their trade-offs, and what the evidence cannot tell. | A first-party model runs on Free Tier credits without a Marketplace subscription, called in the stack's own region (Free Plan accounts get one region; ours is Sydney). |
| **AWS Step Functions** | Runs the verification workflow: isolated build, then evaluate, with retries and error capture. | Waits on CodeBuild natively (`startBuild.sync`), so no Lambda sits idle polling. Every run's history is visible. |
| **AWS CodeBuild** | A throwaway container runs `npm install`, the project's own `npm test` and `npm audit` on both the original and the fixed copy. | A real, disposable build environment with CPU, memory, time (15 min) and concurrency (2) limits. Lambda is the wrong place to run untrusted builds. |
| **Amazon CloudWatch** | Log groups (14-day retention), a structured audit trail (`audit` events: scan created, AI explain, verify start and verdict, PR opened), alarms on API errors and failed workflows, and a dashboard covering Lambda, Bedrock, Step Functions and CodeBuild. | One place to see whether the pipeline is healthy and what it did. |
| **Amazon SNS** | Emails the team when a CloudWatch alarm fires. | The simplest way to get an alarm to a person. |
| **AWS SAM / CloudFormation** | The whole stack is one template (`infra/template.yaml`), deployed with `bash scripts/deploy.sh`. | Repeatable: the same command rebuilds everything, and every change is reviewed as code. |
| **AWS IAM** | Separate least-privilege roles for the API, evaluate, the state machine and the build. | The build runs untrusted code, so its role can only read its own job's zip and write its own output and logs. |

Not used: **Amazon ECR**. The managed CodeBuild image already has Node 22, and a custom image would add storage and upkeep without improving the demo.

## Limits and how they were chosen

| | Limit | Why |
|---|---|---|
| GitHub scan | 3,000 files, 10 MB of text (25 MB compressed tarball) | Measured: `nestjs/nest` (2,824 files) scans in 11.4 s on the live site, inside API Gateway's 30 s limit. Past the cap, the scan still runs on what fits and says how many files it left out. |
| Folder upload | 3,000 files, 4.5 MB | The upload is one request, and Lambda accepts at most 6 MB per request. Larger repos are pointed to the GitHub scan. |
| Stored scan | DynamoDB up to ~380 KB gzipped, otherwise S3 | `fastify/fastify` (a 1.1 MB gzipped record) previously failed with "too large to store"; it now lands in S3. |
| `.siidekickignore` | `.gitignore`-style patterns | Owners leave out demos, fixtures and generated files. Ignored files are counted in the report, never hidden silently. |

## The interface

A React 19 single-page app with a liquid-glass design over a live LED field (WebGL, capped at 30 fps), built to stay smooth on high-refresh screens:
- **Landing page:** a scroll story. The title morphs into a glass pane that plays a forged payment being caught: found, fixed and proven on AWS.
- **The app:** each step opens with a summary panel containing an **LED check board**, one light per check (failing lights by severity, then passing, then not applicable). Checks fixed by your approvals turn green and pulse.
- **Colour:** one colour per meaning (saffron for actions, one red at four strengths for risk, green for resolved).
- **Motion:** a single system (one easing curve, three durations) that turns off entirely for people who prefer reduced motion.

## Three ideas that make it different

1. **The AI never writes your code.** Fixes are deterministic templates behind a *diff guard* that refuses any patch that deletes or rewrites owner code. Bedrock only explains.
2. **The AI cannot invent facts.** Every Bedrock answer goes through an *evidence check*: any CVE or GHSA id, or any version number, that is not in the scan evidence gets the answer retried once, then rejected and labelled. This is the same idea as the diff guard, applied to text.
3. **"Fixed" means proven.** The trust rule in `apps/api/src/verify.ts` labels a fix **verified** only when the fixed copy installs, the project's own tests pass, *and* an independent advisory source (`npm audit`, separate from the OSV.dev data the scan uses) no longer reports the flagged packages. A fix that breaks tests that passed before is flagged as a **regression**. A project with no tests is **inconclusive**, never verified.

## Built for India: the Bharat Pack and the India lens

Generic scanners do not know how Indian apps go wrong. Siidekick checks for the mistakes that show up in Indian student, college and small-business code:

- **Payments that are never verified.** A Razorpay `razorpay_payment_id` accepted without checking `razorpay_signature`, or a Paytm/UPI callback that trusts `STATUS === "TXN_SUCCESS"` from the request. Anyone can then get a fest pass, merch or a fee receipt with a fake payment. The fix adds a constant-time HMAC helper; the check keeps failing until the route calls it.
- **Payment and SMS keys in code,** named by vendor (Razorpay, Paytm, PhonePe, Cashfree, PayU, Instamojo, CCAvenue, MSG91, Fast2SMS, Textlocal), with the money risk explained, and moved to environment variables automatically.
- **Aadhaar and PAN numbers** in code or test data (Aadhaar candidates must pass UIDAI's Verhoeff checksum, which keeps phone numbers and ids out), and identity data written to logs. Evidence is always masked.
- **OTP logins** that return the OTP in the response, log it, or make it with `Math.random`.

The **India lens** at the top of every scan puts findings in Indian context, with sources:
- how many failing checks can expose personal data or accounts: relevant to the DPDP Act's "reasonable security safeguards", whose penalty goes up to ₹250 crore (DPDP Rules notified 14 November 2025);
- whether the repo is ready for CERT-In's 6-hour incident reporting (the incident playbook Siidekick adds now has an India reporting section);
- what the India-specific checks found.

It is context for prioritising, not legal advice: whether a club or shop is covered is a legal question.

## Impact, measured

The Verify & ship step ends with an **Impact** section drawn only from real data: the score before and after (from a rescan), failing checks by severity, `npm audit` counts from the CodeBuild run, the dependency tree turning from red to green, lines added and removed per fix, the AWS run's timeline, and **build metrics measured in CodeBuild** on both copies: installed packages, `node_modules` size, install time, test time. These are shown even when they get worse: the demo's express upgrade takes it from 51 to 69 installed packages and 5.7 to 6.9 MB, while vulnerable packages fall from 8 to 0. A downloadable impact card (PNG) carries the same numbers. A chart that has no data yet says so; nothing is estimated.

## Dependency intelligence

Siidekick rebuilds the dependency graph from `package-lock.json` (each entry's declared dependencies, resolved the way Node resolves them) and shows how each vulnerable package gets in: `your app → express → body-parser`. A flat folder listing cannot show this, because npm hoists packages.

## Security of the platform itself

- Repository code is treated as untrusted. The build skips install scripts (`--ignore-scripts`) and unsets the container's AWS credential variables before any repo code runs. The build role can reach only its own job's files.
- The control plane (API, records, orchestration) is separate from the untrusted build environment.
- GitHub tokens for pull requests are used once and never stored or logged. Pull requests are only proposed; a human merges.
- Everything is encrypted at rest and both buckets are private. The artefacts bucket refuses non-TLS requests.
- **Honest limit:** the build has internet access so `npm install` can reach the registry. Removing it would need a VPC with a NAT gateway, which is not free. We limit what a hostile build could do instead: no credentials, short timeout, small compute, and a role scoped to its own files.

## Measured

| What | Result |
|---|---|
| Demo shop score, before → after approving the 15 guard-passed fixes | 33 → 62 (failing checks 23 → 12; +209 / −8 lines) |
| Failing checks that can expose personal data (DPDP-relevant) | 11 → 6 |
| Attack replay on the live shop | 6 of 7 attacks blocked; fake Razorpay payment 200 → 400, while a correctly signed payment still gets its pass; patched app's tests 4/4 |
| Demo shop: vulnerable packages found by OSV.dev, with dependency paths | 8 (2 direct, 6 transitive via express) |
| Same packages reported by `npm audit` before the fix | 8 of 8 (independent source agrees) |
| After the approved fixes, on AWS CodeBuild (Node 22): `npm audit` | 0 vulnerable packages, tests passing before and after → **verified** |
| Verification workflow on AWS, end to end (Step Functions → CodeBuild → evaluate) | 69–74 s across runs on 2026-11-28 in ap-southeast-2, most of it CodeBuild start-up |
| Bedrock explanation (Nova Lite, Hindi, grounded) | answered live on the first call |
| Large public repos on the live site (scan, then drafting patches) | `fastify/fastify`: 7.1 s, then 2.1 s · `nestjs/nest` (2,824 files): 11.4 s, then 5.4 s |
| Siidekick scanning its own repo (with `.siidekickignore` for its demo shops, rule definitions and fixtures) | 94/100, no critical findings; its own fix drafter added this repo's CI workflow and incident playbook |
| Automated tests | 204 engine + 60 API + 4 demo-app (TypeScript) + 15 Python, all passing |

Live deployment: https://d1ulntgja5qae0.cloudfront.net (Sydney, ap-southeast-2; Free Plan accounts get one region).

## Cost (Free Tier)

At demo traffic the stack stays within free allowances or a few cents of credits: Lambda and API Gateway (1M requests), DynamoDB on demand, S3 storage of a few MB, CloudFront (1 TB), Step Functions (4,000 transitions/month), CodeBuild general1.small (about 2 minutes per verification), Nova Lite (a fraction of a cent per explanation; explanations are cached per finding and language). Per-instance rate limits cap Bedrock (30/min) and builds (6/min), and CodeBuild runs at most 2 builds at once.
