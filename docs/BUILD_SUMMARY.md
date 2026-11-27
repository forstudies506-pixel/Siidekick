# Siidekick: build summary

**Making cybersecurity accessible to all and safe for all.** Siidekick finds the security holes in a small team's source code (Node.js repos first), explains each one in the owner's own language, proposes small fixes that only add code, and proves each fix in an isolated AWS build before anyone merges it.

## The AWS architecture

```
Browser ──► CloudFront ──► S3 (React site, private, Origin Access Control)
               │
               └─ /api/* ──► API Gateway (HTTP API, throttled) ──► Lambda "siidekick-api" (Node 22, arm64)
                                                                      │  scan engine (36 checks, OSV.dev)
                                                                      ├─► DynamoDB: scan records (gzipped, 7-day TTL)
                                                                      ├─► Amazon Bedrock (Amazon Nova): explanations in 8 Indian languages
                                                                      └─► S3 jobs/<id>/source.zip ─► Step Functions "siidekick-verify"
                                                                                                        │
                                                                     CodeBuild "siidekick-verify" ◄─────┤ 1. isolated build
                                                                     (before + after: npm install,      │
                                                                      npm test, npm audit)              │
                                                                                                        ▼
                                                                     Lambda "siidekick-evaluate" ── 2. trust rule ─► S3 verdict.json
CloudWatch: log groups (14 days), audit trail, 2 alarms (+ optional SNS email), one dashboard for the whole pipeline
IAM: one least-privilege role per component
```

Everything is one AWS SAM template (`infra/template.yaml`) and one command (`bash scripts/deploy.sh`).

## AWS services and why each one

| Service | What it does in Siidekick | Why this service |
|---|---|---|
| **Amazon CloudFront** | Serves the site and routes `/api/*` to the API on one HTTPS domain, with HSTS, CSP and frame-blocking headers on every response. | One origin means no CORS to get wrong. A security tool has to pass its own checks. |
| **Amazon S3** | Private bucket for the site (only CloudFront can read it), and an encrypted artefacts bucket for verification jobs (source zips, build output, verdicts) that expire after 7 days. | Cheap and durable. Lifecycle rules delete repo copies automatically, so nothing lingers. |
| **Amazon API Gateway (HTTP API)** | Public API, throttled to 5 requests/s (burst 20). | The cheapest API Gateway type. Throttling caps the cost of an unauthenticated public tool. |
| **AWS Lambda** | `siidekick-api` runs the scan engine, the diff guard, Bedrock calls and job starts. `siidekick-evaluate` applies the trust rule after each build. | Scans are short and bursty, so pay-per-request fits. arm64 is cheaper per GB-second. |
| **Amazon DynamoDB** | Scan records, gzipped, with a 7-day TTL. | On-demand pricing costs nothing when idle. TTL deletes old scans without a cron job. |
| **Amazon Bedrock (Amazon Nova Lite)** | Explains any finding in English, Hindi, Bengali, Marathi, Tamil, Telugu, Gujarati or Kannada: what could happen, what to do, the options and their trade-offs, and what the evidence cannot tell. | A first-party model runs on Free Tier credits without a Marketplace subscription, called in the stack's own region (Free Plan accounts get one region; ours is Sydney). |
| **AWS Step Functions** | Runs the verification workflow: isolated build, then evaluate, with retries and error capture. | Waits on CodeBuild natively (`startBuild.sync`), so no Lambda sits idle polling. Every run's history is visible. |
| **AWS CodeBuild** | A throwaway container runs `npm install`, the project's own `npm test` and `npm audit` on both the original and the fixed copy. | A real, disposable build environment with CPU, memory, time (15 min) and concurrency (2) limits. Lambda is the wrong place to run untrusted builds. |
| **Amazon CloudWatch** | Log groups (14-day retention), a structured audit trail (`audit` events: scan created, AI explain, verify start and verdict, PR opened), alarms on API errors and failed workflows, and a dashboard covering Lambda, Bedrock, Step Functions and CodeBuild. | One place to see whether the pipeline is healthy and what it did. |
| **AWS IAM** | Separate least-privilege roles for the API, evaluate, the state machine and the build. | The build runs untrusted code, so its role can only read its own job's zip and write its own output and logs. |

Not used: **Amazon ECR**. The managed CodeBuild image already has Node 22, and a custom image would add storage and upkeep without improving the demo.

## Three ideas that make it different

1. **The AI never writes your code.** Fixes are deterministic templates behind a *diff guard* that refuses any patch that deletes or rewrites owner code. Bedrock only explains.
2. **The AI cannot invent facts.** Every Bedrock answer goes through an *evidence check*: any CVE or GHSA id, or any version number, that is not in the scan evidence gets the answer retried once, then rejected and labelled. This is the same idea as the diff guard, applied to text.
3. **"Fixed" means proven.** The trust rule in `apps/api/src/verify.ts` labels a fix **verified** only when the fixed copy installs, the project's own tests pass, *and* an independent advisory source (`npm audit`, separate from the OSV.dev data the scan uses) no longer reports the flagged packages. A fix that breaks tests that passed before is flagged as a **regression**. A project with no tests is **inconclusive**, never verified.

## Dependency intelligence

Siidekick rebuilds the dependency graph from `package-lock.json` (each entry's declared dependencies, resolved the way Node resolves them) and shows how each vulnerable package gets in: `your app → express → body-parser`. A flat folder listing cannot show this, because npm hoists packages.

## Security of the platform itself

- Repository code is treated as untrusted. The build skips install scripts (`--ignore-scripts`) and unsets the container's AWS credential variables before any repo code runs. The build role can reach only its own job's files.
- The control plane (API, records, orchestration) is separate from the untrusted build environment.
- GitHub tokens for pull requests are used once and never stored or logged. Pull requests are only proposed; a human merges.
- Everything is encrypted at rest and both buckets are private. The artefacts bucket refuses non-TLS requests.
- **Honest limit:** the build has internet access so `npm install` can reach the registry. Removing it would need a VPC with a NAT gateway, which is not free. We limit what a hostile build could do instead: no credentials, short timeout, small compute, and a role scoped to its own files.

## Measured so far (record more during testing)

| What | Result |
|---|---|
| Demo shop: vulnerable packages found by OSV.dev, with dependency paths | 8 (2 direct, 6 transitive via express) |
| Same packages reported by `npm audit` before the fix | 8 of 8 (independent source agrees) |
| After the approved fixes, on AWS CodeBuild (Node 22): `npm audit` | 0 vulnerable packages, tests passing before and after → **verified** |
| Verification workflow on AWS, end to end (Step Functions → CodeBuild → evaluate) | 69 s, measured 2026-11-28 in ap-southeast-2 |
| Bedrock explanation (Nova Lite, Hindi, grounded) | answered live on the first call |
| Automated tests | 202 engine + 101 API + 4 demo-app, all passing |

Live deployment: https://d1ulntgja5qae0.cloudfront.net (Sydney, ap-southeast-2; Free Plan accounts get one region).

## Cost (Free Tier)

At demo traffic the stack stays within free allowances or a few cents of credits: Lambda and API Gateway (1M requests), DynamoDB on demand, S3 storage of a few MB, CloudFront (1 TB), Step Functions (4,000 transitions/month), CodeBuild general1.small (about 2 minutes per verification), Nova Lite (a fraction of a cent per explanation; explanations are cached per finding and language). Per-instance rate limits cap Bedrock (30/min) and builds (6/min), and CodeBuild runs at most 2 builds at once.
