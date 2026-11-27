# Siidekick infrastructure (AWS SAM)

Provisions the HTTP API (Lambda + DynamoDB) and the static web site (S3 +
CloudFront) behind API Gateway, plus the remediation pipeline described below.

## The remediation pipeline

Every code scan (GitHub, upload, demo) starts one Step Functions execution:

```
prepare ─► explain ─► propose ─► verify? ─► collect
  │          │           │         │           │
  │          │           │         │           └ change report (MD/HTML) + CycloneDX SBOM to S3, record marked done
  │          │           │         └ CodeBuild: npm ci (install scripts off), build, tests, Trivy — original and patched
  │          │           └ guard-checked patches; original + patched snapshots to S3
  │          └ Amazon Bedrock (Converse) explains the worst findings; answers must cite the evidence or are dropped
  └ re-reads the whole GitHub repo (up to 25,000 files / 80 MB of text) when the quick scan had to cap it
any failure ─► fail: record marked failed, SNS alert
```

| Service | What it does here |
|---|---|
| API Gateway (HTTP API) | Public API, throttled to 5 req/s (burst 20) |
| Lambda `siidekick-api` | Router + engine; starts the pipeline |
| Lambda `siidekick-pipeline` | The pipeline stages and the daily rescan (3 GB, 15 min) |
| Step Functions `siidekick-pipeline` | Orchestrates the stages, retries Lambda hiccups, catches failures |
| CodeBuild `siidekick-verify` | Isolated install/build/tests/Trivy (`infra/verify/runner.mjs`) |
| Amazon Bedrock | Grounded explanations (`BedrockModelId`, Converse API) |
| DynamoDB `siidekick-scans` | Scan records, 7-day TTL |
| S3 `siidekick-artifacts-*` | Snapshots, oversized records, verify results, reports, SBOMs; private, encrypted, TLS-only, 8-day expiry |
| S3 + CloudFront | The dashboard |
| EventBridge (daily rule) | Rechecks watched scans against new advisories |
| SNS `siidekick-alerts` | Pipeline failures and new findings (optional email) |
| CloudWatch | Alarms (pipeline failed, API errors, API 5xx), logs with 14-day retention, X-Ray traces |
| IAM | Learner Lab: `LabRole` everywhere. Elsewhere: least-privilege roles per function, state machine and CodeBuild |

Parameters (set as environment variables for `scripts/deploy.sh`):

- `BEDROCK_MODEL_ID` (default `amazon.nova-lite-v1:0`). Enable access to the model in the
  Bedrock console first. If Bedrock is unavailable the pipeline continues without explanations.
- `VERIFY_UNTRUSTED` (default `false`). CodeBuild runs repo code, so by default only the bundled
  demo shop is verified. The runner strips every AWS/CodeBuild variable from the commands that
  run repo code, but that is not a sandbox: before turning this on, deploy outside Learner Lab so
  CodeBuild gets its own role that can only read and write its `verify/` objects.
- `ALERT_EMAIL` (optional) subscribes an address to the SNS topic.

Dry-run the verify runner locally (no AWS needed): see the comment at the top of
`infra/verify/runner.mjs` and the `SIIDEKICK_AWS_SHIM` variable.

## Prerequisites

- AWS CLI configured with credentials and a default region.
- AWS SAM CLI installed (`sam`).
- The CloudFront domain the dashboard will use (for CORS). If you don't have
  one yet, pass a placeholder and update the stack after the first deployment.

## AWS Educate / Learner Lab

Learner Lab accounts cannot create IAM roles. The template accepts an existing
role through `ExistingRoleArn` instead of creating one. For most lab sessions,
use the pre-made `LabRole` ARN:

```text
arn:aws:iam::<account-id>:role/LabRole
```

The deploy script uses this role automatically. If `ROLE_ARN` is not set, it
gets the lab account ID and builds the LabRole ARN. Learner Lab session
credentials expire. Start a new lab session and refresh the AWS CLI credentials
before rerunning deployment.

Run deployment from the repository root:

```bash
scripts/deploy.sh
```

On the first deployment, `CLOUDFRONT_DOMAIN` has no real value yet, because
CloudFront is created in the same stack. The script deploys once with a
placeholder CORS origin, reads the `SiteUrl` output, and deploys again with that
domain so the API accepts requests from the site. Later runs find the domain
already set and deploy once.

## Build

From the repo root:

```bash
# 1. Build the engine (produces packages/engine/dist)
npm run build -w @siidekick/engine

# 2. Bundle the demo repo so /api/scans/demo works (documents the build flow)
npx tsx scripts/bundle-demo.ts
#    writes apps/api/src/demoRepo.generated.json

# 3. Build the API Lambda bundle
npm run build -w @siidekick/api
#    produces apps/api/dist/lambda.mjs (engine source inlined via tsconfig paths)
```

## Deploy

```bash
sam build
sam deploy --guided
```

When `sam deploy --guided` prompts, provide:

- Stack name: `siidekick`
- AWS region: your free-tier region
- `CloudFrontDomain`: the CloudFront distribution domain (or a placeholder)
- Confirm capabilities: `CAPABILITY_IAM` (the Lambda needs DynamoDB write access)

After the stack creates the CloudFront distribution, note the `SiteUrl` output.
If you used a placeholder for `CloudFrontDomain`, re-run `sam deploy` with the
real CloudFront domain so CORS allows the dashboard origin.

## Publish the web build

```bash
aws s3 sync apps/web/dist s3://<BucketName> --delete
aws cloudfront create-invalidation --distribution-id <dist-id> --paths "/*"
```

`<BucketName>` and the distribution id come from the stack outputs.

## Stack outputs

| Output | Meaning |
|---|---|
| `ApiUrl` | API Gateway HTTP API endpoint (e.g. `https://abc.execute-api.r.amazonaws.com`) |
| `SiteUrl` | CloudFront distribution domain name |
| `BucketName` | Private S3 bucket holding the web build |

## Cost note

All resources stay within the AWS free tier at demo traffic:

- Lambda: 1M requests/month and 400,000 GB-seconds free.
- DynamoDB: 25 GB storage + 25 WCU / 25 RCU (on-demand free tier) free.
- S3: 5 GB storage free.
- CloudFront: 1 TB/month outbound free.
- API Gateway HTTP API: 1M requests/month free.

Bedrock is intentionally not used (avoids per-invocation model cost). Scan
records are TTL'd after 7 days via `expiresAt` so DynamoDB storage stays small.

## Local development

```bash
npm run dev -w @siidekick/api   # node:http on :8787 (STORAGE=local, .data/scans)
```

The web dashboard's Vite proxy points at `:8787` (`VITE_MOCK=1` uses mock data).
