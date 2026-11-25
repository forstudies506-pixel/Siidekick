# Siidekick infrastructure (AWS SAM)

Provisions the HTTP API (Lambda + DynamoDB) and the static web site (S3 +
CloudFront) behind API Gateway. Everything here is AWS free-tier friendly at
demo traffic; Bedrock is not used.

## Prerequisites

- AWS CLI configured with credentials and a default region.
- AWS SAM CLI installed (`sam`).
- The CloudFront domain the dashboard will use (for CORS). If you don't have
  one yet, pass a placeholder and update the stack after the first deployment.

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
