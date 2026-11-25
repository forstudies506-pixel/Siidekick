#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v aws >/dev/null 2>&1; then
  echo "AWS CLI is required. Install it from https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html" >&2
  exit 1
fi

if ! command -v sam >/dev/null 2>&1; then
  echo "AWS SAM CLI is required. Install it from https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html" >&2
  exit 1
fi

ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
ROLE_ARN="${ROLE_ARN:-arn:aws:iam::${ACCOUNT_ID}:role/LabRole}"
# CloudFront's domain is only known after the first deploy, so a first run deploys with a placeholder and redeploys below.
CLOUDFRONT_DOMAIN="${CLOUDFRONT_DOMAIN:-placeholder.invalid}"

npm run build -w @siidekick/engine
npx tsx scripts/bundle-demo.ts
npm run build -w @siidekick/api
npm run build -w @siidekick/web

sam build -t infra/template.yaml
deploy() {
  sam deploy \
    --stack-name siidekick \
    --capabilities CAPABILITY_IAM \
    --resolve-s3 \
    --no-fail-on-empty-changeset \
    --parameter-overrides \
    "CloudFrontDomain=$1" \
    "ExistingRoleArn=${ROLE_ARN}"
}

output() {
  aws cloudformation describe-stacks --stack-name siidekick \
    --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text
}

deploy "${CLOUDFRONT_DOMAIN}"
SITE_DOMAIN="$(output SiteUrl)"
if [[ "${SITE_DOMAIN}" != "${CLOUDFRONT_DOMAIN}" ]]; then
  echo "Redeploying so CORS allows https://${SITE_DOMAIN}"
  deploy "${SITE_DOMAIN}"
fi

OUTPUTS="$(aws cloudformation describe-stacks \
  --stack-name siidekick \
  --query 'Stacks[0].Outputs' \
  --output json)"

BUCKET_NAME="$(output BucketName)"

aws s3 sync apps/web/dist "s3://${BUCKET_NAME}" --delete

echo "Deployed stack: siidekick"
echo "${OUTPUTS}"
