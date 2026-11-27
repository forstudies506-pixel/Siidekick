#!/usr/bin/env bash
# Deploys Siidekick to AWS (infra/template.yaml):
#   CloudFront + S3 (site), API Gateway + Lambda + DynamoDB (scans), Amazon Bedrock (explanations),
#   Step Functions + CodeBuild + S3 (verified fixes), CloudWatch (logs, alarms, dashboard), IAM.
#
# Works on a normal AWS Free Tier account (the stack creates least-privilege roles) and on an
# AWS Learner Lab account (it reuses the pre-made LabRole; Bedrock is not available there).
# Runs in bash on macOS, Linux, or Git Bash on Windows.
#
#   bash scripts/deploy.sh
#
# Optional env:
#   AWS_REGION    region (default: the AWS CLI's configured region, else ap-south-1). Free Plan accounts get one region.
#   STACK_NAME    CloudFormation stack name (default: siidekick)
#   ROLE_ARN      an existing role to use instead of creating roles ("" forces creating them)
#   ALARM_EMAIL   email for CloudWatch alarm notifications (confirm the subscription mail)
#   BEDROCK_MODEL_ID / BEDROCK_REGION   override the Bedrock model (default amazon.nova-lite-v1:0)
set -euo pipefail
cd "$(dirname "$0")/.."

need() {
  command -v "$1" >/dev/null 2>&1 || { echo "$1 is required. $2" >&2; exit 1; }
}
need aws "Install: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
need node "Install Node.js 20 or newer."
# The Windows SAM installer ships sam.cmd, which Git Bash does not find as plain 'sam'.
if command -v sam >/dev/null 2>&1; then SAM=sam
elif command -v sam.cmd >/dev/null 2>&1; then SAM=sam.cmd
else
  echo "AWS SAM CLI is required. Install: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html" >&2
  exit 1
fi

STACK_NAME="${STACK_NAME:-siidekick}"
AWS_REGION="${AWS_REGION:-$(aws configure get region 2>/dev/null || true)}"
AWS_REGION="${AWS_REGION:-ap-south-1}"
export AWS_REGION AWS_DEFAULT_REGION="${AWS_REGION}"

ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)" || {
  echo "AWS credentials are not set up. Run 'aws configure' (or 'aws sso login') first." >&2
  exit 1
}

if [[ -z "${ROLE_ARN+set}" ]]; then
  # Learner Lab accounts ship a LabRole and forbid creating roles; everywhere else, let the stack create them.
  if aws iam get-role --role-name LabRole >/dev/null 2>&1; then
    ROLE_ARN="arn:aws:iam::${ACCOUNT_ID}:role/LabRole"
  else
    ROLE_ARN=""
  fi
fi

echo "Account ${ACCOUNT_ID}, region ${AWS_REGION}, stack ${STACK_NAME}"
echo "Roles: ${ROLE_ARN:-created by the stack (least privilege)}"

npm run build -w @siidekick/engine
npx tsx scripts/bundle-demo.ts
npm run build -w @siidekick/api
npm run build -w @siidekick/web

OVERRIDES=()
[[ -n "${ROLE_ARN}" ]] && OVERRIDES+=("ExistingRoleArn=${ROLE_ARN}")
[[ -n "${ALARM_EMAIL:-}" ]] && OVERRIDES+=("AlarmEmail=${ALARM_EMAIL}")
[[ -n "${BEDROCK_MODEL_ID:-}" ]] && OVERRIDES+=("BedrockModelId=${BEDROCK_MODEL_ID}")
[[ -n "${BEDROCK_REGION:-}" ]] && OVERRIDES+=("BedrockRegion=${BEDROCK_REGION}")
PARAMS=()
if [[ ${#OVERRIDES[@]} -gt 0 ]]; then PARAMS=(--parameter-overrides "${OVERRIDES[@]}"); fi

# No 'sam build': apps/api/dist is already a self-contained bundle, and 'sam deploy' zips CodeUri as is.
"${SAM}" deploy \
  --template-file infra/template.yaml \
  --stack-name "${STACK_NAME}" \
  --region "${AWS_REGION}" \
  --capabilities CAPABILITY_IAM CAPABILITY_NAMED_IAM \
  --resolve-s3 \
  --no-confirm-changeset \
  --no-fail-on-empty-changeset \
  ${PARAMS[@]+"${PARAMS[@]}"}

output() {
  aws cloudformation describe-stacks --stack-name "${STACK_NAME}" \
    --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text
}

BUCKET_NAME="$(output BucketName)"
DISTRIBUTION_ID="$(output DistributionId)"
SITE_DOMAIN="$(output SiteUrl)"
API_URL="$(output ApiUrl)"

aws s3 sync apps/web/dist "s3://${BUCKET_NAME}" --delete
aws cloudfront create-invalidation --distribution-id "${DISTRIBUTION_ID}" --paths "/*" >/dev/null

echo
echo "API health (direct, before CloudFront finishes spreading):"
curl -s --max-time 20 "${API_URL}/api/health" || echo "(no answer yet)"
echo
echo
echo "Deployed. A new CloudFront distribution can take a few minutes to start serving."
echo "  Site:      https://${SITE_DOMAIN}"
echo "  Demo:      https://${SITE_DOMAIN}/app?demo=1"
echo "  Health:    https://${SITE_DOMAIN}/api/health"
echo "  Dashboard: $(output DashboardUrl)"
