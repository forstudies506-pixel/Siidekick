# Deploying Siidekick to AWS

One SAM template (`template.yaml`) and one script (`../scripts/deploy.sh`). What gets created and why is in [docs/BUILD_SUMMARY.md](../docs/BUILD_SUMMARY.md).

## 1. One-time setup (Windows)

Run these in PowerShell:

```powershell
winget install -e --id Amazon.AWSCLI
winget install -e --id Amazon.SAM-CLI
```

Close and reopen the terminal, then check:

```powershell
aws --version; sam --version; node --version
```

Node must be 20 or newer. Git for Windows provides Git Bash, which runs the deploy script.

## 2. AWS account and credentials

1. Use a **normal AWS account** (the hackathon's Free Tier account, created with your Builder ID). Learner Lab works for the basic site but has no Bedrock.
2. **Set a budget alert first**: Billing console → Budgets → "Zero spend" or a small monthly budget.
3. Create an access key for deploying: IAM → Users → (your admin user) → Security credentials → Create access key → "Command Line Interface". Do not use the root user's keys.
4. Store it locally:

```powershell
aws configure
```

When prompted, enter the key ID and secret, the region your account is assigned (Free Plan accounts get one: check the console's region menu; ours is `ap-southeast-2`, Sydney), and output `json`. The key stays on your machine.

5. **Bedrock:** Amazon Nova models are enabled by default on new accounts. To check, open the Bedrock console in your region → Model catalog → Amazon Nova Lite → try it in the playground once.

## 3. Deploy

From the repo root, in Git Bash:

```bash
npm install
npm test
ALARM_EMAIL=you@example.com bash scripts/deploy.sh
```

`ALARM_EMAIL` is optional; confirm the subscription email AWS sends. The script builds everything, deploys the stack, uploads the site, invalidates CloudFront, and prints:

- `Site`: the CloudFront URL to submit (`https://dxxxx.cloudfront.net`)
- `Demo`: `…/app?demo=1`
- `Health`: should show `"storage":"dynamo"`, `"ai":{…}` and `"verify":true`
- `Dashboard`: the CloudWatch dashboard

A new CloudFront distribution takes about 5–15 minutes to serve. The first deploy takes about 10 minutes; later ones are faster. Re-run the same command after any code change.

## 4. Smoke test after deploying

1. `…/api/health`: `storage` is `dynamo`, `features.ai` is not null, `features.verify` is true.
2. `…/app?demo=1`, then Findings → open "Dependency vulnerability audit": the "How it gets in" chain shows, and "Explain simply in हिन्दी" returns a Hindi explanation.
3. Fixes → approve all → Verify & ship → **Run verification**: within 1–3 minutes it should read **Verified** with 8/8 packages clean.
4. In the AWS console: Step Functions → `siidekick-verify` shows the run; CodeBuild → `siidekick-verify` shows the build log; CloudWatch → Dashboards → `siidekick`.
5. Pull request: push `demo/vulnerable-app` to a public GitHub repo of yours, scan its URL, approve the fixes, verify, then paste a fine-grained token (that repo only; Contents, Pull requests and Workflows: read and write; Workflows because the CI fix adds .github/workflows/siidekick.yml).

## Troubleshooting

| Symptom | Fix |
|---|---|
| `explain` says Bedrock did not answer / AccessDenied | Open Nova Lite once in the Bedrock console in your region. If Nova is not on demand in your region, try its inference profile, e.g. `BEDROCK_MODEL_ID=apac.amazon.nova-lite-v1:0 bash scripts/deploy.sh` (paid-plan accounts only: profiles route to other regions) |
| Verification ends in "Build error" | CodeBuild console → `siidekick-verify` → the latest build's log. New accounts sometimes have a CodeBuild concurrency quota of 0 or 1 until the account is verified; request an increase in Service Quotas if builds stay queued. |
| Stack fails with "already exists" (bucket, log group) | A previous failed stack left it behind. Delete the leftover in the console, or deploy with `STACK_NAME=siidekick2`. |
| Site shows the old version | The script invalidates CloudFront; wait a minute and hard-refresh. |
| `sam: command not found` in Git Bash | The script falls back to `sam.cmd`. Otherwise reopen the terminal after installing. |

## Remove everything

```powershell
sam delete --stack-name siidekick --region ap-southeast-2
```

Empty the two buckets (`siidekick-web-…`, `siidekick-artifacts-…`) first if the delete complains.

## Learner Lab

Labs cannot create IAM roles, so the script passes the lab's `LabRole` to every component. Bedrock is not available in labs, so explanations will show as unavailable. Lab sessions expire; refresh the credentials and re-run the script.
