# Hackathon Submission

## Title

Siidekick

## One-line pitch

Plain-language repository scans with owner-approved, reversible patches.

## 150-word description

Siidekick helps small teams understand and reduce web security risks. It scans a small repository, explains findings in plain language and proposes predictable patches for known checks. Every proposed change is shown before it is applied. The diff guard rejects patches that delete owner code or make unrelated edits, and the owner approves each patch separately.

The product can rescan after fixes and show the score change. The download includes patched files, a unified diff for each approved patch and a log with a direct revert command. Patch verification runs the owner's test suite locally. Siidekick never runs uploaded code on the server.

The system uses a Lambda API behind API Gateway, DynamoDB for scan state and an S3 and CloudFront architecture for the private web application. It uses the AWS free-tier services available to a Learner Lab account and does not use Bedrock.

The AWS deployment template is prepared; it is not yet deployed.

## Tech stack

- TypeScript
- Node.js
- React and Vite
- AWS Lambda
- Amazon API Gateway
- Amazon DynamoDB
- Amazon S3
- Amazon CloudFront
- AWS SAM

## AWS services

- AWS Lambda
- Amazon API Gateway HTTP API
- Amazon DynamoDB
- Amazon S3
- Amazon CloudFront
- AWS IAM / existing Learner Lab role

## Repo link

https://github.com/forstudies506-pixel/Siidekick

## Demo video link

TODO(team)

## Team names

TODO(team)
