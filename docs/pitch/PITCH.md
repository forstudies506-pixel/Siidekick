# Siidekick

## Problem

Small shops, student groups and colleges ship websites without a security engineer. Risks are easy to miss, and generic security advice is hard to act on.

## Who it is for

Siidekick is for Indian students, small shops and colleges that need plain-language findings and reviewable fixes.

## What it does

Siidekick scans a small web repository and lists security or reliability findings. It proposes small patches, shows the diff and waits for owner approval. After approval, it rescans and reports the score change.

The patches can be downloaded with revert instructions. The local CLI can test an owner's patch and roll back if tests fail.

## Risk reduction

Siidekick never deletes owner code. The diff guard blocks destructive or unrelated changes. The owner approves each fix. Uploaded code is not run on the server. Tests run only on the owner's local machine.

This design reduces risk; it does not eliminate it.

## AWS services

- API Gateway receives HTTP requests.
- Lambda runs the scan API.
- DynamoDB stores scan records.
- S3 stores the private web build.
- CloudFront delivers the site and routes API requests.

At demo traffic, these services use AWS free-tier allowances. DynamoDB records expire after seven days to keep storage small. The build uses the AWS Learner Lab's existing LabRole and does not enable Bedrock or other paid model services.

## What is next

Phase 2 adds Django, Flask and PHP support, plus direct GitHub pull request mode. Later phases add scheduled rescans and score history, guided WAF setup and compliance reports.
