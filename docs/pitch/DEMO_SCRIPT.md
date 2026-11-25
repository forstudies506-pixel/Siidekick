# Siidekick 3-Minute Demo

## 0:00-0:20 - Problem

**Click:** Open the Siidekick dashboard.

**Say:** “Small teams and student groups often ship websites without a security engineer. Small risks can sit in the repo for months.”

## 0:20-0:45 - Load the demo

**Click:** Select the demo shop and run the scan, or call `/api/scans/demo` in the API.

**Say:** “This demo represents a small web shop. Siidekick reads the repo and explains findings in plain language.”

## 0:45-1:10 - Findings

**Click:** Open the findings list.

**Say:** “The findings have severity labels. Here are the highest-risk items and the reason each one matters.”

## 1:10-1:35 - Generate fixes

**Click:** Generate patches for two findings.

**Say:** “Siidekick creates small, predictable templates. It does not run uploaded code or invent changes by itself.”

## 1:35-2:00 - Diff and guard

**Click:** Open one patch diff. Show the addition and a blocked deletion, if available.

**Say:** “The owner can read exactly what changes. The diff guard rejects patches that delete owner code or replace a file outside the approved edit.”

## 2:00-2:25 - Approve two

**Click:** Approve the first patch, then approve the second.

**Say:** “Each patch needs separate approval. Siidekick applies only the approved changes.”

## 2:25-2:40 - Rescan

**Click:** Run the rescan and point to the score.

**Say:** “The rescan shows the score change. It gives the owner a before-and-after check; it reduces risk but does not eliminate it.”

## 2:40-2:55 - Download

**Click:** Download the patched files.

**Say:** “The download includes the patched files, unified patch files, and `SIIDEKICK_LOG.md`. The log gives a one-line revert for each approved patch.”

## 2:55-3:00 - AWS architecture

**Say:** “On AWS, API Gateway sends requests to Lambda, DynamoDB stores scan state, and S3 plus CloudFront serves the private web app.”
