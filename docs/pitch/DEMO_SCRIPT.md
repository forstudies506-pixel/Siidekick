# Siidekick 3-Minute Demo

Record on https://siidekick.ashforge.cv. Open it once a minute before recording so the server is warm.

## 0:00-0:20 - Problem

**Show:** The landing page.

**Say:** "AI can now find and exploit a website's mistakes in minutes, and AI-written code ships the same mistakes again and again. Small shops and student teams have no security engineer to catch them."

## 0:20-0:50 - Scan any live website

**Click:** Paste the team's own site (or one you have permission to show) into the box and press Scan.

**Say:** "Siidekick reads the site the way any browser does. No login, no attack traffic. TLS, headers, cookies, forms, scripts, and whether the page calls an AI model with its key in plain view."

**Click:** Press `f` to show only failing checks. Open one finding.

**Say:** "Each one says what is wrong, why it matters, and the exact fix, in plain words."

## 0:50-1:15 - Scan a repo

**Click:** Back to the landing page. Click "Scan the demo shop" (or paste a public GitHub repo).

**Say:** "For code, it reads the repo file by file. These are the AI-era checks: a package name that does not exist, a server key shipped to the browser, Firebase rules left open, login tokens that are read but never verified."

## 1:15-1:45 - Fixes and the guard

**Click:** Go to Fixes. Open one diff.

**Say:** "Every fix only adds lines. The diff guard refuses any patch that deletes or rewrites your code, and nothing lands until you approve it."

**Click:** Approve the patches one by one. Point to the score.

**Say:** "Each approval rescans the patched copy, so the score is measured, not promised."

## 1:45-2:30 - Proof of fix

**Click:** Go to "Verify & ship" and press "Replay the attacks". Point to the path marked "Fix this one first", then to one receipt.

**Say:** "A score is still a claim. So Siidekick boots the shop twice, as scanned and as patched, and fires the same attacks at both. Five are blocked, and next to each is a control request showing a real customer still gets through. One still works: the SQL injection, because no safe automatic patch exists. That keeps the path to logging in as any customer open, so Siidekick says fix this one first. Risk reduced, not removed."

## 2:30-2:45 - Take it home

**Click:** Export the report as Markdown, copy the share link, download the patched files.

**Say:** "You get the patched files, a patch file per fix, and a log with a one-line revert for each. The same engine runs as a CLI, and `fix --prove` replays the attacks on your machine."

## 2:45-3:00 - AWS

**Say:** "It runs live today on Vercel. The AWS build is in the repo: API Gateway to Lambda, DynamoDB for scan records, S3 and CloudFront for the web app, all on the Learner Lab's free tier, no Bedrock."
