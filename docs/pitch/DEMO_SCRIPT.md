# Siidekick 3-Minute Demo (AWS build)

Record on the **CloudFront URL** from `scripts/deploy.sh`. Before recording:

- Open `/api/health` once so Lambda is warm, and check `"ai"` is set and `"verify": true`.
- Run one verification on the demo beforehand, so you know the timing and CodeBuild's first-run provisioning is done.
- For the pull request moment: push `demo/vulnerable-app` to a public GitHub repo of yours, and have a fine-grained token for that repo ready (Contents, Pull requests and Workflows, read/write). Do not show the token on screen.
- Have the AWS console open in a second tab: Step Functions → `siidekick-verify`.

## 0:00–0:20 · Who it is for

**Show:** The landing page.

**Say:** "Every kirana store going online, every college fest site, every student startup runs on open-source packages. One bad package, three layers deep, can leak their customers' data, and none of them has a security engineer. Siidekick is that engineer, in their language."

## 0:20–0:45 · Connect and discover

**Click:** Paste the GitHub URL of your copy of the demo shop and press Scan (or use "Try the demo shop").

**Say:** "It reads the code and the lockfile on AWS Lambda and checks every package against OSV.dev."

**Click:** Findings → open "Dependency vulnerability audit" → scroll to `qs`.

**Say:** "The app never installed qs. It came in through express. Siidekick rebuilds the dependency graph and shows exactly how it got in."

**Point to:** the India lens: "11 failing checks can expose students' data, the DPDP Act's penalty for that goes up to ₹250 crore, and there's no plan for CERT-In's 6-hour report." Then open "Online payments are verified on the server".

**Say:** "This is the bug we see in fest sites: the server trusts the Razorpay payment id the browser sends. Anyone can get a pass with a fake payment. No generic scanner checks this."

## 0:45–1:15 · Investigate, in your language

**Click:** Set "AI explains in" to हिन्दी (or Tamil). Press "Explain simply".

**Say:** "Amazon Bedrock explains it the way you'd explain it to a shop owner: what could happen, what to do, what the options cost. And it can't make things up: any CVE or version that isn't in the real advisory gets the answer rejected."

## 1:15–1:45 · Propose a minimal fix

**Click:** Fixes → open the dependency bump and one code fix → "Approve all guard-passed".

**Say:** "The AI never writes your code. Fixes are small templates that only add lines, and a diff guard refuses anything that deletes your code. Nothing lands until you approve it."

## 1:45–2:30 · Verify in isolation

**Click:** Verify & ship → **Run verification**. While it runs, switch to the Step Functions tab and show the execution graph, then come back.

**Say:** "Step Functions takes both copies, before and after, into a throwaway CodeBuild container: npm install, *their own* tests, and npm audit, which is a second, independent advisory source. Their code runs with no AWS credentials and no install scripts."

**Point to:** the **Verified** badge, the 8/8 table (high → clean), "tests passed before and after".

**Say:** "Verified means proven: tests pass and the vulnerable packages are gone. If a fix had broken their tests, Siidekick would have caught it as a regression."

## 2:30–3:00 · Evidence and human control

**Click:** Paste the token → **Open pull request** → open the PR on GitHub.

**Say:** "It opens a pull request with the fixes, the refreshed lockfile and the verification evidence. A human still clicks merge. Detect carefully, explain in your language, fix minimally, prove it in isolation. Security that every Indian builder can use."

## If something fails live

- Bedrock slow or erroring: say "the scanner text is the source of truth" and continue; explanations are cached once generated, so pre-generate the one you'll show.
- Build slow: CodeBuild provisioning can add a minute. Show the Step Functions graph and CloudWatch dashboard while waiting, or open a pre-recorded verified run (a reload resumes the last run for that scan).
