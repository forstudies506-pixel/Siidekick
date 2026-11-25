# Siidekick: the idea

**A security sidekick for India's small web teams.** You paste your repo. Siidekick explains each risk in plain English or Hindi and proposes small fixes that only *add* code. A diff guard, enforced in code, proves that none of your code was deleted. You approve each fix, and the score jumps.

We never replace your code. Siidekick reduces risk; it does not make anything "unhackable".

## Who it is for
These people ship websites with no security person:
- student founders
- college club and fest sites
- small shops going online
- NGOs

Their usual failure modes:
- a key pasted into the repo
- no security headers
- an `/admin` route anyone can call
- SQL built from strings
- a two-year-old `lodash`

They don't need another list of 200 warnings in English jargon. They need someone to say "this is the problem, this is the five-line fix, nothing of yours is touched" and then make the fix.

Sourced context: `docs/research/BHARAT.md`. We claim no statistic that isn't sourced there.

## What makes it different
Existing tools either:
- report findings and leave the fix to an expert, or
- let an AI rewrite code the owner can't review.

Comparison: `docs/research/COMPETITORS.md`.

| | Siidekick |
|---|---|
| Fixes | Deterministic templates per check. The same input gives the same patch, so it can be audited. |
| Safety | The diff guard rejects any patch that deletes owner code. It is enforced in `packages/engine/src/diffGuard.ts`, not just promised. |
| Proof | `--verify` runs the owner's own tests after each patch and rolls back any patch that breaks them. Every patch is saved with a `git apply -R` revert line. |
| Language | Every finding comes with a plain-language "why it matters", in English and Hindi. |
| Cost | Free. Runs within the AWS free tier, and sends no code to any AI service. |

## The demo (the moments a judge remembers)
1. Paste a public GitHub URL, or use the planted-flaw demo shop. Within seconds the scan shows a score of **3/100**.
2. Findings appear in plain words, with a हिन्दी toggle.
3. Each fix shows its diff with the added lines highlighted, and the guard's verdict.
4. **Tamper:** make a fix delete one line of owner code. The real guard on the server blocks it and shows the line.
5. Approve the fixes. The score animates to **77**. The three remaining items are honest owner tasks, each with its rewrite shown.
6. Download the patched repo, including `.siidekick/*.patch` files and a log with revert commands.
7. *(stretch)* The Siidekick Guard GitHub Action keeps the repo safe on every pull request after that.

## Judging map (Campus to Cloud weights, ROADMAP §12)
| Criterion | Weight | What answers it |
|---|---|---|
| Bharat impact | 30 | The target users above, Hindi explanations, free, and a pilot on real sites the owners agreed to share (human-supplied, #2) |
| AWS build | 25 | A live URL running Lambda (arm64), API Gateway HTTP API, DynamoDB, S3, and CloudFront via SAM |
| Innovation | 25 | The diff guard as a hard gate, test-and-rollback, deterministic patches, and the tamper demo |
| Demo | 20 | The seven moments above, in under 3 minutes |

## Deliberately not doing
- **AI-written patches.** Bedrock is blocked, and sending code to a third-party model would undercut the safety story.
- **Running uploaded code on our server.** Test-and-rollback is local CLI only.
- **Login and accounts.** Cognito comes after the hackathon.
- **Claiming a site is "secure".**
