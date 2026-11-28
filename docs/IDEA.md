# Siidekick: idea brief

**Catch the breach before it ships.** *Making Cybersecurity accessible to all.*

Team **Schrödinger's Code**, a part of Echelon Systems Architecture · Campus to Cloud Hackathon sponsored by AWS, Techfest 2026-27

Live: https://d1ulntgja5qae0.cloudfront.net · One-click demo: https://d1ulntgja5qae0.cloudfront.net/app?demo=1 · Code: https://github.com/forstudies506-pixel/Siidekick

---

## 1. The problem

India is building its own internet, fast, and mostly without security engineers.

- **886 million** Indians were online in 2024, 488 million of them in rural India. *(Kantar–IAMAI, Internet in India 2024)*
- **About 228 billion UPI payments**, worth nearly **₹300 lakh crore**, were made in 2025. *(NPCI data, as reported by Business Standard and Deccan Chronicle, Jan 2026)*
- **21.9 million developers** build on GitHub in India, the second-largest community in the world. *(GitHub Octoverse 2025)*
- **7.28 crore** small businesses are registered on Udyam. *(Ministry of MSME, PIB)*

The sites and apps behind those numbers are increasingly written by a kirana store owner's nephew, a college fest team, a solo developer at 2 a.m., often with an AI assistant. They take UPI and Razorpay payments, OTP logins and Aadhaar or PAN for KYC. And they ship with the same mistakes: a payment accepted without checking its signature, an OTP sent back in the API response, a key pasted into the repo, an admin route anyone can call, a dependency with a known exploit.

The cost is real:
- **29.44 lakh** cyber incidents were handled by CERT-In in 2025. *(PIB, Jan 2026)*
- Cyber crime cases rose **24.4%** in a single year (52,974 in 2021 to 65,893 in 2022), and **64.8%** were fraud. *(NCRB Crime in India 2022, via news report)*
- The DPDP Rules (notified 14 November 2025) set penalties of up to **₹250 crore** for failing to keep reasonable security safeguards. *(PIB)*
- CERT-In requires listed incidents to be reported **within 6 hours**. *(CERT-In Directions, April 2022)*

Today's tools do not reach these people. Scanners produce long lists of warnings in English jargon and stop there. AI coding tools rewrite code the owner cannot review. Professional security help is unaffordable. **Security has been a luxury. It should not be.**

## 2. Who it is for

People who ship code that handles money or personal data, with no security person:
- **students and college clubs** building fest, event and placement sites;
- **small shops and local businesses** taking orders and UPI payments online;
- **solo and indie developers** shipping side projects and freelance work;
- **NGOs and early startups** collecting personal data.

They are comfortable in Hindi, Tamil, Bengali or another Indian language as often as in English. They need someone to say "this is the problem, this is the fix, none of your code is touched", then make the fix and prove it works.

## 3. How Siidekick works

1. **Scan.** Paste a public GitHub repo (up to 3,000 files and 10 MB of code) or upload a folder. 39 checks read the code as text; nothing is run on our server. A **Bharat Pack** of India-specific checks catches unverified Razorpay and Paytm/UPI payments, Aadhaar and PAN in code or logs, and leaked or guessable OTPs. Checks for AI-era mistakes catch invented package names, server keys shipped to the browser, open Firebase or Supabase rules, and login tokens that are decoded but never verified.
2. **Explain.** Every finding in plain words, with the file and line. **Amazon Bedrock** (Nova Lite) explains any finding in **8 languages**: English, Hindi, Bengali, Marathi, Tamil, Telugu, Gujarati, Kannada. Each AI answer is checked against the scan evidence, so it cannot invent a CVE or a version number. An **India lens** shows which findings matter under the DPDP Act and CERT-In's 6-hour rule.
3. **Fix.** Each fixable finding gets a small, deterministic patch that **only adds code**. A **diff guard** refuses any patch that deletes or rewrites the owner's code, enforced on the server, not promised. Nothing changes until the owner approves each fix.
4. **Prove.** Approved fixes run in a **throwaway AWS CodeBuild** container, original and fixed copies side by side: install, the project's own tests, and an independent `npm audit`. A fix is labelled **verified** only when the tests still pass and the flagged packages are gone.
5. **Ship.** Download the changed files with a revert log, or open a **GitHub pull request** carrying the evidence. A human always merges. A **GitHub Action** keeps scanning every future pull request.

What it deliberately does not do: the AI never writes your code; uploaded code is never executed on our server; Siidekick never claims an app is "unhackable".

## 4. Impact

**Measured on the live AWS deployment** against a realistic college-fest shop (28 November 2026). Nothing here is estimated.

| | Before | After Siidekick |
|---|---|---|
| Security score | 33 / 100 | **62 / 100** |
| Failing checks | 23 | 12 |
| Checks that can expose personal data (DPDP-relevant) | 11 | 6 |
| Forged Razorpay payment | `200`: free fest pass issued | **`400`: rejected** (a real signed payment still works) |
| Live attacks that work against the shop | 7 | 1 |
| Vulnerable packages (independent `npm audit` on AWS) | 8 | **0** |
| The shop's own tests | 4 / 4 pass | 4 / 4 pass |
| Owner's lines deleted | | **0** (+209 added) |
| Time to proof on AWS | | **74 s** |

The 12 checks that still fail are left to the owner on purpose (for example, rewriting a SQL query), each with the exact fix and an explanation in their language.

It scales to real projects: on the live site, `fastify/fastify` scans in 7 s and `nestjs/nest` (2,824 files) in 11 s. Siidekick also scans itself: with a `.siidekickignore` for its deliberately vulnerable demos and rule files, its own repo scores 94/100 with no critical findings.

**Why it matters:** for a student, a shop owner or a solo developer, Siidekick turns "you have 200 warnings" into "here are the five fixes that stop a fake payment or a stolen account, explained in your language, proven before you merge". That is the gap between a forged ₹499 fest pass, a leaked customer list or a DPDP notice, and an app people can trust. It is free to use, needs no login, and runs on AWS for a few cents a month.

## 5. Why most people should care

Every Indian who pays by UPI, logs in with an OTP or shares Aadhaar with a small business depends on code that nobody security-checked. Siidekick makes that check available to every builder, in their language, at no cost: **cybersecurity accessible to all.**

---
*All statistics are sourced in `docs/research/BHARAT.md` or listed inline. Siidekick reduces risk; no tool can promise an app is unhackable, and this one does not.*
