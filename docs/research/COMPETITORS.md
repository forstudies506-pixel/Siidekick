# Competitors

Tools a small team could use today. Cells say "not stated" when the pages I opened did not say. Each cell points to the tool's own docs or pricing page. Accessed 2026-11-25.

| Tool | What it finds | Does it fix? | How the fix is made | Free tier limits | Needs security knowledge? | Indian languages? |
|---|---|---|---|---|---|---|
| GitHub Dependabot | Vulnerable dependencies in the dependency graph [1] | Yes, for dependencies in a manifest or lock file [1] | Version bump: a pull request to the minimum version that includes the patch [1] | Alerts and security updates are available on every GitHub plan [2] | Not stated | Not stated |
| GitHub code scanning (CodeQL) + Copilot Autofix | Security vulnerabilities and coding errors [3] | Suggests fixes for CodeQL alerts [4] | LLM-generated. Docs say it is non-deterministic and "you must always review" suggestions [4] | Free for public repos. Private repos need a GitHub Code Security licence [2][3] | Not stated | Docs say English is the primary supported language for the AI features [4] |
| Snyk | Open source, code, IaC and container issues [5] | Yes [6][7] | Open Source: upgrade direct dependencies, via fix PRs [6]. Code: LLM "Snyk Agent Fix", single-file fixes only [7] | Free plan: 100 Code tests per month, 200 Open Source, 300 IaC, 100 Container [5] | Not stated | Not stated |
| Semgrep (Free / Community) | Code (SAST) and Supply Chain (SCA) findings [8] | Partly. Rule-defined fixes are deterministic. AI Autofix opens PRs. The AI "Suggested fix" has no inline diffs [9] | Mix of rule-defined and AI [9] | Free: up to 10 contributors, 10 repos, 60 AI credits [8]. Community Edition is LGPL-2.1 and analyses only within a single function or file [10] | Not stated | Not stated |
| SonarQube Cloud (SonarCloud) | Code quality and security issues [11] | AI CodeFix on Team and Enterprise only [11][12] | LLM: sends the affected code and issue text to an LLM [12] | Free: up to 50k LOC in private projects, 5 members, no AI CodeFix [11] | Not stated | Not stated |
| OWASP ZAP | Vulnerabilities in a running web app, via scans [13] | Not stated. Docs describe scanning and attacking targets [13][14] | n/a | Free, open source [13] | Docs warn active scan is an attack and must only be used on apps you may test. It cannot find logic flaws such as broken access control [14] | Not stated |
| MDN HTTP Observatory | HTTP headers and other security configuration [15] | No. It reports results and recommendations [16] | n/a | Not stated on pages read. Scans limited to one per site per 60 seconds [16] | Aimed at developers and site operators (page content, my reading) [16] | Not stated |
| securityheaders.com | HTTP response headers of a domain [17] | No. It shows a report [17] | n/a | Free, no account (2016 launch post; may have changed) [17] | Not stated | Not stated |

## Limits worth knowing (from the same docs)

- Observatory says an A+ grade does not mean a site is "perfectly secure". It does not test SQL injection, outdated software or vulnerable CMS plugins. [16]
- Copilot Autofix and Snyk Agent Fix both say fixes can be wrong or missing and need human review or checks. [4][7]
- Snyk Agent Fix handles one file at a time. [7]

## Gap Siidekick fills

Only what the table supports, plus Siidekick's own design (from `docs/IDEA.md`, not external sources):

1. The two header tools I read report only. [16][17] Siidekick proposes the patch for headers as well.
2. The AI fixers I read (Copilot Autofix, Snyk Agent Fix, SonarQube AI CodeFix) use LLMs, and two of their docs say output is non-deterministic or needs review. [4][7][12] Siidekick uses fixed templates per check, so the same input gives the same patch. Project design claim.
3. SonarQube's free plan has no AI CodeFix, and Copilot Autofix on private repos needs a licence. [2][11] Siidekick is free and sends no code to an AI service. Project design claim.
4. Only the Copilot Autofix docs say anything about language, and it is English. [4] I found nothing in the pages I read about Hindi. Siidekick adds plain-language Hindi explanations. Project design claim.
5. Siidekick's diff guard (rejects patches that delete owner code) has no counterpart in the pages I read. That is an absence in my reading, not proof no tool does this.

Siidekick does not replace these tools. Dependabot already does version bumps well. ZAP tests running apps, which Siidekick does not.

## Sources

Accessed 2026-11-25.

1. About Dependabot security updates, GitHub Docs. https://docs.github.com/en/code-security/dependabot/dependabot-security-updates/about-dependabot-security-updates
2. GitHub security features, GitHub Docs. https://docs.github.com/en/code-security/getting-started/github-security-features
3. About code scanning, GitHub Docs. https://docs.github.com/en/code-security/code-scanning/introduction-to-code-scanning/about-code-scanning
4. About Copilot Autofix for CodeQL code scanning, GitHub Docs. https://docs.github.com/en/code-security/code-scanning/managing-code-scanning-alerts/about-autofix-for-codeql-code-scanning
5. Snyk plans, Snyk. https://snyk.io/plans/
6. Fix your vulnerabilities (Open Source), Snyk Docs. https://docs.snyk.io/scan-with-snyk/snyk-open-source/manage-vulnerabilities/fix-your-vulnerabilities
7. Fix code vulnerabilities automatically (Snyk Agent Fix), Snyk Docs. https://docs.snyk.io/scan-with-snyk/snyk-code/manage-code-vulnerabilities/fix-code-vulnerabilities-automatically
8. Semgrep pricing, Semgrep. https://semgrep.dev/pricing
9. Semgrep Multimodal overview, Semgrep Docs (the page that replaced the Assistant overview URL). https://docs.semgrep.dev/semgrep-assistant/overview
10. semgrep/semgrep README, GitHub. https://github.com/semgrep/semgrep
11. Subscription plans, SonarQube Cloud Docs. https://docs.sonarsource.com/sonarqube-cloud/administering-sonarcloud/managing-subscription/subscription-plans/
12. AI CodeFix, SonarQube Cloud Docs. https://docs.sonarsource.com/sonarqube-cloud/ai-capabilities/ai-codefix/
13. ZAP home page, ZAP project. https://www.zaproxy.org/
14. Active scan, ZAP Docs. https://www.zaproxy.org/docs/desktop/start/features/ascan/
15. HTTP Observatory, MDN. https://developer.mozilla.org/en-US/observatory
16. HTTP Observatory FAQ, MDN. https://developer.mozilla.org/en-US/observatory/docs/faq
17. "Introducing securityheaders.io", Scott Helme, 2016. https://scotthelme.co.uk/introducing-securityheaders-io/

## Wanted but not sourced

- Free-tier limits for Observatory and securityheaders.com today (pages say nothing on cost, or were blocked).
- Whether any of these tools offers non-English explanations (docs read are silent except Copilot Autofix).
- Any statement on how much security knowledge each tool assumes.
- SonarQube pages disagreed in wording about plan names and free limits; I used the subscription docs.
