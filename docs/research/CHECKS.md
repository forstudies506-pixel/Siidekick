# Checks: why each one matters

Siidekick's 15 checks, with a primary source for each. Wording is mine and kept plain. Fixing a check lowers risk. It does not make a site safe. Accessed 2026-11-25.

OWASP Top 10 2021 (A01, A03, A06) is a 2021 list. NIST SP 800-61 Rev. 2 (2012) was withdrawn in 2025. NIST SP 800-41 Rev. 1 is from 2009. Both NIST items are old.

| # | Check | Why it matters | Source |
|---|---|---|---|
| 1 | Secrets in code | OWASP says secrets kept in plaintext in source code spread across files and tools, are easy to leak and hard to manage. [1] CWE-798 names the weakness: a password or key built into the code. [2] | [1][2] |
| 2 | Security headers | OWASP recommends CSP (helps against XSS), HSTS (HTTPS only), `X-Content-Type-Options: nosniff` and clickjacking protection. [3] | [3] |
| 3 | Rate limit on auth endpoints | OWASP API4:2023 says missing limits let one client overload a service and abuse costly calls like password reset. It advises throttling sensitive operations such as one-time password checks. [4] | [4] |
| 4 | Open CORS | `Access-Control-Allow-Origin: *` lets any origin read the response. With cookies or auth, the wildcard is not allowed, so a named origin must be set. [5] | [5] |
| 5 | Auth on admin routes | OWASP ranks Broken Access Control first in 2021. Its example: an attacker requests an admin URL directly, and it loads for a non-admin. [6] CWE-306 is the matching weakness. [7] | [6][7] |
| 6 | String-built SQL | OWASP says concatenating untrusted values into the query text defeats protection. Use parameterized queries. [8] Injection is A03 in the 2021 Top 10. [9] | [8][9] |
| 7 | Dependency audit | A06 in the 2021 Top 10: you are likely at risk if you do not know your component versions, including nested ones, or patch slowly. [10] | [10] |
| 8 | Input validation | Validate on the server even when the browser checks. Prefer allowlists. This reduces malformed data and excess resource use, but does not replace parameterized queries. [11] | [11] |
| 9 | Firewall rules | NIST gives guidance on firewall policy and on choosing, setting up and managing firewalls (2009). [12] | [12] |
| 10 | Incident playbook | NIST's incident handling guide helps teams build a response capability and says it needs planning (2012, withdrawn 2025, replaced by Rev. 3). [13] In India, CERT-In's 2022 directions require reporting listed incidents within 6 hours of noticing. [14] | [13][14] |
| 11 | README | GitHub says a README tells visitors what the project is and how to use it, and is often the first thing they read. [15] A README with run steps helps a new owner or helper act in an incident. (My reasoning, not from the source.) | [15] |
| 12 | CI workflow | GitHub Actions can build and test every pull request, so a change is checked before it merges. [16] | [16] |
| 13 | Health endpoint | Kubernetes liveness probes use a path such as `/healthz`. A 200 to 399 code is success, otherwise the container is restarted. [17] The check is not Kubernetes-only, but this is the clearest primary source I opened. | [17] |
| 14 | Error handler | OWASP says unhandled errors help attackers, and stack traces can expose framework and server versions. Log details on the server, return a safe message. [18] | [18] |
| 15 | Heavy UI animation | MDN says animating properties that do not trigger reflow or repaint, such as `transform`, can run off the main thread. [19] Animating layout properties is the opposite case (MDN's page does not list them). This is a reliability and speed check, not a security one. | [19] |

## Sources

Accessed 2026-11-25.

1. Secrets Management Cheat Sheet, OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
2. CWE-798: Use of Hard-coded Credentials, MITRE. https://cwe.mitre.org/data/definitions/798.html
3. HTTP Headers Cheat Sheet, OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
4. API4:2023 Unrestricted Resource Consumption, OWASP API Security Top 10. https://api-security.owasp.org/editions/2023/en/0xa4-unrestricted-resource-consumption
5. Cross-Origin Resource Sharing (CORS), MDN. https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS
6. A01:2021 Broken Access Control, OWASP Top 10 (2021). https://top10.owasp.org/2021/A01_2021-Broken_Access_Control/index.html
7. CWE-306: Missing Authentication for Critical Function, MITRE. https://cwe.mitre.org/data/definitions/306.html
8. SQL Injection Prevention Cheat Sheet, OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
9. A03:2021 Injection, OWASP Top 10 (2021). https://top10.owasp.org/2021/A03_2021-Injection/index.html
10. A06:2021 Vulnerable and Outdated Components, OWASP Top 10 (2021). https://top10.owasp.org/2021/A06_2021-Vulnerable_and_Outdated_Components/index.html
11. Input Validation Cheat Sheet, OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
12. Guidelines on Firewalls and Firewall Policy, NIST SP 800-41 Rev. 1, September 2009. https://csrc.nist.gov/pubs/sp/800/41/r1/final
13. Computer Security Incident Handling Guide, NIST SP 800-61 Rev. 2, August 2012 (withdrawn 3 April 2025). https://csrc.nist.gov/pubs/sp/800/61/r2/final
14. CERT-In Directions under section 70B(6), MeitY, 28 April 2022. https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf
15. About READMEs, GitHub Docs. https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-readmes
16. Understanding GitHub Actions, GitHub Docs. https://docs.github.com/en/actions/get-started/understand-github-actions
17. Configure Liveness, Readiness and Startup Probes, Kubernetes docs. https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/
18. Error Handling Cheat Sheet, OWASP Cheat Sheet Series. https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
19. CSS and JavaScript animation performance, MDN. https://developer.mozilla.org/en-US/docs/Web/Performance/Guides/CSS_JavaScript_animation_performance
