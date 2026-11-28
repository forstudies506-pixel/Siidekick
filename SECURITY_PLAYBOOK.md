# Security Incident Playbook — Siidekick

## Detect
- Confirm the alert: which endpoint or log triggered it, and when.
- Review recent deploys and changed files in git.
- Identify affected users and any exposed data.
- Record the time, source, and scope of the event.

## Contain
- Rotate any exposed keys and revoke all active sessions immediately.
- Block offending IPs at the firewall or WAF.
- Take the affected route offline if data is being exfiltrated.

## Report (India)
- CERT-In Directions (28 April 2022): service providers, intermediaries, data centres and body corporate must report listed cyber incidents to CERT-In within 6 hours of noticing them, and keep logs for a rolling 180 days.
- DPDP Rules, 2025: after a personal data breach, tell affected people without delay, in plain language, with a contact for help, and notify the Data Protection Board.
- Who must do what depends on your organisation. Check the current rules or ask a lawyer; this playbook is not legal advice.

## Eradicate
- Check access and error logs for how the attacker got in.
- Remove malicious code and revert to a clean, signed git commit.
- Patch the dependency or code path that allowed the issue.

## Recover
- Redeploy from git (`git checkout <clean-sha>` then push).
- Restart the Node/Express service and verify it responds on /health.
- Confirm logs show clean traffic after the redeploy.

## Review
- Write a postmortem: what happened, what changed, how long response took.
- Notify users if their data was affected.
- Add a check or test so the same issue cannot recur.
