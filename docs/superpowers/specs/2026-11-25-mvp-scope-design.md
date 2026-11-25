# MVP scope: close the gap to the roadmap PDF

Date: 2026-11-25. Source of truth: `docs/ROADMAP.md` (the team's roadmap PDF) plus the hackathon brief.
The user opted out of questions for now, so every "call" below is the lead's (Kairav) and can be overruled on the board.

## Intent

Win Campus to Cloud with a working product, not slides. A judge pastes or uploads a small site, sees real findings,
approves fixes one by one, downloads the patched files, and watches the score rise. Every fix is additive or shown as a
diff, never deletes owner code, and is reversible.

## Goals

- The PDF's Phase 1 MVP: six security checks, the diff guard, the approve loop, a live demo.
- The PDF's safe-patching promises made real: one patch file per fix, a log of reason, risk and revert, and test-then-rollback.
- Runs on AWS free tier with the Educate account's LabRole. No Bedrock, no paid services.

## Non-goals (Phase 2+)

Django/Flask/PHP, GitHub PR mode, scheduled rescans and score history, WAF rules, compliance reports, MFA generation.

## Anti-goals

- Running uploaded code on the server. Tests run only in the local CLI on the owner's machine.
- Claiming "unhackable", or any statistic we have not measured.
- Patches that remove or rewrite owner lines without the owner seeing the diff.

## PDF MVP list vs the code

| PDF item | Check | Status |
|---|---|---|
| Security headers | `security-headers` | done |
| Secrets | `secrets-in-repo` | done |
| Dependency audit | `dependency-audit` | in progress (opencode) |
| Rate limits on login | `rate-limit` | done |
| Validation scaffolding | `input-validation` | new, kilo |
| Admin role setup | `auth-on-endpoints` | in progress (opencode) |
| Generated firewall rules | `firewall-rules` | new, kilo |
| Incident playbook | `incident-playbook` | new, kilo |
| Patch file + log per fix | API download | new, Kairav |
| Test, then roll back | CLI `fix --verify` | new, Kairav |

## Approach

Considered: (a) deterministic templates per check, (b) an LLM drafting patches, (c) a hybrid where an LLM explains and
templates patch. Bedrock is not allowed on the Educate account and a free third-party LLM would ship owner code to an
outside service, so (a) wins. Explanations are written per check in plain English. This also makes the diff guard's job
easy to demonstrate: every patch is predictable.

## Calls made by the lead

- `input-validation`: flags `req.body` / `req.query` read in a route with no validation call; the fix creates
  `middleware/validate.js` (no dependency, a tiny shape checker) and does not touch routes. Report-plus-template.
- `firewall-rules`: always offered when no `infra/` security group exists; creates `infra/security-group.yaml`
  (CloudFormation, 443/80 in, SSH closed) and `infra/ufw.sh` (deny by default, 80/443 allowed). Never applied by us.
- `incident-playbook`: creates `SECURITY_PLAYBOOK.md` with the five steps (Detect, Contain, Eradicate, Recover, Review).
- Download returns, besides the patched files, `.siidekick/<patch-id>.patch` (unified diff) for each approved patch
  and `SIIDEKICK_LOG.md` listing each patch's reason, class and a one-line revert (`git apply -R .siidekick/<id>.patch`).
- `siidekick fix --verify`: runs the owner's `npm test` before; applies each patch; reruns; reverts that patch if tests
  newly fail. Local only.
- Scanners skip `.md` files and test files where a code pattern is being matched, so docs never cause a false pass.

## Left to the builders

Exact detection regexes, wording of explanations, test fixtures. Each check follows the shape of
`packages/engine/src/checks/health-endpoint.ts` and passes the diff guard.
