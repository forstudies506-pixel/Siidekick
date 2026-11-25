# Siidekick scanner (Python, v0.1)

A standalone Python version of the Siidekick checks, used for prototyping and for live attack simulation. It does not depend on `packages/engine` (the TypeScript engine the web app uses) and nothing else in the repo imports it.

`demo/vulnerable-shop/` is deliberately insecure test material. Every key and password in it, including `.env`, is fake (`AKIAIOSFODNN7EXAMPLE` is AWS's published example key). Never deploy it.

Commands: `scan`, `fix`, `guard`, `threats`, `attack`, and `full` (the 3-step test: vulnerabilities, entry and exit points, live virus and malware attack simulation).

Finds security problems in a project, fixes what is safe to fix on a **copy**, and proves with a diff guard that none of the owner's code was removed or rewritten.

Pure Python 3, no packages needed. Uses Semgrep, Gitleaks and `npm audit` automatically when they are installed.

## Run it

```bash
python3 -m siidekick scan  path/to/project            # list findings
python3 -m siidekick fix   path/to/project --out out  # scan -> fix copy -> guard -> verify -> re-scan -> out/report.html
python3 -m siidekick threats path/to/project --out report.md   # entry points + way in / way out / run code
python3 -m siidekick guard some.patch --findings findings.json   # check any patch, e.g. one written by an AI
python3 -m unittest discover -s tests -v              # 11 tests, including attacks on the guard
```

`fix` never touches the original folder. It writes `out/patched/` (fixed copy), `out/siidekick.patch` (exact diff), `out/results.json` and `out/report.html`.

## What counts as a vulnerability

Siidekick uses one definition. A vulnerability is any of:

1. **Way in**: an entry point through which an attacker can get access (missing login checks, injection, weak tokens, no rate limit).
2. **Way out**: a path through which data or information can leak (secrets in code, error details, missing headers, third-party files).
3. **Run code**: a route through which malware or a virus can attack the server (command injection, eval, unsafe uploads, unsafe deserialisation, vulnerable libraries, scripts piped into a shell).

`threats` first maps the **attack surface** (every route, API handler, serverless function, PHP page and form, with whether it checks login and takes input), then sorts every finding into these groups. One finding can be in more than one group.

## What it checks

- **42 built-in rules** for JavaScript/TypeScript, Python, PHP and HTML: SQL and command injection, XSS, path traversal, eval, weak hashing, CORS, cookie flags, JWT misuse, error leaks, unguarded admin routes, debug mode, unsafe deserialisation, TLS off.
- **Secrets**: AWS, GitHub, Stripe, Google and Slack keys, private keys, hardcoded passwords and tokens, and `.env` files that git would commit. Secrets are masked in every output.
- **Project checks**: missing security headers, login without rate limit, `.env` not ignored, no README, CI or tests.
- **Dependencies**: a small offline list of known-vulnerable versions (lodash, minimist, jsonwebtoken, express, axios, marked, moment, node-serialize, flask, requests, pyyaml). Run `npm audit`, `pip-audit` or OSV-Scanner online for full coverage.

## What it fixes automatically (Express apps)

Parameterised SQL, `innerHTML` to `textContent`, escaping reflected input, safe file names, admin role guard, CORS allow-list, cookie flags, secrets moved to environment variables (plus `.env.example`), hidden stack traces, helmet and login rate limiting via one new file `siidekick.security.js`, and `.env` added to `.gitignore`.

Anything that needs a decision (password re-hashing, key rotation, library upgrades, Python and PHP fixes) is reported with a plain-language explanation and fix.

## The diff guard

A plain script, not an AI. A patch is rejected if it deletes a file, removes or rewrites any line that no approved finding points at, replaces an approved line with unrelated code, adds eval, shell calls, outside URLs or credentials, or is too large. Then every changed file is syntax-checked; if one fails, all changes are rolled back.

## Limits

Regex rules are fast and explainable but miss flaws that span several lines or files, and cannot judge business logic. Semgrep or CodeQL should be added for deeper data-flow analysis. Only scan code you own or have permission to test.
