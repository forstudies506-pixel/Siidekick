# Cyber Hardening Assistant

An AI helper that scans an existing website or web app, then adds the missing security, reliability and UI-speed pieces **without removing or replacing the owner's code**.

Built for the Campus to Cloud Hackathon (AWS, Techfest 2026-27).

## What it does

- Checks identity and admin access, application security, firewalls and hosting, secrets, dependencies and monitoring.
- Runs a registry of 32 production-readiness checks, including CI/CD, backups, rollback, error tracking, email authentication, AI-feature safety and audit evidence.
- Proposes small UI speed fixes: a lighter login page and smoother animations.
- Enforces a "diff guard": any patch that deletes user code outside approved patterns is rejected automatically.

## Read the full roadmap

[docs/ROADMAP.md](docs/ROADMAP.md) has the complete guide: pipeline, per-layer steps, safe-patching rules, the 32-check registry, testing plan and the 6-day build timeline.

## Status

Planning phase. The roadmap is the current deliverable; the implementation follows the timeline in section 10 of the roadmap.
