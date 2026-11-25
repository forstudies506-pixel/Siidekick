# AGENTS.md: team rules (humans + AI agents)

Read `BRAIN.md` first (the map), then `HANDOFF.md` (current state), then your brief in `docs/workstreams/`.

## Team
| Workstream | Owner | Owns (only edit these) | Brief |
|---|---|---|---|
| WS-core | Claude (lead) | `packages/engine/src/{types,diffGuard,registry,apply,cli,index,util,loadRepo}.ts`, `checks/secrets.ts`, root docs | — |
| WS-demo | kilo | `demo/vulnerable-app/**` | `docs/workstreams/WS-demo.md` |
| WS-engine-security | opencode (lead agent) | `packages/engine/src/checks/security.ts` + new security check/test files | `WS-engine-security.md` |
| WS-engine-delivery | kilo (after demo) | `packages/engine/src/checks/delivery.ts` + new delivery check/test files | `WS-engine-delivery.md` |
| WS-api-infra | opencode (developer agent) | `apps/api/**`, `infra/**` | `WS-api-infra.md` |
| WS-web-landing | copilot | `apps/web/**` | `WS-web-landing.md` |

Rules for every worker: `docs/workstreams/COMMON.md`. `types.ts` is the shared contract: change it only via a board comment.

## Message board = GitHub Issues
- #1 is the team board: status updates, questions, handoffs. One comment per update.
- #2 lists what we need from the human team.
- One issue per workstream (label `workstream`). Humans drop tasks/fixes as new issues; any agent may take one by commenting "taking this".
- Free worker CLIs do not post. The lead relays their reports.

## Working with teammates on main
Before starting and before every push:
```bash
git fetch origin && git log --oneline --stat HEAD..origin/main
```
Read what others pushed, skip work already done, and do not edit files another person is changing. Rebase (`git pull --rebase`), run tests, then push. Never force-push main.

## Lead's agent commands (free models only; never omit `-m`)
```bash
perl -e 'alarm shift; exec @ARGV' 1800 opencode run --auto --agent lead -m opencode/mimo-v2.6-flash-free "$TASK"
perl -e 'alarm shift; exec @ARGV' 1800 opencode run --auto --agent developer -m opencode/mimo-v2.6-flash-free "$TASK"
perl -e 'alarm shift; exec @ARGV' 1800 kilo run --auto -m kilo/nvidia/nemotron-3.5-super-vl:free "$TASK"
perl -e 'alarm shift; exec @ARGV' 1800 copilot -p "$TASK" -s --no-color --allow-all-tools
```
Exit 142 = timeout. On quota/5xx switch model (`opencode/nemotron-3.5-super-vl-free`, `kilo/kilo-auto/free`), then agent. Review chain: worker → Sonnet reviewer on the diff → lead runs tests. A worker's exit code proves nothing.
