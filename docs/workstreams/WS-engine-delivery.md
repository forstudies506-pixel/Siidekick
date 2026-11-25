# WS-engine-delivery — Groups A/B/E checks (owner: kilo, after WS-demo)

**Own:** new files `packages/engine/src/checks/<id>.ts`, `packages/engine/test/<id>.test.ts`, and the array in `packages/engine/src/checks/delivery.ts`. Do not edit `types.ts`, `registry.ts`, `diffGuard.ts`, `security.ts`, `secrets.ts`.

Same pattern and rules as `checks/secrets.ts` (read `docs/workstreams/WS-engine-security.md` "Copy the pattern" paragraph: pure TS detectors, deterministic fixers, recompute from `ctx.repo`, patches must pass `guardPatch`, no new npm deps in the user's app). Express app line = the line with `= express()`.

1. `readme` (low, auto, group A-delivery): fail if no `README.md` or under 200 chars. Fix: create `README.md` (only when missing) from package.json name/description/scripts and env var names found in `.env.example`.
2. `ci-workflow` (medium, auto, A-delivery): fail if no `.github/workflows/*.yml`. Fix: create `.github/workflows/siidekick.yml`: on push/PR, Node 20, `npm ci`, `npm test --if-present`, `npm audit --audit-level=high || true`.
3. `health-endpoint` (low, auto, B-monitoring): fail if Express app has no `/health` or `/healthz` route. Fix (additive): insert `app.get('/health', (req, res) => res.json({ ok: true }));` after the app line.
4. `error-handler` (medium, auto, B-monitoring): fail if no 4-argument middleware `(err, req, res, next)`. Fix (additive): create `errorHandler.js` (logs `err.stack` server-side, returns `{error:'Something went wrong'}` 500 with no stack to the client) and insert `app.use(require('./errorHandler'));` on the line immediately before `module.exports = app` or the `app.listen(` line, whichever comes first.
5. `ui-heavy-animation` (low, report, E-states): in `.css` and `.html` files, flag `@keyframes` blocks that animate `left|top|right|bottom|width|height|margin` and inline `<script>` blocks over 200 lines. Report-only; explanation suggests `transform`/`opacity` and `defer`/lazy-load.

Tests per check: failing fixture, clean fixture, fix → `applyPatch` OK → re-detect `[]` (report-only: detect tests only).

Done when `npm test -w @siidekick/engine` passes and `npx tsc -p packages/engine/tsconfig.json` has no errors.
