# WS-api-infra — HTTP API, Lambda, AWS SAM template (owner: opencode developer)

**Own:** `apps/api/**` (except `package.json`) and `infra/**`. Read `packages/engine/src/index.ts` for what the engine exports; import it as `@siidekick/engine`.

No Express here (not installed). Write one pure router and two thin adapters:
- `src/router.ts`: `handle(req: { method: string; path: string; body?: unknown }): Promise<{ status: number; body: unknown }>`.
- `src/lambda.ts`: API Gateway HTTP API (payload v2) handler → `handle` → `{ statusCode, headers: {content-type: application/json}, body }`.
- `src/local.ts`: `node:http` server on `PORT` (default 8787) → `handle`. Used by `npm run dev -w @siidekick/api` and by the web dashboard's Vite proxy.

Storage adapter `src/store.ts`: interface `get(id)`, `put(id, record)`; `STORAGE=local` (default) writes `.data/scans/<id>.json` at the repo root; `STORAGE=dynamo` uses `@aws-sdk/lib-dynamodb` on table `process.env.TABLE_NAME`, key `id`, plus `expiresAt` (epoch seconds, 7 days) for TTL. Record = `{ id, createdAt, repo (RepoSnapshot), report, patches?, after? }`.

Routes (validate every body with zod; reject with 400 `{error}`; never echo file contents in errors):
- `GET /api/health` → `{ ok: true, checks: registry.length }`.
- `POST /api/scans` body `{ name: string, files: {path, content}[] }`. Limits: ≤500 files, total content ≤2 MB, path must be relative POSIX with no `..`, no leading `/`, no NUL. → runs `runScan({ repo, fetch }, registry)` → stores → `201 { id, report }`. id = `crypto.randomUUID()`.
- `POST /api/scans/demo` → same, using the bundled demo repo (see below).
- `GET /api/scans/:id` → `{ id, report, patches?, after? }` or 404. Validate id is a UUID.
- `POST /api/scans/:id/patches` → for each failing check with a `fix`, in registry order: build patch from the *current* snapshot, run `guardPatch`, record `{ patch, guard, diff }` where `diff` = per modified/created file `{ path, lines: renderDiff(before, after) }` (created file: before = ""); if guard ok, `applyPatch` and continue on the new snapshot. Then rescan → `after` report. Response `{ patches: [...], scoreBefore, scoreAfter, status: "rescan-clean" | "partial" }` (never "verified": tests did not run on the server).
- `POST /api/scans/:id/patches/:patchId/approve` → marks approved in the record, returns `{ approved: [ids] }`.
- `GET /api/scans/:id/download` → `{ files: [{path, content}] }` of files created/changed by **approved** patches only.
- Unknown route 404, wrong method 405, thrown error 500 `{ error: "internal" }` with the real error logged server-side only.
- Every response sets `cache-control: no-store`.

Demo bundle: `scripts/bundle-demo.ts` uses `loadRepo` on `../../demo/vulnerable-app` and writes `src/demoRepo.generated.json` (`RepoSnapshot`). Add it to the api `build` flow by documenting `npx tsx scripts/bundle-demo.ts` in `infra/README.md` (do not edit package.json). If the demo folder has no server.js yet, the script still writes whatever files exist.

Tests (`apps/api/test/router.test.ts`, Vitest, `STORAGE=local` into a temp dir via env `DATA_DIR`): health; create scan on a tiny repo with a hardcoded key → report has failing `secrets-in-repo`; 400 on `..` path; 400 on >500 files; 404 unknown id; patches → scoreAfter > scoreBefore and every recorded guard ok; download returns only approved files.

`infra/template.yaml` (AWS SAM, all free-tier friendly): `AWS::Serverless::HttpApi` with CORS for the CloudFront domain + localhost:5173; one `AWS::Serverless::Function` nodejs22.x arm64, 512 MB, 30 s timeout, `CodeUri: ../apps/api/dist`, handler `lambda.handler`, env `STORAGE=dynamo`, `TABLE_NAME`; `AWS::DynamoDB::Table` PAY_PER_REQUEST with TTL on `expiresAt`; private S3 bucket for the web build + CloudFront distribution with Origin Access Control, default root `index.html`, SPA 403/404 → `/index.html`, and a second origin/behavior `/api/*` → the HttpApi. Outputs: ApiUrl, SiteUrl, BucketName. `infra/README.md`: exact deploy steps (`npm run build`, `sam build`, `sam deploy --guided`, `aws s3 sync apps/web/dist s3://<bucket>`, CloudFront invalidation) and a cost note (all within free tier at demo traffic; Bedrock not used).

Done when `npm test -w @siidekick/api` passes, `npx tsc --noEmit -p apps/api` (write `apps/api/tsconfig.json` like the engine's, `noEmit`) is clean, and `npm run build -w @siidekick/api` produces `dist/lambda.mjs`.
