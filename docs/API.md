# Siidekick HTTP API

Same router everywhere: `apps/api/src/router.ts` (`makeRouter`). Served by `local.ts` (node:http), `lambda.ts` (AWS) and `vercel.ts` (live at https://siidekick.ashforge.cv). All bodies are JSON. Errors are `{ "error": "<reason>" }`.

Storage (`GET /api/health` reports which one as `storage`):

- `STORAGE=upstash`: Upstash Redis over its REST API, records kept 7 days. Needs `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN` (the `KV_REST_API_URL` / `KV_REST_API_TOKEN` names also work). The Vercel build picks it on its own when both are set.
- `STORAGE=redis`: Redis over TCP (`redis://` or `rediss://`), records kept 7 days, at most 1 MB per record after gzip. Needs `KV_REDIS_URL` (set by the Vercel Redis integration with the `KV` prefix) or `REDIS_URL`. The Vercel build picks it when Upstash is not set. Live uses this.
- `STORAGE=local` writes records to `DATA_DIR`. On Vercel without Upstash or Redis that is `/tmp/siidekick`, one copy per function instance, so a scan id can return 404 after the instance recycles.
- `STORAGE=dynamo` (AWS build) keeps records 7 days.

## Endpoints

| Method and path | Body | Answer |
|---|---|---|
| `GET /api/health` | none | `{ ok: true, checks, storage }` |
| `GET /api/checks` | none | `{ repo: CheckInfo[] }`, read from the engine registry |
| `POST /api/scans` | `{ name, files: [{ path, content }] }` | `201 { id, report }`. At most 3000 files and 4.5 MB (one request; GitHub scans read up to 3000 files and 10 MB); paths relative POSIX, no `..`, no NUL |
| `POST /api/scans/github` | `{ url }` (public github.com repo, ≤300 chars) | `201 { id, report, omitted? }`. `omitted` counts text files left out past the size caps |
| `POST /api/scans/demo` | none | `201 { id, report }` for the bundled demo shop; the record is marked `demo: true` |
| `GET /api/scans/:id` | none | `{ id, report, patches?, after?, omitted?, demo, kind?, site?, approvedSummary? }` |
| `POST /api/scans/:id/patches` | none | `{ patches: [{ patch, guard, diff }], scoreBefore, scoreAfter, status }`. `status` is `rescan-clean` or `partial`, never `verified`: no tests run on the server |
| `POST /api/scans/:id/patches/:patchId/approve` | none | `{ approved, score, passed, total, failing }` from a rescan with only the approved patches. `409` if the guard blocked the patch |
| `POST /api/scans/:id/patches/:patchId/check` | `{ edits: FileEdit[] }` (≤20) | `{ guard, diff }`. Runs an edited patch through the diff guard; nothing is stored |
| `POST /api/scans/:id/prove` | none | `ReplayReport` (attacks, paths, tests, ms). `409` for any record that is not a demo scan |
| `GET /api/scans/:id/download` | none | `{ files: [{ path, content }] }`: files the approved patches touch, plus `.siidekick/*.patch` and `SIIDEKICK_LOG.md` |

`CheckInfo` is `{ id, title, group, severity }`. `group` is one of `A-delivery`, `B-monitoring`, `C-security`, `D-domain`, `E-states`, `F-ai`, `G-enterprise`. `severity` is `critical`, `high`, `medium`, `low` or `info`.

`:id` must be a UUID (`400 invalid id`); an unknown one is `404 not found`.

## `GET /api/checks` in detail

The landing page reads this list, so it always shows what a scan runs. Nothing in the web app hardcodes it.

```bash
curl -s https://siidekick.ashforge.cv/api/checks
```

## Removed

`POST /api/sites` (passive website scans) was removed on 2026-11-28: Siidekick scans source code only. It returns `404`.
