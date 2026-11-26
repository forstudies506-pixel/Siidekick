# Siidekick HTTP API

Same router everywhere: `apps/api/src/router.ts` (`makeRouter`). Served by `local.ts` (node:http), `lambda.ts` (AWS) and `vercel.ts` (live at https://siidekick.ashforge.cv). All bodies are JSON. Errors are `{ "error": "<reason>" }`.

Storage: `STORAGE=local` writes records to `DATA_DIR`. On Vercel that is `/tmp/siidekick`, one copy per function instance, so a scan id can return 404 after the instance recycles. `STORAGE=dynamo` (AWS build) keeps records 7 days.

## Endpoints

| Method and path | Body | Answer |
|---|---|---|
| `GET /api/health` | none | `{ ok: true, checks }` |
| `GET /api/checks` | none | `{ repo: CheckInfo[], site: CheckInfo[] }`, read from the engine registry. Today 19 repo and 16 site checks |
| `POST /api/sites` | `{ url }` (1 to 2048 chars) | `201 { id, report, kind: "site", site: { url, finalUrl, fetchedAt } }` |
| `POST /api/scans` | `{ name, files: [{ path, content }] }` | `201 { id, report }`. At most 500 files and 2 MB; paths relative POSIX, no `..`, no NUL |
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

## `POST /api/sites` in detail

A passive read of a public website: the page, its same-origin scripts (at most 8), the `http://` redirect, `/.well-known/security.txt`, and up to 4 linked source maps. Nothing on the site is run and no attack traffic is sent.

- Every hop, redirects included (at most 5), is checked against private and reserved address space when the socket connects, so a hostname that rebinds to an internal address is refused.
- Limits: 1.5 MB of HTML, 1 MB per script, 8 s per hop, 20 s for the whole scan.
- At most 20 site scans a minute per server instance; past that, `429`.
- Errors: `400` for a private address or an unusable URL, `502` for an unreadable redirect or too many redirects, `504` for a timeout.
- The page body is not stored. The record keeps only the report and `{ url, finalUrl, fetchedAt }`.
- Site findings are a report only: a site has no patches, so `/patches`, `/prove` and `/download` do not apply.

```bash
curl -s -X POST https://siidekick.ashforge.cv/api/sites \
  -H 'Content-Type: application/json' -d '{"url":"example.com"}'
```

## `GET /api/checks` in detail

The landing page reads this list, so it always shows what a scan runs. Nothing in the web app hardcodes it.

```bash
curl -s https://siidekick.ashforge.cv/api/checks
```
