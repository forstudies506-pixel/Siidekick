# Siidekick GitHub Action

Runs a Siidekick security scan on every push and pull request. Findings appear as annotations on the changed lines and in the job summary, with a link to the full report: fixes, the India lens, and AI explanations in eight Indian languages.

```yaml
name: Siidekick
on:
  push:
    branches: [main]
  pull_request:
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: forstudies506-pixel/Siidekick/action@main   # pin a commit SHA for production use
        with:
          fail-on: none   # or critical / high / medium to fail the check
```

| Input | Default | What it does |
| --- | --- | --- |
| `fail-on` | `none` | Fail the job when a finding of this severity or worse is present: `none`, `critical`, `high`, `medium`. |
| `path` | `.` | Folder to scan, relative to the repo root. |
| `api-url` | the live Siidekick API on AWS | Where the scan runs. |

Outputs: `score` (0–100) and `scan-url` (the full report).

**What leaves the runner:** the repo's text files (up to 500 files and 2 MB, package manifests and source first) are sent to the Siidekick API, read as text and never run; scan records expire after 7 days. `.env` files are never sent: a committed one is reported from the runner itself. Binary files, `node_modules`, build output and files over 512 KB are skipped.

Siidekick reduces risk; it does not make an app secure.
