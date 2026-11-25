# WS-web-landing — landing page + dashboard (owner: copilot)

**Own:** `apps/web/**` (except `package.json`). Installed: React 19, Vite 8, TypeScript, `lucide-react`, `motion`. No router, no Tailwind, no component library: plain CSS with custom properties.

Files to create: `index.html`, `vite.config.ts` (react plugin; dev proxy `/api` → `http://localhost:8787`), `tsconfig.json`, `src/main.tsx`, `src/styles.css`, `src/pages/Landing.tsx`, `src/pages/Dashboard.tsx`, `src/components/*`, `src/api/client.ts`, `src/api/mock.ts`. Route by `location.pathname`: `/` landing, `/app` dashboard.

Types: `import type { ScanReport, CheckResult, Patch, GuardResult } from "../../../../packages/engine/src/types"` (type-only, erased at build). A diff line is `{ type: "same" | "add" | "del"; text: string }`.

API (`src/api/client.ts`): `createDemoScan()` → `POST /api/scans/demo`; `uploadScan(name, files)` → `POST /api/scans`; `getScan(id)`; `generatePatches(id)` → `POST /api/scans/:id/patches` returning `{ patches: [{ patch, guard, diff: [{ path, lines }] }], scoreBefore, scoreAfter, status }`; `approve(id, patchId)`; `download(id)`. If `import.meta.env.VITE_MOCK === "1"` or the API call fails with a network error, use `src/api/mock.ts` (realistic data: score 31 → 88, 8 findings across the checks `secrets-in-repo`, `sql-string-concat`, `security-headers`, `open-cors`, `rate-limit`, `auth-on-endpoints`, `dependency-audit`, `ui-heavy-animation`, and one patch whose guard is rejected to show the guard working). Show a small "demo data" badge when mock is used.

Product: **Siidekick** scans a small website's repo, explains each risk in plain words, and proposes small add-only patches. A diff guard blocks any patch that deletes the owner's code. The owner approves each patch. Audience: Indian student founders, college clubs and fest sites, small shops, NGOs. Tone: plain, confident, honest ("risk reduced", never "unhackable" or "100% secure").

**Design direction (follow strictly):** dark graphite with amber; soft neo-brutalism; editorial. Every colour has a job: amber = action/added lines, red = blocked/deleted, green only for "passed". Tokens as CSS variables (OKLCH), e.g. bg `oklch(0.18 0.005 260)`, surface `oklch(0.23 0.006 260)`, ink `oklch(0.95 0.01 90)`, muted `oklch(0.7 0.01 90)`, amber `oklch(0.8 0.16 75)`, red `oklch(0.65 0.2 25)`, green `oklch(0.75 0.15 150)`. Fonts: Schibsted Grotesk (UI) + JetBrains Mono (code, numbers) from Google Fonts. Thick 2px ink borders, small radius (6px), hard offset shadows (`4px 4px 0` darker tone), underlines as a brand mark. **Reject:** gradient hero, three-feature-card row, stock illustrations, glassmorphism, emoji icons, animation for show.

Landing (`/`):
1. Hero: left, headline "We never replace your code." with "never" underlined in amber, one-line sub, primary button "Scan the demo shop" → `/app?demo=1`, secondary "Upload a repo" → `/app`. Right: a real-looking diff card where an amber `+ require('./security')(app);` line is added and a red struck-through `- app.get('/admin/users', …)` line carries a stamp "BLOCKED BY DIFF GUARD".
2. "How it works" as a numbered editorial strip (not cards): Scan → Explain → Patch (add-only) → Guard → You approve → Rescan.
3. "What it checks": compact table of the 12 checks with group and severity chips.
4. "Who it's for": short paragraph on Indian student teams, clubs, small shops, with an honest line on limits (it reduces risk, it does not certify).
5. Footer: built on AWS (Lambda, API Gateway, DynamoDB, S3, CloudFront), GitHub link `https://github.com/forstudies506-pixel/Siidekick`.
Motion: only a short fade/slide on the hero diff lines and a counting score; respect `prefers-reduced-motion`.

Dashboard (`/app`):
- Start panel: "Use demo shop" button and a folder upload (`<input type="file" webkitdirectory>`): read text files in the browser, skip `node_modules/`, `.git/`, files >512 KB and binaries, max 500 files, then `uploadScan`.
- Report: big score (mono, 0–100) with passed/total; results grouped by group (A–G), each row: check title, severity chip, pass/fail, findings (file:line, evidence, explanation) expandable.
- "Generate fixes" → patch list: each patch shows title, class (additive / minimal-edit), reason, guard verdict (`+added / −removed`, violations), and the diff with amber add / red del lines in mono. Approve button per patch (disabled when guard failed). After: score before → after and status chip ("rescan clean — tests not run" or "partial"). "Download approved files" saves a JSON file.
- Loading, empty and error states for every request. Keyboard reachable, visible focus, contrast AA. Works at 375px and 1280px.

No `dangerouslySetInnerHTML`. Render file contents as text only.

Done when `npm run build -w @siidekick/web` passes and `npx vite` (in apps/web) with `VITE_MOCK=1` shows both pages working with the mock data.
