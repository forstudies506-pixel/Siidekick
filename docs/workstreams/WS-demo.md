# WS-demo — deliberately vulnerable demo app (owner: kilo)

**Own:** `demo/vulnerable-app/**` only. Its `package.json` already exists (express 4, lodash 4.17.15). Do not edit package.json.

Build a small, realistic-looking Express app ("CampusKart", a college-fest merch shop) that Siidekick scans live in the demo. It must look like real student code: no comments that mention flaws, vulnerabilities or "planted".

1. `server.js` (CommonJS): `const app = express();` on its own line. Use the built-in `node:sqlite` (`const { DatabaseSync } = require('node:sqlite')`), in-memory DB seeded with 3 users and 6 products. `module.exports = app;` and only `app.listen(process.env.PORT || 3000)` when `require.main === module`.
2. Plant exactly these 8 flaws:
   1. Hardcoded key: `const PAYMENT_API_KEY = "pk_demo_9f8a7b6c5d4e3f2a1b0c";` used in a `/checkout` handler.
   2. String-built SQL in `GET /api/products?q=`: `db.prepare("SELECT * FROM products WHERE name LIKE '%" + req.query.q + "%'").all()`.
   3. No security headers (no helmet, nothing sets CSP/HSTS/X-Frame-Options).
   4. Open CORS: a middleware doing `res.setHeader('Access-Control-Allow-Origin', '*')`.
   5. No rate limit on `POST /login` (JSON body `{email,password}`, plain compare is fine for the demo).
   6. Public admin route: `GET /admin/users` returns all users with no auth middleware.
   7. Outdated package: `const _ = require('lodash');` and use `_.merge` on a request body in `POST /api/cart`.
   8. Heavy login page: `public/login.html` served by `express.static('public')`, with a CSS `@keyframes` that animates `left` and `top` (not transform) on a large decorative element, plus a 300+ line inline script that runs on load.
3. No `/health` route, no error-handling middleware, no `.github/workflows`. Do include a short `README.md` for the demo.
4. `test/app.test.js` using `node:test` + `assert` + global `fetch`, starting the app on port 0: `GET /` 200, `POST /login` with a seeded user returns 200 and with a bad password 401, `GET /api/products?q=tee` returns an array. These are "the user's existing tests" that must still pass after Siidekick patches.
5. `FLAWS.md`: table of the 8 flaws → file:line → Siidekick check id: `secrets-in-repo`, `sql-string-concat`, `security-headers`, `open-cors`, `rate-limit`, `auth-on-endpoints`, `dependency-audit`, `ui-heavy-animation`.

Done when `npm test -w @siidekick/vulnerable-app` passes and `node demo/vulnerable-app/server.js` serves `/` and `/login.html`.
