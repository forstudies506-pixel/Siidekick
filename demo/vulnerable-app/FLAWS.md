# FLAWS

Planted flaws in CampusKart, mapped to Siidekick check ids.

| # | Flaw | File:line | Check id |
|---|------|-----------|----------|
| 1 | Hardcoded payment API key used in `/checkout` | `server.js:33` | `secrets-in-repo` |
| 2 | String-built SQL in `GET /api/products?q=` | `server.js:51` | `sql-string-concat` |
| 3 | No security headers (CSP/HSTS/X-Frame-Options) | `server.js:11` | `security-headers` |
| 4 | Open CORS (`Access-Control-Allow-Origin: *`) | `server.js:12` | `open-cors` |
| 5 | No rate limit on `POST /login` | `server.js:39` | `rate-limit` |
| 6 | Public admin route `GET /admin/users` with no auth | `server.js:64` | `auth-on-endpoints` |
| 7 | Outdated lodash with `_.merge` on request body in `POST /api/cart` | `server.js:3` | `dependency-audit` |
| 8 | Heavy login page with `left`/`top` keyframe animation and 300+ line inline script | `public/login.html` | `ui-heavy-animation` |
| 9 | Shopping assistant depends on `react-chatbot-openai-helper`, a package that does not exist on npm (an AI-invented name an attacker could register) | `assistant/package.json:9` | `hallucinated-package` |
| 10 | OpenAI key read from `VITE_OPENAI_API_KEY` and the SDK told to run in the browser | `assistant/src/chat.js:5` | `client-exposed-secrets` |
| 11 | Firestore rules left open: anyone can read and write orders | `firestore.rules:6` | `baas-open-rules` |
| 12 | JWT secret falls back to a value in the code, and expired tokens are accepted | `lib/session-token.js:4` | `jwt-misuse` |

Flaws 9–12 live in files `server.js` never loads, so the running demo and its tests are unchanged. `assistant/` is outside the npm workspace glob and is never installed.
