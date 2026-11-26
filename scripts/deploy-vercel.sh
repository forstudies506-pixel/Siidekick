#!/usr/bin/env bash
# Builds the web app and the API into Vercel's Build Output API (v3) layout and deploys it.
# Usage: scripts/deploy-vercel.sh [--prod]
# scripts/deploy.sh is the AWS SAM path; this one needs no AWS credentials.
set -euo pipefail
cd "$(dirname "$0")/.."

PROJECT="${VERCEL_PROJECT:-siidekick}"
OUT=".vercel-deploy"
FUNC="$OUT/.vercel/output/functions/api.func"

npm run build -w @siidekick/engine
npx tsx scripts/bundle-demo.ts
npm run build -w @siidekick/api
npm run build -w @siidekick/web

rm -rf "$OUT/.vercel/output"
mkdir -p "$OUT/.vercel/output/static" "$FUNC"
cp -R apps/web/dist/. "$OUT/.vercel/output/static/"

# The AWS SDK is bundled, not external: Vercel's runtime does not ship it.
npx esbuild apps/api/src/vercel.ts --bundle --platform=node --target=node22 --format=esm \
  --banner:js="import{createRequire as __cr}from'module';const require=__cr(import.meta.url);" \
  --outfile="$FUNC/index.mjs" --log-level=warning
cp apps/api/src/demoRepo.generated.json "$FUNC/"
# express + lodash for the attack replay child processes (router.ts looks for ./runtime/node_modules).
cp -R apps/api/dist/runtime "$FUNC/runtime"

cat > "$FUNC/.vc-config.json" <<'JSON'
{ "runtime": "nodejs22.x", "handler": "index.mjs", "launcherType": "Nodejs", "shouldAddHelpers": false, "maxDuration": 60 }
JSON

cat > "$OUT/.vercel/output/config.json" <<'JSON'
{
  "version": 3,
  "routes": [
    { "src": "^/api/(.*)$", "dest": "/api" },
    { "handle": "filesystem" },
    { "src": "^/(.*)$", "dest": "/index.html" }
  ]
}
JSON

if [[ ! -f "$OUT/.vercel/project.json" ]]; then
  (cd "$OUT" && vercel link --yes --project "$PROJECT")
fi

(cd "$OUT" && vercel deploy --prebuilt "$@")
