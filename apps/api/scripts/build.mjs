// Lambda bundles for the API and the pipeline, plus the replay runtime.
// The banner gives the ESM bundle a real `require`, which CommonJS dependencies (yaml, redis …)
// call for Node built-ins; without it the bundle throws "Dynamic require of … is not supported".
import { build } from "esbuild";

export const requireBanner = "import { createRequire as __createRequire } from 'node:module'; const require = __createRequire(import.meta.url);";

await build({
  entryPoints: ["src/lambda.ts", "src/pipeline.ts"],
  bundle: true,
  platform: "node",
  target: "node20",
  format: "esm",
  outdir: "dist",
  outExtension: { ".js": ".mjs" },
  external: ["@aws-sdk/*"],
  banner: { js: requireBanner },
  logLevel: "info",
});
await import("./build-runtime.mjs");
