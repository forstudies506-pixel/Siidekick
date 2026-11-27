// Builds the Lambda bundle into dist/. Plain Node so it runs the same on Windows, macOS and Linux.
//   dist/lambda.mjs                      the API handler, engine inlined
//   dist/demoRepo.generated.json         the bundled demo shop
//   dist/runtime/node_modules/{express,lodash}   what the attack replay's child processes require
import { build } from "esbuild";
import { copyFileSync, mkdirSync, rmSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const dist = join(root, "dist");
const require = createRequire(join(root, "package.json"));

rmSync(dist, { recursive: true, force: true });
mkdirSync(dist, { recursive: true });

await build({
  entryPoints: [join(root, "src/lambda.ts")],
  bundle: true,
  platform: "node",
  target: "node20",
  format: "esm",
  outfile: join(dist, "lambda.mjs"),
  external: ["@aws-sdk/*"],
  // Some bundled CommonJS deps call require(); give the ESM bundle one.
  banner: { js: "import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);" },
});

copyFileSync(join(root, "src/demoRepo.generated.json"), join(dist, "demoRepo.generated.json"));

const runtime = join(dist, "runtime/node_modules");
await build({
  stdin: { contents: "module.exports = require('express');", resolveDir: root, loader: "js" },
  bundle: true,
  platform: "node",
  target: "node20",
  format: "cjs",
  minify: true,
  logLevel: "warning",
  outfile: join(runtime, "express/index.js"),
});
mkdirSync(join(runtime, "lodash"), { recursive: true });
copyFileSync(require.resolve("lodash/lodash.js"), join(runtime, "lodash/index.js"));

console.log("built", dist);
