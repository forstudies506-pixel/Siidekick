// node_modules for the attack replay's child processes (express + lodash), next to the Lambda bundle.
// A Node script rather than shell, so `npm run build` works from cmd.exe on Windows too.
import { build } from "esbuild";
import { copyFileSync, mkdirSync } from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
await build({
  stdin: { contents: "module.exports=require('express')", resolveDir: process.cwd() },
  bundle: true,
  platform: "node",
  target: "node20",
  format: "cjs",
  minify: true,
  logLevel: "warning",
  outfile: "dist/runtime/node_modules/express/index.js",
});
mkdirSync("dist/runtime/node_modules/lodash", { recursive: true });
copyFileSync(require.resolve("lodash/lodash.js"), "dist/runtime/node_modules/lodash/index.js");
copyFileSync("src/demoRepo.generated.json", "dist/demoRepo.generated.json");
