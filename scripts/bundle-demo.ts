import { writeFile, mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { loadRepo } from "@siidekick/engine";

const __dirname = dirname(fileURLToPath(import.meta.url));

/** Bundles the demo repo into apps/api/src/demoRepo.generated.json so the API can
 * scan it without reading the filesystem at request time. */
async function main(): Promise<void> {
  const demoRoot = join(__dirname, "..", "demo", "vulnerable-app");
  const out = join(__dirname, "..", "apps", "api", "src", "demoRepo.generated.json");
  const repo = await loadRepo(demoRoot);
  await mkdir(dirname(out), { recursive: true });
  await writeFile(out, JSON.stringify(repo, null, 2), "utf8");
  console.log(`Bundled ${repo.files.length} file(s) from ${demoRoot} into ${out}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
