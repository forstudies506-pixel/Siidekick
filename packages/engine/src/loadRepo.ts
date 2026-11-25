import { readdir, readFile, stat } from "node:fs/promises";
import { basename, join, relative, sep } from "node:path";
import type { RepoSnapshot } from "./types.js";

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", "coverage", ".data"]);
const MAX_BYTES = 512 * 1024;

/** Reads a local folder into memory. Text files only; nothing is executed. */
export async function loadRepo(root: string): Promise<RepoSnapshot> {
  const files: RepoSnapshot["files"] = [];
  async function walk(dir: string): Promise<void> {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) await walk(full);
      } else if (entry.isFile()) {
        if ((await stat(full)).size > MAX_BYTES) continue;
        const buf = await readFile(full);
        if (buf.includes(0)) continue; // binary
        files.push({ path: relative(root, full).split(sep).join("/"), content: buf.toString("utf8") });
      }
    }
  }
  await walk(root);
  files.sort((a, b) => a.path.localeCompare(b.path));
  return { name: basename(root), files };
}
