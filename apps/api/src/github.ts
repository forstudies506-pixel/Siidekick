import { gunzipSync } from "node:zlib";
import type { RepoSnapshot } from "@siidekick/engine";

const OWNER_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPO_RE = /^[A-Za-z0-9._-]{1,100}$/;
const REF_RE = /^[A-Za-z0-9._/-]{1,100}$/;

export interface GithubLimits {
  compressed: number;
  tar: number;
  fileBytes: number;
  files: number;
  totalBytes: number;
  timeoutMs: number;
}

/** The synchronous API path: small enough to scan inside one HTTP request. */
export const QUICK_LIMITS: GithubLimits = { compressed: 10 * 1024 * 1024, tar: 30 * 1024 * 1024, fileBytes: 512 * 1024, files: 500, totalBytes: 2 * 1024 * 1024, timeoutMs: 10_000 };
/** The AWS pipeline's full scan (Lambda with 15 minutes and 3 GB): every text file of a normal repo. */
export const FULL_LIMITS: GithubLimits = { compressed: 120 * 1024 * 1024, tar: 600 * 1024 * 1024, fileBytes: 1024 * 1024, files: 25_000, totalBytes: 80 * 1024 * 1024, timeoutMs: 60_000 };
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "coverage", "vendor"]);

export class GithubError extends Error {}

export function parseGithubUrl(input: string): { owner: string; repo: string; ref: string } | null {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return null;
  }
  if (url.protocol !== "https:") return null;
  if (url.hostname !== "github.com") return null;
  if (url.port !== "") return null;
  if (url.username || url.password) return null;
  if (url.search || url.hash) return null;

  const segs = url.pathname.split("/");
  if (segs[0] === "") segs.shift();
  if (segs.length > 0 && segs[segs.length - 1] === "") segs.pop();
  if (segs.length < 2) return null;

  const owner = segs[0];
  let repo = segs[1];
  if (repo.endsWith(".git")) repo = repo.slice(0, -4);
  if (!OWNER_RE.test(owner)) return null;
  if (!REPO_RE.test(repo) || repo === "." || repo === "..") return null;

  let ref = "HEAD";
  if (segs.length > 2) {
    if (segs[2] !== "tree") return null;
    const refParts = segs.slice(3);
    if (refParts.length === 0) return null;
    ref = refParts.join("/");
    if (!REF_RE.test(ref)) return null;
    if (ref.split("/").includes("..")) return null;
  }

  return { owner, repo, ref };
}

async function readCapped(res: Response, cap: number): Promise<Buffer> {
  const reader = res.body?.getReader();
  if (!reader) {
    const ab = await res.arrayBuffer();
    if (ab.byteLength > cap) throw new GithubError("repo too large");
    return Buffer.from(ab);
  }
  const chunks: Buffer[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > cap) {
      await reader.cancel();
      throw new GithubError("repo too large");
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks, total);
}

function field(buf: Buffer, off: number, len: number): string {
  let end = off;
  const max = off + len;
  while (end < max && buf[end] !== 0) end++;
  return buf.toString("utf8", off, end);
}

function parsePaxPath(data: Buffer): string | null {
  let i = 0;
  while (i < data.length) {
    const sp = data.indexOf(0x20, i);
    if (sp < 0) break;
    const len = parseInt(data.toString("utf8", i, sp), 10);
    if (!Number.isFinite(len) || len <= 0) break;
    let record = data.toString("utf8", sp + 1, i + len);
    if (record.endsWith("\n")) record = record.slice(0, -1);
    if (record.startsWith("path=")) return record.slice(5);
    i += len;
  }
  return null;
}

function isZeroBlock(block: Buffer): boolean {
  for (let i = 0; i < block.length; i++) if (block[i] !== 0) return false;
  return true;
}

function safePath(path: string): boolean {
  if (path.includes("\0")) return false;
  if (path.startsWith("/")) return false;
  return !path.split("/").includes("..");
}

function shouldSkip(path: string): boolean {
  const segs = path.split("/");
  for (const seg of segs) if (SKIP_DIRS.has(seg)) return true;
  const base = segs[segs.length - 1];
  if (base === ".env" || (base.startsWith(".env.") && base !== ".env.example")) return true;
  return false;
}

function stripTopDir(path: string): string {
  const idx = path.indexOf("/");
  return idx < 0 ? "" : path.slice(idx + 1);
}

function parseTar(tar: Buffer, lim: GithubLimits = QUICK_LIMITS): { files: RepoSnapshot["files"]; omitted: number } {
  const files: RepoSnapshot["files"] = [];
  let total = 0;
  let omitted = 0;
  let pendingPaxPath: string | null = null;
  let zeroBlocks = 0;
  let off = 0;

  while (off + 512 <= tar.length) {
    const header = tar.subarray(off, off + 512);
    if (isZeroBlock(header)) {
      zeroBlocks++;
      if (zeroBlocks >= 2) break;
      off += 512;
      continue;
    }
    zeroBlocks = 0;

    const name = field(header, 0, 100);
    const prefix = field(header, 345, 155);
    const size = parseInt(field(header, 124, 12).trim(), 8) || 0;
    if (size < 0) break;
    const typeflag = header[156];
    const dataStart = off + 512;
    const dataEnd = dataStart + size;
    const next = dataStart + Math.ceil(size / 512) * 512;
    if (dataEnd > tar.length) break;

    const type = String.fromCharCode(typeflag);
    if (type === "x") {
      pendingPaxPath = parsePaxPath(tar.subarray(dataStart, dataEnd));
    } else if (type === "0" || type === "\0") {
      let full = prefix ? `${prefix}/${name}` : name;
      if (pendingPaxPath) {
        full = pendingPaxPath;
        pendingPaxPath = null;
      }
      const rel = stripTopDir(full);
      if (rel && safePath(rel) && !shouldSkip(rel)) {
        const content = tar.subarray(dataStart, dataEnd);
        if (content.length <= lim.fileBytes && !content.subarray(0, 8192).includes(0)) {
          const text = content.toString("utf8");
          const bytes = Buffer.byteLength(text, "utf8");
          // Past the caps, keep reading so the count is exact, but keep no more text.
          if (files.length >= lim.files || total + bytes > lim.totalBytes) {
            omitted++;
          } else {
            total += bytes;
            files.push({ path: rel, content: text });
          }
        }
      }
      pendingPaxPath = null;
    } else {
      pendingPaxPath = null;
    }

    off = next;
  }

  return { files, omitted };
}

export async function fetchGithubRepo(
  input: string,
  deps?: { fetch?: typeof fetch; limits?: GithubLimits },
): Promise<RepoSnapshot & { omitted: number }> {
  const lim = deps?.limits ?? QUICK_LIMITS;
  const parsed = parseGithubUrl(input);
  if (!parsed) throw new GithubError("not a valid public GitHub repo URL");
  const { owner, repo, ref } = parsed;
  const doFetch = deps?.fetch ?? fetch;

  const url = `https://codeload.github.com/${owner}/${repo}/tar.gz/${ref}`;
  let res: Response;
  try {
    res = await doFetch(url, { redirect: "error", signal: AbortSignal.timeout(lim.timeoutMs) });
  } catch {
    throw new GithubError("repo not found or not public");
  }
  if (res.status !== 200) throw new GithubError("repo not found or not public");

  const compressed = await readCapped(res, lim.compressed);
  let tar: Buffer;
  try {
    tar = gunzipSync(compressed, { maxOutputLength: lim.tar });
  } catch {
    throw new GithubError("repo too large");
  }

  const { files, omitted } = parseTar(tar, lim);
  return { name: `${owner}/${repo}`, files, omitted };
}