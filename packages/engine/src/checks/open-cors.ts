import type { Check, FileEdit, Finding, Patch, RepoFile } from "../types.js";

const SKIP = /(^|\/)node_modules\//;
/** The one expression the fixer writes: a single, configurable origin. */
const ORIGIN_EXPR = "process.env.ALLOWED_ORIGIN || 'http://localhost:3000'";

interface CorsHit {
  file: string;
  line: number;
}

/** Wildcard origin set as a header, a bare cors() call (defaults to any origin), or origin: '*'. */
function isOffending(line: string): boolean {
  if (/Access-Control-Allow-Origin/i.test(line) && /['"]\*['"]/.test(line)) return true;
  if (/\bcors\s*\(\s*\)/.test(line)) return true;
  if (/origin\s*:\s*['"]\*['"]/i.test(line)) return true;
  return false;
}

function findHits(files: RepoFile[]): CorsHit[] {
  const hits: CorsHit[] = [];
  for (const f of files) {
    if (SKIP.test(f.path)) continue;
    const lines = f.content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      if (isOffending(lines[i])) hits.push({ file: f.path, line: i + 1 });
    }
  }
  return hits;
}

/** Swap the wildcard for the configured origin; for a bare cors(), pass explicit options. */
function replaceWildcard(line: string): string {
  if (/['"]\*['"]/.test(line)) return line.replace(/(['"])\*\1/, ORIGIN_EXPR);
  if (/\bcors\s*\(\s*\)/.test(line)) return line.replace(/\bcors\s*\(\s*\)/, `cors({ origin: ${ORIGIN_EXPR} })`);
  return line;
}

export const openCors: Check = {
  id: "open-cors",
  group: "C-security",
  title: "CORS origin restriction",
  severity: "medium",
  mode: "auto",

  detect({ repo }): Finding[] {
    return findHits(repo.files).map((h) => ({
      checkId: "open-cors",
      title: "Wildcard CORS origin",
      severity: "medium" as const,
      file: h.file,
      line: h.line,
      evidence: "origin configured as '*' (any website)",
      explanation:
        "A wildcard origin lets any website call this API with the visitor's credentials. Restricting it to the configured origin reduces that risk; it holds only while ALLOWED_ORIGIN is set correctly.",
    }));
  },

  fix({ repo }): Patch | null {
    const hits = findHits(repo.files);
    if (hits.length === 0) return null;

    // Group by file: one modify edit per file, recomputed from the current content.
    const byFile = new Map<string, { file: RepoFile; lines: number[] }>();
    for (const h of hits) {
      const file = repo.files.find((f) => f.path === h.file)!;
      const entry = byFile.get(h.file) ?? { file, lines: [] };
      entry.lines.push(h.line);
      byFile.set(h.file, entry);
    }

    const edits: FileEdit[] = [];
    const removals: string[] = [];
    for (const [path, { file, lines: lineNos }] of byFile) {
      const lines = file.content.split("\n");
      for (const no of lineNos) {
        const original = lines[no - 1];
        const replaced = replaceWildcard(original);
        if (replaced === original) continue;
        lines[no - 1] = replaced;
        removals.push(original.trim());
      }
      const after = lines.join("\n");
      if (after !== file.content) edits.push({ kind: "modify", path, before: file.content, after });
    }
    if (edits.length === 0) return null;

    return {
      id: "open-cors-1",
      checkId: "open-cors",
      title: "Restrict CORS to the configured origin",
      class: "minimal-edit",
      reason:
        "A wildcard origin lets any site call this API with the visitor's credentials. Each changed line now uses ALLOWED_ORIGIN (default http://localhost:3000); risk reduced as long as that variable is set for every deployment.",
      edits,
      allowedRemovals: removals,
    };
  },
};
