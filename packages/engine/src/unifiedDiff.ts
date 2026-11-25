import { diffLines, type DiffLine } from "./diffGuard.js";
import { applyPatch } from "./apply.js";
import { secretValues } from "./checks/secrets.js";
import { redact } from "./util.js";
import type { Patch, RepoFile, RepoSnapshot } from "./types.js";

// Marks a last line that had no trailing "\n", so it differs from the same text with one (git does the same).
const NOEOL = "\0";

/** Splits on "\n" only, so CRLF files keep their "\r" and the patch applies byte for byte. */
function split(s: string): string[] {
  if (s === "") return [];
  const l = s.split("\n");
  if (l[l.length - 1] === "") l.pop();
  else l[l.length - 1] += NOEOL;
  return l;
}

function emit(out: string[], prefix: string, text: string) {
  if (text.endsWith(NOEOL)) {
    out.push(prefix + text.slice(0, -1), "\\ No newline at end of file");
  } else {
    out.push(prefix + text);
  }
}

const range = (start: number, count: number) => (count === 1 ? `${start}` : `${start},${count}`);

/**
 * Git-style unified diff for one file. `before` null means the file is new.
 * unifiedFileDiff("a.js", null, "x\n") -> "diff --git a/a.js b/a.js\nnew file mode 100644\n--- /dev/null\n+++ b/a.js\n@@ -0,0 +1 @@\n+x\n"
 */
export function unifiedFileDiff(path: string, before: string | null, after: string, context = 3): string {
  const ops: DiffLine[] = diffLines(split(before ?? ""), split(after));
  const changed = ops.flatMap((o, i) => (o.type === "same" ? [] : [i]));
  if (changed.length === 0 && before !== null) return "";

  const out = [`diff --git a/${path} b/${path}`];
  if (before === null) out.push("new file mode 100644", "--- /dev/null");
  else out.push(`--- a/${path}`);
  out.push(`+++ b/${path}`);

  // Group changes whose gap of unchanged lines is small enough that their context would overlap.
  const groups: Array<[number, number]> = [];
  for (const i of changed) {
    const last = groups[groups.length - 1];
    if (last && i - last[1] - 1 <= 2 * context) last[1] = i;
    else groups.push([i, i]);
  }

  // Line numbers (1-based) of each op in the old and new file.
  const oldAt: number[] = [];
  const newAt: number[] = [];
  let o = 1;
  let n = 1;
  for (const op of ops) {
    oldAt.push(o);
    newAt.push(n);
    if (op.type !== "add") o++;
    if (op.type !== "del") n++;
  }

  for (const [first, last] of groups) {
    const start = Math.max(0, first - context);
    const end = Math.min(ops.length, last + 1 + context);
    const slice = ops.slice(start, end);
    const oc = slice.filter((x) => x.type !== "add").length;
    const nc = slice.filter((x) => x.type !== "del").length;
    // An empty side is numbered by the line before it, as git expects ("-0,0" for a new file).
    const os = oc === 0 ? oldAt[start] - 1 : oldAt[start];
    const ns = nc === 0 ? newAt[start] - 1 : newAt[start];
    out.push(`@@ -${range(os, oc)} +${range(ns, nc)} @@`);
    for (const x of slice) emit(out, x.type === "same" ? " " : x.type === "del" ? "-" : "+", x.text);
  }
  return out.join("\n") + "\n";
}

const safeId = (id: string) => id.replace(/[^A-Za-z0-9_-]/g, "-");

/**
 * The owner's audit trail for approved patches: `.siidekick/<id>.patch` per patch (applies with `git apply`
 * on top of the previous ones) and `SIIDEKICK_LOG.md` with each patch's reason and revert command.
 * Secrets in a patch file are masked, because the owner may commit `.siidekick/`; such a patch's revert
 * puts back the mask, not the key.
 */
export function patchArtifacts(original: RepoSnapshot, applied: Patch[]): RepoFile[] {
  if (applied.length === 0) return [];
  const files: RepoFile[] = [];
  const log = [
    "# Siidekick change log",
    "",
    "Siidekick added these patches to your project, oldest first. Each one is saved as `.siidekick/<id>.patch`.",
    "To undo a patch, run its revert command from the project root. Undo the newest first, because a later",
    "patch can build on an earlier one.",
    "",
  ];
  let current = original;
  applied.forEach((patch, i) => {
    const file = `.siidekick/${safeId(patch.id)}.patch`;
    // applyPatch first: it throws if this patch does not fit the state the previous ones left.
    current = applyPatch(current, patch);
    let diff = patch.edits
      .map((e) => (e.kind === "create" ? unifiedFileDiff(e.path, null, e.content) : unifiedFileDiff(e.path, e.before, e.after)))
      .join("");
    const secrets = secretValues(patch.edits.map((e) => ({ path: e.path, content: e.kind === "create" ? e.content : e.before })));
    for (const v of secrets) diff = diff.split(v).join(redact(v));
    files.push({ path: file, content: diff });
    log.push(
      `## ${i + 1}. ${patch.title}`,
      "",
      `- Patch: \`${patch.id}\` from check \`${patch.checkId}\` (${patch.class})`,
      `- Why: ${patch.reason}`,
      `- Files: ${[...new Set(patch.edits.map((e) => `\`${e.path}\``))].join(", ")}`,
      `- Revert: \`git apply -R ${file}\``,
      ...(secrets.length
        ? ["- Note: the old secret is masked in the patch file, so the revert puts back the mask, not the key. Treat the key as leaked and rotate it."]
        : []),
      "",
    );
  });
  files.push({ path: "SIIDEKICK_LOG.md", content: log.join("\n") });
  return files;
}
