/**
 * Opens a pull request with the approved fixes and their evidence, using a token the owner pastes for this
 * one request. The token is never stored or logged. Nothing is merged: a human reviews the PR on GitHub.
 */
import type { Verdict } from "./verify.js";

export class PullRequestError extends Error {
  constructor(
    message: string,
    readonly status = 400,
  ) {
    super(message);
  }
}

export interface PrFile {
  path: string;
  content: string;
}

export interface PrInput {
  token: string;
  owner: string;
  repo: string;
  /** Branch the scan read; "HEAD" means the default branch. */
  ref: string;
  scanId: string;
  files: PrFile[];
  title: string;
  body: string;
  fetch?: typeof fetch;
}

const API = "https://api.github.com";

/** Plain names for each GitHub call, so an error says which step failed. */
const STEP: Record<string, string> = {
  "GET /": "reading the repository",
  "GET /git/ref/heads": "reading the base branch",
  "GET /git/commits": "reading the base commit",
  "POST /git/trees": "uploading the changed files",
  "POST /git/commits": "creating the commit",
  "POST /git/refs": "creating the branch",
  "POST /pulls": "opening the pull request",
};

export async function openPullRequest(input: PrInput): Promise<{ url: string; number: number; branch: string }> {
  const f = input.fetch ?? fetch;
  const touchesWorkflows = input.files.some((file) => file.path.startsWith(".github/workflows/"));
  const gh = async (method: string, path: string, body?: unknown): Promise<Record<string, unknown>> => {
    const res = await f(`${API}${path}`, {
      method,
      headers: {
        authorization: `Bearer ${input.token}`,
        accept: "application/vnd.github+json",
        "x-github-api-version": "2022-11-28",
        "user-agent": "siidekick",
        ...(body ? { "content-type": "application/json" } : {}),
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(10_000),
    });
    const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (!res.ok) {
      const msg = typeof json.message === "string" ? json.message : `HTTP ${res.status}`;
      if (res.status === 401) throw new PullRequestError("GitHub rejected the token (expired or wrong).", 401);
      if (res.status === 403 || res.status === 404) {
        // GitHub only lets a token write under .github/workflows/ with the Workflows permission, and its error does not say so.
        const needed = touchesWorkflows ? "Contents, Pull requests and Workflows" : "Contents and Pull requests";
        const step = STEP[`${method} ${path.replace(/^\/repos\/[^/]+\/[^/]+/, "").replace(/\/heads\/.*$/, "/heads").replace(/\/commits\/.+$/, "/commits") || "/"}`] ?? `${method} request`;
        throw new PullRequestError(
          `GitHub refused while ${step}: ${msg}. The token needs ${needed} set to read and write, on ${input.owner}/${input.repo} only.` +
            (touchesWorkflows ? " (One approved fix adds a GitHub Actions file in .github/workflows/, which needs the Workflows permission.)" : ""),
          403,
        );
      }
      throw new PullRequestError(`GitHub ${method} ${path.split("?")[0]} failed: ${msg}`, 502);
    }
    return json;
  };
  if (input.files.length === 0) throw new PullRequestError("approve at least one fix before opening a pull request");

  const repoPath = `/repos/${encodeURIComponent(input.owner)}/${encodeURIComponent(input.repo)}`;
  const repo = await gh("GET", repoPath);
  const base = input.ref === "HEAD" ? String(repo.default_branch) : input.ref;
  const baseRef = await gh("GET", `${repoPath}/git/ref/heads/${base.split("/").map(encodeURIComponent).join("/")}`);
  const baseSha = String((baseRef.object as Record<string, unknown>).sha);
  const baseCommit = await gh("GET", `${repoPath}/git/commits/${baseSha}`);
  const baseTree = String((baseCommit.tree as Record<string, unknown>).sha);

  const tree = await gh("POST", `${repoPath}/git/trees`, {
    base_tree: baseTree,
    tree: input.files.map((file) => ({ path: file.path, mode: "100644", type: "blob", content: file.content })),
  });
  const commit = await gh("POST", `${repoPath}/git/commits`, {
    message: `${input.title}\n\nProposed by Siidekick scan ${input.scanId}. Every change was approved by the owner and passed the add-only diff guard.`,
    tree: tree.sha,
    parents: [baseSha],
  });
  const branch = `siidekick/fixes-${input.scanId.slice(0, 8)}-${Date.now().toString(36)}`;
  await gh("POST", `${repoPath}/git/refs`, { ref: `refs/heads/${branch}`, sha: commit.sha });
  const pr = await gh("POST", `${repoPath}/pulls`, { title: input.title, head: branch, base, body: input.body, maintainer_can_modify: true });
  return { url: String(pr.html_url), number: Number(pr.number), branch };
}

const ICON: Record<string, string> = { verified: "✅", inconclusive: "⚠️", "not-verified": "❌", regression: "🛑", error: "❌" };

/** The PR description: what changed, the guard verdicts and, when a CodeBuild run exists, its evidence. */
export function prBody(opts: {
  scanId: string;
  scoreBefore: number;
  scoreAfter: number;
  fixes: Array<{ title: string; reason: string; added: number; removed: number; revert?: string }>;
  verdict?: Verdict | null;
  siteUrl?: string;
}): string {
  const lines = [
    "## Siidekick security fixes",
    "",
    `Scan score **${opts.scoreBefore} → ${opts.scoreAfter}** (rescan of this branch's code).`,
    "Each change below was approved by the repo owner and checked by Siidekick's diff guard, which refuses any patch that deletes or rewrites existing code beyond the lines it declares.",
    "",
    "| Fix | Lines | Why |",
    "|---|---|---|",
    ...opts.fixes.map((x) => `| ${x.title} | +${x.added} / −${x.removed} | ${x.reason.replace(/\|/g, "\\|").replace(/\n/g, " ")} |`),
    "",
  ];
  const v = opts.verdict;
  if (v) {
    lines.push(`## Isolated verification (AWS CodeBuild): ${ICON[v.status] ?? ""} ${v.status}`, "", v.headline, "");
    for (const c of v.checks) lines.push(`- ${c.ok === true ? "✅" : c.ok === false ? "❌" : "⚪"} **${c.label}**: ${c.detail}`);
    if (v.targets.length > 0) {
      lines.push("", "| Package | Before | After |", "|---|---|---|");
      for (const t of v.targets) lines.push(`| ${t.name} | ${t.before ?? "clean"} | ${t.fixed ? "clean" : (t.after ?? "unknown")} |`);
    }
    lines.push("", "The build ran in a throwaway container with install scripts disabled and no AWS credentials exposed to the repository's code.");
  } else {
    lines.push("## Verification", "", "Not run in the isolated build yet. Run your tests before merging.");
  }
  lines.push(
    "",
    "## Limits",
    "",
    "- This reduces specific risks; it does not make the app secure or prove the absence of other vulnerabilities.",
    "- Passing tests only cover what the tests check.",
    "- Each fix also ships as `.siidekick/<id>.patch`; `git apply -R` on it reverts that fix.",
    "",
    `_Opened by [Siidekick](${opts.siteUrl ?? "https://siidekick.ashforge.cv"}) for scan \`${opts.scanId}\`. Review before merging._`,
  );
  return lines.join("\n");
}
