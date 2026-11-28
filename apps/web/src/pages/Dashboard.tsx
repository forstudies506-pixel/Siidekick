import { flushSync } from "react-dom";
import { useEffect, useRef, useState, type ChangeEvent, type FormEvent, type InputHTMLAttributes } from "react";
import type { CheckGroup, CheckResult, FileEdit, GuardViolation, RepoFile, Severity } from "../../../../packages/engine/src/types";
import {
  approve,
  checkPatch,
  createDemoScan,
  download,
  generatePatches,
  getFeatures,
  getScan,
  githubScan,
  isMockSession,
  isGithubRepo,
  proveFix,
  uploadScan,
  type AttackPath,
  type ApprovedSummary,
  type AttackReceipt,
  type CheckResponse,
  type ReplayReport,
  type ReplayVerdict,
  type PatchEntry,
  type PatchResponse,
  type ScanResponse,
  type Features,
  type VerifyStatus,
} from "../api/client";
import { AI_LANGS, AiExplain, DependencyChain, PullRequestPanel, VerifyPanel } from "../components/AwsPanels";
import { ImpactSection, downloadImpactCard } from "../components/Impact";
import { IndiaLens } from "../components/IndiaLens";
import { DPDP_CHECKS } from "../bharat";
import { checkHi, ui, type Lang } from "../i18n/hi";
import { zipFiles } from "../zip";

const groupLabels: Record<CheckGroup, string> = {
  "A-delivery": "Delivery",
  "B-monitoring": "Monitoring",
  "C-security": "Security",
  "D-domain": "India (Bharat Pack)",
  "E-states": "States",
  "F-ai": "AI",
  "G-enterprise": "Enterprise",
};

// Same caps as apps/api/src/router.ts, so an upload is trimmed here instead of rejected there.
const MAX_FILES = 500;
const MAX_TOTAL_BYTES = 2 * 1024 * 1024;
const MAX_FILE_BYTES = 512 * 1024;

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : /(ch|sh|s|x)$/.test(word) ? "es" : "s"}`;

function isBinary(buffer: ArrayBuffer) {
  const bytes = new Uint8Array(buffer, 0, Math.min(buffer.byteLength, 8000));
  let nulls = 0;
  for (const byte of bytes) if (byte === 0) nulls += 1;
  return nulls > 2;
}

const isVendored = (path: string) => path.split("/").some((part) => part === "node_modules" || part === ".git");

function isEnvFile(path: string) {
  const base = path.split("/").pop() ?? "";
  return (base === ".env" || base.startsWith(".env.")) && base !== ".env.example";
}

interface FolderRead {
  name: string;
  files: RepoFile[];
  notes: string[];
}

async function readFolder(list: FileList): Promise<FolderRead> {
  const all = Array.from(list);
  const first = all[0]?.webkitRelativePath ?? "";
  const name = first.includes("/") ? first.split("/")[0] : "uploaded-repo";

  let envSkipped = 0;
  let tooBig = 0;
  const candidates: File[] = [];
  for (const file of all) {
    const path = file.webkitRelativePath || file.name;
    if (isVendored(path)) continue;
    if (isEnvFile(path)) {
      envSkipped += 1;
      continue;
    }
    if (file.size > MAX_FILE_BYTES) {
      tooBig += 1;
      continue;
    }
    candidates.push(file);
  }

  const files: RepoFile[] = [];
  let total = 0;
  let capped = 0;
  for (const file of candidates) {
    if (files.length >= MAX_FILES || total + file.size > MAX_TOTAL_BYTES) {
      capped += 1;
      continue;
    }
    const buffer = await file.arrayBuffer();
    if (isBinary(buffer)) continue;
    total += file.size;
    const relative = file.webkitRelativePath || file.name;
    files.push({ path: relative.replace(/^[^/]+\//, ""), content: new TextDecoder().decode(buffer) });
  }

  const notes: string[] = [];
  if (envSkipped) notes.push(`${plural(envSkipped, ".env file")} left on your machine, not uploaded.`);
  if (tooBig) notes.push(`${plural(tooBig, "file")} over 512 KB skipped.`);
  if (capped) notes.push(`${plural(capped, "file")} not scanned: the limit is 500 files or 2 MB in total.`);
  return { name, files, notes };
}

function Score({ score }: { score: number }) {
  const [display, setDisplay] = useState(score);
  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      setDisplay(score);
      return;
    }
    let frame = 0;
    const started = performance.now();
    const tick = (now: number) => {
      const t = Math.min((now - started) / 500, 1);
      setDisplay(Math.round(score * (1 - (1 - t) ** 3)));
      if (t < 1) frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [score]);
  return (
    <div className="score-block">
      <span>Score</span>
      <strong aria-hidden="true">{display}</strong>
      <span className="visually-hidden">{score} out of 100</span>
      <small aria-hidden="true">/100</small>
    </div>
  );
}

function Remedy({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => setCopied(false), 1600);
    return () => clearTimeout(t);
  }, [copied]);
  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
    } catch {
      // Clipboard can be blocked (insecure origin, permissions). The text stays selectable.
    }
  }
  return (
    <div className="remedy">
      <div className="remedy-head">
        <span>Fix</span>
        <button type="button" className="copy-button" onClick={() => void copy()}>
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre>{text}</pre>
    </div>
  );
}

function FindingRow({
  result,
  lang,
  hasFix,
  ai,
}: {
  result: CheckResult;
  lang: Lang;
  hasFix: boolean;
  /** Set when Amazon Bedrock is available: the scan and the language to explain in. */
  ai?: { scanId: string; lang: string };
}) {
  const t = ui[lang];
  const hi = lang === "hi" ? checkHi[result.checkId] : undefined;
  const state = result.skipped ? "na" : result.passed ? "passed" : "failed";
  return (
    <details className={`finding-row is-${state}`}>
      <summary>
        <span className="finding-name" lang={hi ? "hi" : undefined}>
          {hi?.title ?? result.title}
          {!result.passed && !result.skipped && DPDP_CHECKS.has(result.checkId) && (
            <span className="law-tag" title="Can expose personal data or accounts: relevant to the DPDP Act's 'reasonable security safeguards'">
              DPDP
            </span>
          )}
        </span>
        <span className={`severity ${result.severity}`}>{result.severity}</span>
        {state === "failed" ? (
          <span className={`fix-badge ${hasFix ? "auto" : "manual"}`}>{hasFix ? "auto-fix" : "manual"}</span>
        ) : (
          <span aria-hidden="true" />
        )}
        <span className={`verdict ${state === "na" ? "na" : result.passed ? "pass" : "fail"}`} lang={lang}>
          {state === "na" ? "N/A" : result.passed ? t.pass : t.fail}
        </span>
      </summary>
      <div className="finding-content">
        {result.skipped ? (
          <p>Not applicable: {result.skipped}</p>
        ) : (
          <>
            {hi && (
              <div className="why-hi" lang="hi">
                <strong>{ui.hi.why}</strong>
                <p>{hi.why}</p>
              </div>
            )}
            {result.findings.length === 0 ? (
              <p lang={lang}>{t.nothing}</p>
            ) : (
              result.findings.map((finding, index) => (
                <div className="finding" key={`${finding.file ?? "repo"}-${finding.line ?? 0}-${index}`}>
                  <code className="finding-loc">
                    {finding.file || "repository"}
                    {finding.line ? `:${finding.line}` : ""}
                  </code>
                  {finding.evidence && <pre>{finding.evidence}</pre>}
                  {finding.chain && <DependencyChain chain={finding.chain} />}
                  <p>{finding.explanation}</p>
                  {finding.remedy && <Remedy text={finding.remedy} />}
                  {ai && !result.passed && <AiExplain scanId={ai.scanId} checkId={result.checkId} index={index} lang={ai.lang} />}
                </div>
              ))
            )}
            {!result.passed && (
              <p className="fix-mode" lang={lang}>
                {result.mode === "report" ? t.reportOnly : t.patchable}
              </p>
            )}
          </>
        )}
        {result.error && <p className="error-text">{result.error}</p>}
      </div>
    </details>
  );
}

const SIGN = { add: "+", del: "−", same: " " } as const;
const SR_SIGN = { add: "added: ", del: "removed: ", same: "" } as const;

const REASON_TEXT: Record<GuardViolation["reason"], string> = {
  "overwrites-existing-file": "would overwrite a file you already have",
  "modify-missing-file": "edits a file that is not in your repo",
  "before-mismatch": "expects file content that does not match yours",
  "removal-in-additive-patch": "deletes a line of your code",
  "removed-line-not-allowed": "deletes a line this fix is not allowed to touch",
  "patch-too-large": "is larger than the size limit",
};

function Violations({ items }: { items: GuardViolation[] }) {
  return (
    <ul className="violations">
      {items.map((v, index) => (
        <li key={`${v.reason}-${index}`}>
          <span>
            Blocked: {REASON_TEXT[v.reason]} in <code>{v.path}</code>
          </span>
          {v.line && <code className="violation-line">{v.line}</code>}
        </li>
      ))}
    </ul>
  );
}

interface Tamper {
  edits: FileEdit[];
  path: string;
  line: string;
}

// Builds the "tamper" demo: drop one line the owner already had from a modify edit's result.
function tamperEdits(edits: FileEdit[]): Tamper | null {
  for (const [i, edit] of edits.entries()) {
    if (edit.kind !== "modify") continue;
    const owned = new Set(edit.before.split("\n").map((l) => l.trim()).filter(Boolean));
    const after = edit.after.split("\n");
    const at = after.findIndex((l) => l.trim() !== "" && owned.has(l.trim()));
    if (at === -1) continue;
    const next = { ...edit, after: [...after.slice(0, at), ...after.slice(at + 1)].join("\n") };
    return { edits: edits.map((e, j) => (j === i ? next : e)), path: edit.path, line: after[at].trim() };
  }
  return null;
}

function TamperResult({ tamper, result }: { tamper: Tamper; result: CheckResponse }) {
  return (
    <div className={`tamper-result${result.guard.ok ? "" : " rejected"}`}>
      <p>
        We deleted <code>{tamper.line}</code> from <code>{tamper.path}</code> in this patch and sent it to the server's
        diff guard.
      </p>
      <p className={`guard-verdict ${result.guard.ok ? "ok" : "bad"}`}>
        {result.guard.ok ? "guard passed: this should not happen" : "guard blocked the edited patch"}
      </p>
      {result.guard.violations.length > 0 && <Violations items={result.guard.violations} />}
    </div>
  );
}

function PatchCard({
  entry,
  scanId,
  tamperable,
  approved,
  pending,
  locked,
  onApprove,
}: {
  entry: PatchEntry;
  scanId: string;
  tamperable: boolean;
  approved: boolean;
  pending: boolean;
  /** Another patch is being approved. Each approve rewrites the whole scan record, so two at once could drop one. */
  locked: boolean;
  onApprove: () => void;
}) {
  const { patch, guard, diff } = entry;
  const tamper = tamperable ? tamperEdits(patch.edits) : null;
  const [tamperState, setTamperState] = useState<{ busy: boolean; result?: CheckResponse; error?: string }>({ busy: false });

  async function handleTamper() {
    if (!tamper) return;
    setTamperState({ busy: true });
    try {
      setTamperState({ busy: false, result: await checkPatch(scanId, patch.id, tamper.edits) });
    } catch (caught) {
      setTamperState({ busy: false, error: caught instanceof Error ? caught.message : "The guard did not answer." });
    }
  }

  const label = approved ? "Approved" : pending ? "Approving…" : guard.ok ? "Approve patch" : "Blocked: cannot approve";
  return (
    <article className={`patch-card${guard.ok ? "" : " blocked"}`}>
      <div className="patch-meta">
        <div>
          <h3>{patch.title}</h3>
          <p>{patch.reason}</p>
        </div>
        <div className="patch-chips">
          <span className="patch-class">{patch.class}</span>
          <span className={`guard-verdict ${guard.ok ? "ok" : "bad"}`}>{guard.ok ? "guard passed" : "guard blocked"}</span>
        </div>
      </div>
      <p className="guard-counts">
        <span>+{guard.added} added</span>
        <span>−{guard.removed} removed</span>
      </p>
      {guard.violations.length > 0 && <Violations items={guard.violations} />}
      <div className="diff-block">
        {diff.map((file) => (
          <div key={file.path}>
            <div className="diff-path">{file.path}</div>
            <pre className="diff-lines">
              {file.lines.map((line, index) => (
                <span className={`diff-code ${line.type}`} key={index}>
                  <span className="diff-sign" aria-hidden="true">
                    {SIGN[line.type]}
                  </span>
                  <span className="visually-hidden">{SR_SIGN[line.type]}</span>
                  {line.text}
                  {"\n"}
                </span>
              ))}
            </pre>
          </div>
        ))}
      </div>
      <div className="patch-actions">
        <button className="button approve" disabled={!guard.ok || approved || pending || locked} onClick={onApprove}>
          {label}
        </button>
        {tamper && !tamperState.result && (
          <button className="button secondary" onClick={handleTamper} disabled={tamperState.busy}>
            {tamperState.busy ? "Asking the guard…" : "Try to tamper"}
          </button>
        )}
      </div>
      <div aria-live="polite">
        {tamperState.result && tamper && <TamperResult tamper={tamper} result={tamperState.result} />}
        {tamperState.error && <p className="error-text">{tamperState.error}</p>}
      </div>
    </article>
  );
}

const verdictText: Record<ReplayVerdict, string> = {
  blocked: "blocked",
  "still-open": "still works",
  "not-reproduced": "did not reproduce",
  inconclusive: "inconclusive",
};

function Receipt({ receipt }: { receipt: AttackReceipt }) {
  const { before, after, control, verdict } = receipt;
  return (
    <li className={`receipt ${verdict}`}>
      <div className="receipt-head">
        <h4>{receipt.title}</h4>
        <span className={`verdict-chip ${verdict}`}>{verdictText[verdict]}</span>
      </div>
      <code className="receipt-request">{receipt.request}</code>
      <dl className="receipt-probes">
        <div className={before.exploited ? "hit" : "miss"}>
          <dt>Before</dt>
          <dd>
            <strong>{before.exploited ? "Worked." : "Did not work."}</strong> {before.detail}
          </dd>
        </div>
        <div className={after.exploited ? "hit" : "miss"}>
          <dt>After</dt>
          <dd>
            <strong>{after.exploited ? "Still works." : "Blocked."}</strong> {after.detail}
          </dd>
        </div>
      </dl>
      {control && (
        <p className={`receipt-control ${control.ok ? "ok" : "bad"}`}>
          <span aria-hidden="true">{control.ok ? "✓" : "✗"}</span>
          <span className="visually-hidden">{control.ok ? "Passed:" : "Failed:"}</span> {control.label}
        </p>
      )}
    </li>
  );
}

function PathCard({ path, first, titleOf }: { path: AttackPath; first: boolean; titleOf: (checkId: string) => string }) {
  const open = path.openAfter;
  const cuts = path.cutBy.map(titleOf);
  return (
    <li className={`attack-path ${open ? "open" : "closed"} ${path.impact}`}>
      <div className="path-head">
        <span className="path-impact">{path.impact}</span>
        <h4>{path.title}</h4>
        <span className={`verdict-chip ${open ? "still-open" : "blocked"}`}>{open ? "still open" : "closed"}</span>
      </div>
      <ol className="path-steps">
        {path.steps.map((s, i) => (
          <li key={i} className={s.after ? "live" : "cut"}>
            <span className="step-no">{i + 1}</span>
            <span>{s.text}</span>
            <span className="step-state">{s.after ? "works" : s.before ? "cut" : "never worked"}</span>
          </li>
        ))}
      </ol>
      {open ? (
        <p className="path-fix">
          {first && <strong className="fix-first">Fix this one first.</strong>} Cut it with: {cuts.join(" or ")}.
          {path.cutBy.includes("sql-string-concat") && " No patch can do this safely; the rewrite with ? placeholders is in the report above."}
        </p>
      ) : (
        <p className="path-fix muted">Closed by your approved fix{cuts.length === 1 ? "" : "es"}: {cuts.join(", ")}.</p>
      )}
    </li>
  );
}

function ProofPanel({ scanId, approved, mock, results }: { scanId: string; approved: string[]; mock: boolean; results: CheckResult[] }) {
  const [proof, setProof] = useState<ReplayReport | null>(null);
  const [ranFor, setRanFor] = useState("");
  const [proving, setProving] = useState(false);
  const [error, setError] = useState("");
  const approvedKey = [...approved].sort().join(",");
  const stale = proof !== null && ranFor !== approvedKey;
  const titleOf = (checkId: string) => results.find((r) => r.checkId === checkId)?.title ?? checkId;

  async function handleProve() {
    setProving(true);
    setError("");
    try {
      const result = await proveFix(scanId);
      setProof(result);
      setRanFor(approvedKey);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The replay did not finish.");
    } finally {
      setProving(false);
    }
  }

  const attacks = proof?.attacks ?? [];
  const blocked = attacks.filter((a) => a.verdict === "blocked").length;
  const rank = (p: AttackPath) => (p.openAfter ? 0 : 2) + (p.impact === "critical" ? 0 : 1);
  const paths = [...(proof?.paths ?? [])].sort((a, b) => rank(a) - rank(b));
  const openPaths = paths.filter((p) => p.openAfter).length;
  const firstOpen = paths.find((p) => p.openAfter)?.id;
  const status = proving
    ? "Replaying attacks."
    : proof?.available
      ? `Replay finished. ${blocked} of ${attacks.length} attacks blocked. ${openPaths} attack ${openPaths === 1 ? "path" : "paths"} still open.`
      : "";

  return (
    <section className="proof-panel" aria-labelledby="proof-title">
      <p className="visually-hidden" role="status">
        {status}
      </p>
      <div className="proof-heading">
        <div>
          <h2 id="proof-title">Proof of fix</h2>
          <p className="muted">
            We boot the demo shop twice, as scanned and with your approved fixes, then run the same attacks on both.
            Each attack comes with a check that real customers still get through.
          </p>
        </div>
        <button className="button primary" onClick={handleProve} disabled={proving || mock || approved.length === 0}>
          {proving ? "Replaying…" : proof ? "Replay again" : "Replay the attacks"}
        </button>
      </div>

      {mock && <p className="muted">Attack replay needs the scan server. Demo data cannot be attacked.</p>}
      {!mock && approved.length === 0 && !proof && <p className="muted">Approve at least one fix above, then replay.</p>}
      {proving && <div className="state-box">Attacking both copies of the shop… about 3 seconds.</div>}
      {error && <div className="state-box error">{error}</div>}
      {stale && !proving && <p className="stale-note">Your approved fixes changed since this run. Replay to update it.</p>}

      {proof && !proof.available && <div className="state-box">{proof.reason ?? "Replay is not available here."}</div>}

      {proof?.available && (
        <>
          <div className="proof-summary">
            <div>
              <strong>
                {blocked}/{attacks.length}
              </strong>
              <span>attacks blocked</span>
            </div>
            <div>
              <strong>
                {paths.length - openPaths}/{paths.length}
              </strong>
              <span>attack paths closed</span>
            </div>
            {proof.tests?.ran && (
              <div className={proof.tests.failed === 0 ? "" : "bad"}>
                <strong>
                  {proof.tests.passed}/{proof.tests.passed + proof.tests.failed}
                </strong>
                <span>shop tests pass after</span>
              </div>
            )}
            <div>
              <strong>{(proof.ms / 1000).toFixed(1)}s</strong>
              <span>replay time</span>
            </div>
          </div>

          <h3 className="proof-sub">Attack paths</h3>
          <p className="muted">Single flaws chain into real harm. A path stays open while every step in it works.</p>
          <ol className="attack-paths">
            {paths.map((p) => (
              <PathCard key={p.id} path={p} first={p.id === firstOpen} titleOf={titleOf} />
            ))}
          </ol>

          <h3 className="proof-sub">Receipts</h3>
          <ul className="receipts">
            {attacks.map((a) => (
              <Receipt key={a.id} receipt={a} />
            ))}
          </ul>
          <p className="muted proof-foot">
            Risk reduced, not removed. Attacks ran against local copies of the demo shop only; no data left the server.
          </p>
        </>
      )}
    </section>
  );
}


type Busy = "" | "scan" | "patches" | "restore" | "approve-all";
type Step = "connect" | "findings" | "fixes" | "verify";
type Filter = "failing" | "passed" | "na" | "all";
type View = "severity" | "category";
type Source = "github" | "upload" | "demo";
type Report = ScanResponse["report"];

const STEPS: { id: Step; label: string }[] = [
  { id: "connect", label: "Connect" },
  { id: "findings", label: "Findings" },
  { id: "fixes", label: "Fixes" },
  { id: "verify", label: "Verify & ship" },
];
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const SEV_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SOURCE_LABEL: Record<Source, string> = { github: "GitHub", upload: "folder", demo: "demo" };

interface Recent {
  id: string;
  repo: string;
  score: number;
  at: string;
  source: Source;
  url?: string;
}
const RECENT_KEY = "siidekick.recent";
const MAX_RECENT = 6;

function loadRecent(): Recent[] {
  try {
    const raw: unknown = JSON.parse(localStorage.getItem(RECENT_KEY) ?? "[]");
    if (!Array.isArray(raw)) return [];
    return raw
      .filter(
        (r): r is Recent =>
          typeof r === "object" &&
          r !== null &&
          typeof r.id === "string" &&
          typeof r.repo === "string" &&
          typeof r.score === "number" &&
          typeof r.at === "string" &&
          (r.source === "github" || r.source === "upload" || r.source === "demo") &&
          (r.url === undefined || typeof r.url === "string"),
      )
      .slice(0, MAX_RECENT);
  } catch {
    return [];
  }
}

function saveRecent(list: Recent[]) {
  try {
    localStorage.setItem(RECENT_KEY, JSON.stringify(list));
  } catch {
    // Private mode or a full store can throw. Recents are a convenience, so the scan carries on without them.
  }
}

const isStep = (s: string | null): s is Step => STEPS.some((x) => x.id === s);

function readUrl() {
  const q = new URLSearchParams(window.location.search);
  const step = q.get("step");
  return { scan: q.get("scan") ?? "", step: isStep(step) ? step : null, demo: q.get("demo") === "1", url: q.get("url")?.trim() ?? "" };
}

/** Keeps a server message, but never shows a bare transport word or status code. */
function errorText(e: unknown, fallback: string) {
  const msg = e instanceof Error ? e.message.trim() : "";
  return !msg || /^(network|not json|\d{3})$/i.test(msg) ? fallback : msg;
}

function ago(iso: string) {
  const s = (Date.now() - Date.parse(iso)) / 1000;
  if (!Number.isFinite(s) || s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(iso).toLocaleDateString();
}

const isFailing = (r: CheckResult) => !r.passed && !r.skipped;
const bySeverity = (a: CheckResult, b: CheckResult) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity] || a.title.localeCompare(b.title);
const rank = (r: CheckResult) => (isFailing(r) ? 0 : r.skipped ? 2 : 1);

/** Search over what a row shows: title, id, and each finding's file, explanation and evidence. */
function matches(r: CheckResult, q: string) {
  if (!q) return true;
  const hay = [r.title, r.checkId, r.group, r.severity, ...r.findings.flatMap((f) => [f.file ?? "", f.explanation, f.evidence ?? ""])];
  return hay.join("\n").toLowerCase().includes(q);
}

const verdictOf = (r: CheckResult) => (r.skipped ? "n/a" : r.passed ? "pass" : "FAIL");

function toMarkdown(report: Report, target: string, summary: ApprovedSummary | null) {
  const out = [
    `# Siidekick report: ${target}`,
    "",
    `Scanned ${report.startedAt}. Score **${report.score}/100**, ${report.passed} of ${report.total} applicable checks pass.`,
  ];
  if (summary) out.push(`With approved fixes: **${summary.score}/100**, ${summary.passed} of ${summary.total} pass.`);
  out.push("", "| Verdict | Severity | Check |", "|---|---|---|");
  for (const r of [...report.results].sort((a, b) => rank(a) - rank(b) || bySeverity(a, b))) {
    out.push(`| ${verdictOf(r)} | ${r.severity} | ${r.title.replace(/\|/g, "\\|")} |`);
  }
  const failing = report.results.filter(isFailing).sort(bySeverity);
  if (failing.length) out.push("", "## Failing checks");
  for (const r of failing) {
    out.push("", `### ${r.title} (${r.severity})`);
    for (const f of r.findings) {
      const where = f.file ? ` \`${f.file}${f.line ? `:${f.line}` : ""}\`` : "";
      out.push("", `-${where} ${f.explanation}`);
      if (f.remedy) out.push("", "  Fix:", "", "  ```", ...f.remedy.split("\n").map((l) => `  ${l}`), "  ```");
    }
  }
  out.push("", "---", "Siidekick reduces risk. No tool can promise an app is unhackable.", "");
  return out.join("\n");
}

function saveText(name: string, text: string, type: string) {
  const href = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = href;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(href), 1000);
}

const isTyping = (el: EventTarget | null) =>
  el instanceof HTMLElement && (el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName));

export function Dashboard() {
  const [step, setStep] = useState<Step>("connect");
  const [report, setReport] = useState<Report | null>(null);
  const [scanId, setScanId] = useState("");
  const [mock, setMock] = useState(false);
  const [demo, setDemo] = useState(false);
  const [omitted, setOmitted] = useState<number | undefined>(undefined);
  const [notes, setNotes] = useState<string[]>([]);
  const [patchResult, setPatchResult] = useState<PatchResponse | null>(null);
  const [approved, setApproved] = useState<string[]>([]);
  const [summary, setSummary] = useState<ApprovedSummary | null>(null);
  const [pendingId, setPendingId] = useState("");
  const [busy, setBusy] = useState<Busy>("");
  const [error, setError] = useState("");
  const [gone, setGone] = useState<{ repo: string; url?: string } | null>(null);
  const [filter, setFilter] = useState<Filter>("failing");
  const [view, setView] = useState<View>("severity");
  const [lang, setLang] = useState<Lang>("en");
  const [aiLang, setAiLang] = useState("hi");
  const [features, setFeatures] = useState<Features | null>(null);
  const [verifyStatus, setVerifyStatus] = useState<VerifyStatus | null>(null);
  useEffect(() => {
    void getFeatures().then(setFeatures);
  }, []);
  const [selectedPatch, setSelectedPatch] = useState("");
  const [recent, setRecent] = useState<Recent[]>(loadRecent);
  const [repoUrl, setRepoUrl] = useState("");
  const [scanning, setScanning] = useState<Source>("github");
  const [downloading, setDownloading] = useState(false);
  const [query, setQuery] = useState("");
  const [sourceUrl, setSourceUrl] = useState("");
  const [copied, setCopied] = useState("");
  const folderInput = useRef<HTMLInputElement>(null);
  const searchInput = useRef<HTMLInputElement>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const genTried = useRef(false);
  const started = useRef(false);
  const shownStep = useRef<Step>(step);

  function remember(entry: Recent) {
    setRecent((list) => {
      const next = [entry, ...list.filter((r) => r.id !== entry.id)].slice(0, MAX_RECENT);
      saveRecent(next);
      return next;
    });
  }

  function forget(id: string) {
    setRecent((list) => {
      const next = list.filter((r) => r.id !== id);
      saveRecent(next);
      return next;
    });
  }

  /** Moves to a step and mirrors it in the address bar, so reload and back keep the place. */
  function go(next: Step, id = scanId, isMock = mock, replace = false) {
    type Vt = { ready: Promise<unknown>; finished: Promise<unknown> };
    const doc = document as Document & { startViewTransition?: (cb: () => void) => Vt };
    const still = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (next !== step && doc.startViewTransition && !still && document.visibilityState === "visible") {
      const t = doc.startViewTransition(() => flushSync(() => setStep(next)));
      // A skipped transition still applies the step; only the animation is lost.
      t.ready.catch(() => undefined);
      t.finished.catch(() => undefined);
      // If the browser never paints (a hidden or throttled tab), apply the step anyway.
      window.setTimeout(() => setStep(next), 400);
    } else setStep(next);
    const q = new URLSearchParams();
    if (id && !isMock) q.set("scan", id);
    if (next !== "connect") q.set("step", next);
    const qs = q.toString();
    const url = window.location.pathname + (qs ? `?${qs}` : "");
    if (url === window.location.pathname + window.location.search) return;
    if (replace) window.history.replaceState(null, "", url);
    else window.history.pushState(null, "", url);
  }

  const canOpen = (s: Step) =>
    s === "connect" || (s === "verify" ? !!patchResult : !!report);

  async function runScan(start: () => Promise<ScanResponse>, readNotes: string[], source: Source, url?: string) {
    setBusy("scan");
    setScanning(source);
    setError("");
    setGone(null);
    setNotes(readNotes);
    try {
      const res = await start();
      setReport(res.report);
      setScanId(res.id);
      setMock(res.mock);
      setOmitted(res.omitted);
      setDemo(source === "demo" && !res.mock);
      setPatchResult(null);
      setApproved([]);
      setSummary(null);
      setSelectedPatch("");
      setFilter(res.report.results.some(isFailing) ? "failing" : "all");
      setQuery("");
      setSourceUrl(source === "upload" ? "" : (url ?? ""));
      genTried.current = false;
      if (!res.mock) remember({ id: res.id, repo: res.report.repo, score: res.report.score, at: new Date().toISOString(), source, url });
      go("findings", res.id, res.mock, readUrl().demo);
    } catch (e) {
      setError(errorText(e, "The scan failed. Try again."));
    } finally {
      setBusy("");
    }
  }

  async function restore(id: string, target: Step) {
    setBusy("restore");
    setError("");
    setGone(null);
    try {
      const stored = await getScan(id);
      const pr: PatchResponse | null = stored.patches
        ? {
            patches: stored.patches.map(({ patch, guard, diff }) => ({ patch, guard, diff })),
            scoreBefore: stored.report.score,
            scoreAfter: stored.after?.score ?? stored.report.score,
            status: stored.after && stored.after.passed === stored.after.total ? "rescan-clean" : "partial",
            mock: false,
          }
        : null;
      setReport(stored.report);
      setScanId(id);
      setMock(false);
      setOmitted(stored.omitted);
      setNotes([]);
      setDemo(!!stored.demo);
      setPatchResult(pr);
      setApproved(stored.patches?.filter((p) => p.approved).map((p) => p.patchId) ?? []);
      setSummary(stored.approvedSummary ?? null);
      setSelectedPatch("");
      setFilter(stored.report.results.some(isFailing) ? "failing" : "all");
      setQuery("");
      setSourceUrl(recent.find((r) => r.id === id)?.url ?? "");
      genTried.current = !!pr;
      go(target === "verify" && !pr ? "fixes" : target, id, false, true);
    } catch (e) {
      const msg = e instanceof Error ? e.message : "";
      if (/not found/i.test(msg)) {
        const entry = recent.find((r) => r.id === id);
        setGone({ repo: entry?.repo ?? "That scan", url: entry?.url });
        forget(id);
        setReport(null);
        setScanId("");
        setPatchResult(null);
        go("connect", "", false, true);
      } else {
        setError(errorText(e, "Could not load that scan."));
        setStep("connect");
      }
    } finally {
      setBusy("");
    }
  }

  useEffect(() => {
    if (started.current) return;
    started.current = true;
    const { scan, step: s, demo: wantDemo, url } = readUrl();
    if (wantDemo) void runScan(createDemoScan, [], "demo");
    else if (scan) void restore(scan, s && s !== "connect" ? s : "findings");
    else if (url) {
      setRepoUrl(url);
      scanUrl(url);
    }
    // Runs once on load: the address bar decides where the visit starts.
  }, []);

  useEffect(() => {
    const onPop = () => {
      const { scan, step: s } = readUrl();
      const target = s ?? "connect";
      if (scan && scan !== scanId) {
        void restore(scan, target);
        return;
      }
      setStep(canOpen(target) ? target : report ? "findings" : "connect");
    };
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  });

  useEffect(() => {
    if (shownStep.current === step) return;
    shownStep.current = step;
    heading.current?.focus();
  }, [step]);

  async function handleFiles(e: ChangeEvent<HTMLInputElement>) {
    const input = e.currentTarget;
    const list = input.files;
    if (!list?.length) return;
    let read: FolderRead;
    try {
      read = await readFolder(list);
    } catch (err) {
      setError(errorText(err, "Could not read that folder."));
      return;
    } finally {
      input.value = "";
    }
    if (!read.files.length) {
      setError("No readable text files in that folder.");
      return;
    }
    await runScan(() => uploadScan(read.name, read.files), read.notes, "upload");
  }

  /** Siidekick reads source code only: a GitHub repo URL, an uploaded folder or the demo shop. */
  function scanUrl(url: string) {
    if (isGithubRepo(url)) void runScan(() => githubScan(url), [], "github", url);
    else setError("Siidekick scans source code, not live websites. Paste a GitHub repo address (github.com/owner/repo), upload a folder, or try the demo shop.");
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    const url = repoUrl.trim();
    if (url) scanUrl(url);
  }

  async function handleGenerate() {
    if (!report || !scanId) return;
    genTried.current = true;
    setBusy("patches");
    setError("");
    setApproved([]);
    setSummary(null);
    setSelectedPatch("");
    try {
      setPatchResult(await generatePatches(scanId, report.repo));
    } catch (e) {
      setError(errorText(e, "Could not draft patches. Try again."));
    } finally {
      setBusy("");
    }
  }

  useEffect(() => {
    if (step === "fixes" && report && !patchResult && !busy && !genTried.current) void handleGenerate();
  });

  async function approveOne(patchId: string): Promise<boolean> {
    setPendingId(patchId);
    setError("");
    try {
      const res = await approve(scanId, patchId);
      setApproved(res.approved);
      if (res.score !== undefined && res.passed !== undefined && res.total !== undefined && res.failing) {
        setSummary({ score: res.score, passed: res.passed, total: res.total, failing: res.failing });
      }
      return true;
    } catch (e) {
      setError(errorText(e, "Could not approve that patch. Try again."));
      return false;
    } finally {
      setPendingId("");
    }
  }

  async function handleApproveAll() {
    if (!patchResult) return;
    setBusy("approve-all");
    try {
      // One at a time: each approve rewrites the scan record on the server.
      for (const { patch, guard } of patchResult.patches) {
        if (!guard.ok || approved.includes(patch.id)) continue;
        if (!(await approveOne(patch.id))) break;
      }
    } finally {
      setBusy("");
    }
  }

  async function handleDownload() {
    if (!report) return;
    setDownloading(true);
    setError("");
    try {
      const res = await download(scanId);
      const href = URL.createObjectURL(zipFiles(res.files));
      const a = document.createElement("a");
      a.href = href;
      a.download = `siidekick-${report.repo.replace(/[^\w.-]+/g, "-")}-approved.zip`;
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(href), 1000);
    } catch (e) {
      setError(errorText(e, "Could not build the download. Try again."));
    } finally {
      setDownloading(false);
    }
  }

  function newScan() {
    setError("");
    setGone(null);
    go("connect", "", false);
  }

  /** A link that reproduces this scan: the address rescans fresh, an upload reopens the stored record. */
  function shareLink() {
    const base = `${window.location.origin}/app`;
    if (demo) return `${base}?demo=1`;
    if (sourceUrl) return `${base}?url=${encodeURIComponent(sourceUrl)}`;
    return scanId && !mock ? `${base}?scan=${encodeURIComponent(scanId)}` : "";
  }

  async function copyLink() {
    const link = shareLink();
    if (!link) return;
    try {
      await navigator.clipboard.writeText(link);
      setCopied(sourceUrl || demo ? "Link copied. Opening it runs a fresh scan." : "Link copied. It works while this server keeps the scan.");
    } catch {
      setCopied(`Copy this link: ${link}`);
    }
    setTimeout(() => setCopied(""), 4000);
  }

  function exportAs(kind: "json" | "md") {
    if (!report) return;
    const target = report.repo;
    const stem = `siidekick-${target.replace(/^https?:\/\//, "").replace(/[^\w.-]+/g, "-")}`;
    if (kind === "md") saveText(`${stem}.md`, toMarkdown(report, target, summary), "text/markdown");
    else {
      const body = { tool: "siidekick", target, report, approvedFixes: approved, approvedSummary: summary ?? undefined };
      saveText(`${stem}.json`, JSON.stringify(body, null, 2), "application/json");
    }
  }

  // Keys: / search, 1–4 steps, f p n a filters, Esc clears the search. Never while typing in a field.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.metaKey || e.ctrlKey || e.altKey || isTyping(e.target)) {
        if (e.key === "Escape" && e.target === searchInput.current) {
          setQuery("");
          searchInput.current?.blur();
        }
        return;
      }
      if (busy === "scan" || busy === "restore") return;
      const n = Number(e.key);
      if (n >= 1 && n <= STEPS.length) {
        const target = STEPS[n - 1].id;
        if (canOpen(target) && target !== step) go(target);
        return;
      }
      if (!report) return;
      if (e.key === "/") {
        e.preventDefault();
        if (step !== "findings") go("findings");
        requestAnimationFrame(() => searchInput.current?.focus());
        return;
      }
      if (step !== "findings") return;
      const f = ({ f: "failing", p: "passed", n: "na", a: "all" } as const)[e.key];
      if (f) setFilter(f);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  const results = report?.results ?? [];
  const failing = results.filter(isFailing);
  const passedList = results.filter((r) => r.passed && !r.skipped);
  const naList = results.filter((r) => r.skipped);
  const patches = patchResult?.patches ?? [];
  const patchedChecks = new Set(patches.map((e) => e.patch.checkId));
  const hasFix = (r: CheckResult) => (patchResult ? patchedChecks.has(r.checkId) : r.mode !== "report");
  const byFilter: Record<Filter, CheckResult[]> = { failing, passed: passedList, na: naList, all: results };
  const q = query.trim().toLowerCase();
  const shown = [...byFilter[filter]].filter((r) => matches(r, q)).sort((a, b) => rank(a) - rank(b) || bySeverity(a, b));
  const groups = (Object.keys(groupLabels) as CheckGroup[])
    .map((g) => ({ id: g, items: shown.filter((r) => r.group === g) }))
    .filter((g) => g.items.length > 0);
  const failCount = (s: Severity) => failing.filter((r) => r.severity === s).length;
  const fixableFailing = failing.filter(hasFix).length;
  const manual = patchResult ? failing.filter((r) => !patchedChecks.has(r.checkId)).sort(bySeverity) : [];
  const selected = patches.find((e) => e.patch.id === selectedPatch) ?? patches[0];
  const tamperId = mock || patchResult?.mock ? undefined : patches.find((e) => e.guard.ok && tamperEdits(e.patch.edits))?.patch.id;
  const toApprove = patches.filter((e) => e.guard.ok && !approved.includes(e.patch.id));
  const severityOf = (checkId: string) => results.find((r) => r.checkId === checkId)?.severity ?? "info";
  const aiFor = features?.ai && scanId && !mock ? { scanId, lang: aiLang } : undefined;
  const statusText =
    busy === "scan"
      ? "Scanning the repo…"
      : busy === "restore"
        ? "Loading the scan…"
        : busy === "patches"
          ? "Drafting patches and rescanning…"
          : busy === "approve-all"
            ? "Approving guard-passed patches…"
            : downloading
              ? "Building the download…"
              : "";
  const stepTitle: Record<Step, string> = {
    connect: "Scan a repo",
    findings: "Findings",
    fixes: "Review fixes",
    verify: "Verify & ship",
  };

  const filterButtons: { id: Filter; label: string; n: number }[] = [
    { id: "failing", label: "Failing", n: failing.length },
    { id: "passed", label: "Passing", n: passedList.length },
    { id: "na", label: "N/A", n: naList.length },
    { id: "all", label: "All", n: results.length },
  ];

  return (
    <div className="app-shell">
      <header className="dashboard-header">
        <a className="wordmark" href="/">
          Siide<span>kick</span>
        </a>
        <nav aria-label="Steps">
          <ol className="step-rail">
            {STEPS.map((s, i) => (
              <li key={s.id}>
                <button
                  type="button"
                  disabled={!canOpen(s.id) || busy === "scan" || busy === "restore"}
                  aria-current={step === s.id ? "step" : undefined}
                  onClick={() => go(s.id)}
                >
                  <span className="step-num">{i + 1}</span>
                  {s.label}
                </button>
              </li>
            ))}
          </ol>
        </nav>
        <div className="dashboard-tools">
          {report && step !== "connect" && (
            <button type="button" className="button secondary" onClick={newScan}>
              New scan
            </button>
          )}
          {(mock || isMockSession()) && <span className="demo-badge">sample data, API offline</span>}
          <a className="back-link" href="/">
            Back to home
          </a>
        </div>
      </header>

      <p className="visually-hidden" role="status">
        {statusText}
      </p>
      {statusText && (
        <div className="busy-bar" aria-hidden="true">
          <span>{statusText}</span>
        </div>
      )}

      <main className="dashboard">
        {report && step !== "connect" && (
          <section className="scan-strip" aria-label="Current scan">
            <Score score={report.score} />
            <dl>
              <div>
                <dt>Repo</dt>
                <dd className="repo-name">{report.repo}</dd>
              </div>
              <div>
                <dt>Failing</dt>
                <dd className="sev-counts">
                  {failing.length === 0
                    ? "none"
                    : SEVERITIES.filter((s) => failCount(s) > 0).map((s) => (
                        <span key={s} className={`severity ${s}`}>
                          {failCount(s)} {s}
                        </span>
                      ))}
                </dd>
              </div>
              <div>
                <dt>Passing</dt>
                <dd>
                  {report.passed} of {report.total}
                </dd>
              </div>
              {naList.length > 0 && (
                <div>
                  <dt>Not applicable</dt>
                  <dd>{naList.length}</dd>
                </div>
              )}
              {omitted ? (
                <div>
                  <dt>Not read</dt>
                  <dd>{plural(omitted, "file")}</dd>
                </div>
              ) : null}
            </dl>
            <div className="scan-actions">
              <button type="button" className="button secondary" onClick={() => exportAs("md")}>
                Report .md
              </button>
              <button type="button" className="button secondary" onClick={() => exportAs("json")}>
                Data .json
              </button>
              {shareLink() && (
                <button type="button" className="button secondary" onClick={copyLink}>
                  Copy link
                </button>
              )}
              <p className="copied-note" role="status">
                {copied}
              </p>
            </div>
          </section>
        )}

        {error && (
          <div className="state-box error" role="alert">
            <p>{error}</p>
            <button type="button" className="button secondary" onClick={() => setError("")}>
              Dismiss
            </button>
          </div>
        )}

        {step === "connect" && (
          <div className="connect-grid">
            <section className="connect-main">
              <h1 ref={heading} tabIndex={-1}>
                {stepTitle.connect}
              </h1>
              <p className="lede">
                Find what an attacker would, then approve the fixes.
              </p>
              <form className="repo-form" onSubmit={handleSubmit}>
                <label htmlFor="repo-url">GitHub repo</label>
                <div>
                  <input
                    id="repo-url"
                    type="text"
                    inputMode="url"
                    autoComplete="off"
                    spellCheck={false}
                    placeholder="github.com/owner/repo"
                    value={repoUrl}
                    onChange={(e) => setRepoUrl(e.target.value)}
                    aria-describedby="repo-note"
                    required
                  />
                  <button className="button primary" type="submit" disabled={!!busy}>
                    {busy === "scan" ? "Scanning…" : "Scan"}
                  </button>
                </div>
                <small id="repo-note">
                  Only scan code you own. It's read as text, never run.
                </small>
              </form>
              <div className="connect-alt">
                <span>or</span>
                <button
                  type="button"
                  className="button secondary"
                  disabled={!!busy}
                  onClick={() => folderInput.current?.click()}
                >
                  Upload a folder
                </button>
                <button
                  type="button"
                  className="button secondary"
                  disabled={!!busy}
                  onClick={() => void runScan(createDemoScan, [], "demo")}
                >
                  Try the demo shop
                </button>
                <input
                  ref={folderInput}
                  className="visually-hidden"
                  type="file"
                  multiple
                  tabIndex={-1}
                  aria-hidden="true"
                  onChange={handleFiles}
                  {...({ webkitdirectory: "", directory: "" } as InputHTMLAttributes<HTMLInputElement>)}
                />
              </div>
              {(busy === "scan" || busy === "restore") && (
                <div className="state-box" aria-hidden="true">
                  <p>{statusText}</p>
                </div>
              )}
              {gone && (
                <div className="state-box">
                  <p>
                    {gone.repo}: this scan is gone (the server restarted). Scan again.
                  </p>
                  {gone.url && (
                    <button
                      type="button"
                      className="button secondary"
                      disabled={!!busy}
                      onClick={() => scanUrl(gone.url!)}
                    >
                      Rescan {gone.repo}
                    </button>
                  )}
                </div>
              )}
              {notes.length > 0 && (
                <ul className="read-notes">
                  {notes.map((n) => (
                    <li key={n}>{n}</li>
                  ))}
                </ul>
              )}
            </section>

            <aside className="connect-side">
              {report && (
                <section className="side-card current">
                  <h2>Current scan</h2>
                  <p>
                    <strong>{report.repo}</strong> scored {report.score}, with {plural(failing.length, "failing check")}.
                  </p>
                  <button type="button" className="button primary" onClick={() => go("findings")}>
                    Continue to findings
                  </button>
                </section>
              )}
              {recent.length > 0 && (
                <section className="side-card">
                  <h2>Recent scans</h2>
                  <ul className="recent-list">
                    {recent.map((r) => (
                      <li key={r.id}>
                        <button type="button" disabled={!!busy} onClick={() => void restore(r.id, "findings")}>
                          <span className="recent-repo">{r.repo}</span>
                          <span className="recent-meta">
                            {SOURCE_LABEL[r.source]} · {ago(r.at)}
                          </span>
                          <span className="recent-score">{r.score}</span>
                        </button>
                      </li>
                    ))}
                  </ul>
                </section>
              )}
            </aside>
          </div>
        )}

        {step === "findings" && report && (
          <section className="findings-step">
            <div className="step-head">
              <h1 ref={heading} tabIndex={-1}>
                {stepTitle.findings}
              </h1>
              <p className="lede">
                {failing.length === 0
                  ? `Every applicable check passes on ${report.repo}.`
                  : `${plural(failing.length, "check")} failing, worst first.`}
              </p>
            </div>
            <IndiaLens results={report.results} afterFailing={mock ? null : (summary?.failing ?? null)} />
            <div className="findings-layout">
            <aside className="findings-rail" aria-label="Filter findings">
            <div className="toolbar">
              <label className="search-box">
                <span className="visually-hidden">Search checks</span>
                <input
                  ref={searchInput}
                  type="search"
                  placeholder="Search checks, files, evidence"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                />
                <kbd aria-hidden="true">/</kbd>
              </label>
              <div className="seg" role="group" aria-label="Show">
                {filterButtons.map((f) => (
                  <button key={f.id} type="button" aria-pressed={filter === f.id} onClick={() => setFilter(f.id)}>
                    {f.label} <span className="count">{f.n}</span>
                  </button>
                ))}
              </div>
              <div className="seg" role="group" aria-label="Group by">
                <button type="button" aria-pressed={view === "severity"} onClick={() => setView("severity")}>
                  By severity
                </button>
                <button type="button" aria-pressed={view === "category"} onClick={() => setView("category")}>
                  By category
                </button>
              </div>
              <div className="seg lang-toggle" role="group" aria-label="Explanation language">
                <button type="button" aria-pressed={lang === "en"} onClick={() => setLang("en")}>
                  English
                </button>
                <button type="button" aria-pressed={lang === "hi"} onClick={() => setLang("hi")} lang="hi">
                  हिन्दी
                </button>
              </div>
              {(
                <label className="ai-lang" title={aiFor ? undefined : "AI explanations run on the live AWS site"}>
                  <span>More languages</span>
                  <select value={aiLang} disabled={!aiFor} onChange={(e) => setAiLang(e.target.value)}>
                    {AI_LANGS.map((l) => (
                      <option key={l.id} value={l.id} lang={l.id}>
                        {l.native}
                        {l.id === "en" ? "" : ` (${l.label})`}
                      </option>
                    ))}
                  </select>
                </label>
              )}
            </div>
            </aside>
            <div className="findings-main">
            {lang === "hi" && (
              <p className="hi-line" lang="hi">
                {report.total} {ui.hi.of} <strong>{report.passed}</strong> {ui.hi.checksPass}
              </p>
            )}
            {shown.length === 0 ? (
              <p className="empty-state">{q ? `No ${filter === "all" ? "" : `${filterButtons.find((f) => f.id === filter)?.label.toLowerCase()} `}checks match “${query.trim()}”.` : "Nothing here."}</p>
            ) : view === "severity" ? (
              <div className="finding-list">
                {shown.map((r) => (
                  <FindingRow key={r.checkId} result={r} lang={lang} hasFix={hasFix(r)} ai={aiFor} />
                ))}
              </div>
            ) : (
              groups.map((g) => (
                <section className="group" key={g.id}>
                  <h3>
                    <span className="group-letter">{groupLabels[g.id]}</span>
                  </h3>
                  <div className="finding-list">
                    {g.items.map((r) => (
                      <FindingRow key={r.checkId} result={r} lang={lang} hasFix={hasFix(r)} ai={aiFor} />
                    ))}
                  </div>
                </section>
              ))
            )}
            {failing.length > 0 && (
              <div className="step-cta">
                <p>
                  <strong>{fixableFailing}</strong> of {failing.length} can be fixed automatically.
                </p>
                <button type="button" className="button primary" onClick={() => go("fixes")}>
                  Review fixes
                </button>
              </div>
            )}
            </div>
            </div>
          </section>
        )}

        {step === "fixes" && report && (
          <section className="fixes-step">
            <div className="step-head with-actions">
              <div>
                <h1 ref={heading} tabIndex={-1}>
                  {stepTitle.fixes}
                </h1>
                <p className="lede">
                  Nothing changes until you approve it.
                </p>
              </div>
              {patchResult && patches.length > 0 && (
                <div className="head-actions">
                  <button
                    type="button"
                    className="button approve"
                    disabled={toApprove.length === 0 || !!busy || !!pendingId}
                    onClick={() => void handleApproveAll()}
                  >
                    {busy === "approve-all" ? "Approving…" : `Approve all guard-passed (${toApprove.length})`}
                  </button>
                  <button
                    type="button"
                    className="button secondary"
                    disabled={!!busy || !!pendingId}
                    onClick={() => void handleGenerate()}
                  >
                    Regenerate
                  </button>
                </div>
              )}
            </div>

            {busy === "patches" && (
              <div className="state-box" aria-hidden="true">
                <p>Drafting patches and rescanning…</p>
              </div>
            )}

            {!patchResult && busy !== "patches" && (
              <div className="state-box">
                <p>No patches drafted yet.</p>
                <button type="button" className="button primary" onClick={() => void handleGenerate()}>
                  Draft patches
                </button>
              </div>
            )}

            {patchResult && patches.length === 0 && (
              <p className="empty-state">
                {failing.length === 0 ? "Nothing to fix: every applicable check passes." : "No failing check has an auto-fix template. See the list below."}
              </p>
            )}

            {patchResult && patches.length > 0 && selected && (
              <div className="fix-layout">
                <ol className="fix-list" aria-label="Patches">
                  {patches.map((e) => {
                    const isOn = approved.includes(e.patch.id);
                    const added = e.guard.added;
                    const removed = e.guard.removed;
                    return (
                      <li key={e.patch.id}>
                        <button
                          type="button"
                          aria-current={selected.patch.id === e.patch.id ? "true" : undefined}
                          onClick={() => setSelectedPatch(e.patch.id)}
                        >
                          <span className="fix-title">
                            {isOn && <span className="fix-done" aria-label="approved">✓ </span>}
                            {e.patch.title}
                          </span>
                          <span className="fix-meta">
                            <span className={`severity ${severityOf(e.patch.checkId)}`}>{severityOf(e.patch.checkId)}</span>
                            <span className={`guard-chip ${e.guard.ok ? "ok" : "blocked"}`}>{e.guard.ok ? "guard ok" : "blocked"}</span>
                            <span className="fix-lines">
                              <span className="plus">+{added}</span> <span className="minus">−{removed}</span>
                            </span>
                          </span>
                        </button>
                      </li>
                    );
                  })}
                </ol>
                <div className="fix-detail">
                  <PatchCard
                    key={selected.patch.id}
                    entry={selected}
                    scanId={scanId}
                    tamperable={selected.patch.id === tamperId}
                    approved={approved.includes(selected.patch.id)}
                    pending={pendingId === selected.patch.id}
                    locked={(!!pendingId && pendingId !== selected.patch.id) || busy === "approve-all"}
                    onApprove={() => void approveOne(selected.patch.id)}
                  />
                </div>
              </div>
            )}

            {manual.length > 0 && (
              <section className="manual-list">
                <h2>Needs a human ({manual.length})</h2>
                <ul>
                  {manual.map((r) => {
                    const first = r.findings[0];
                    return (
                      <li key={r.checkId}>
                        <div className="manual-head">
                          <strong>{r.title}</strong>
                          <span className={`severity ${r.severity}`}>{r.severity}</span>
                        </div>
                        {first && (
                          <>
                            <code className="finding-loc">
                              {first.file || "repository"}
                              {first.line ? `:${first.line}` : ""}
                            </code>
                            <p>{first.explanation}</p>
                          </>
                        )}
                        {r.findings.length > 1 && <small>and {plural(r.findings.length - 1, "more place")}</small>}
                      </li>
                    );
                  })}
                </ul>
              </section>
            )}

            {patchResult && (
              <div className="step-cta">
                <p>
                  {patches.length > 0 ? (
                    <>
                      {approved.length} of {patches.length} approved. All of them: <strong>{patchResult.scoreAfter}</strong>.
                    </>
                  ) : (
                    "Nothing to approve."
                  )}
                </p>
                <button type="button" className="button primary" onClick={() => go("verify")}>
                  Verify & download →
                </button>
              </div>
            )}
          </section>
        )}

        {step === "verify" && report && patchResult && (
          <section className="verify-step">
            <div className="step-head">
              <h1 ref={heading} tabIndex={-1}>
                {stepTitle.verify}
              </h1>
            </div>
            <div className="verify-scores">
              <div>
                <span>Before</span>
                <strong>{report.score}</strong>
              </div>
              <div className="is-main">
                <span>With approved fixes</span>
                <strong>{mock || patchResult.mock ? "—" : (summary?.score ?? report.score)}</strong>
                <small>
                  {mock || patchResult.mock
                    ? "Needs the scan server."
                    : approved.length === 0
                      ? "Nothing approved yet."
                      : `${plural(approved.length, "patch")} approved.`}
                </small>
              </div>
              <div>
                <span>Ideal</span>
                <strong>{patchResult.scoreAfter}</strong>
                <small>Every fix approved.</small>
              </div>
            </div>

            {!mock && !patchResult.mock && scanId && (
              <VerifyPanel key={`v-${scanId}`} scanId={scanId} approved={approved} features={features} onStatus={setVerifyStatus} />
            )}

            {(() => {
              const impact = {
                report,
                summary: mock || patchResult.mock ? null : summary,
                idealScore: patchResult.scoreAfter,
                approvedPatches: patches.filter((e) => approved.includes(e.patch.id)),
                verify: verifyStatus,
              };
              return <ImpactSection {...impact} onCard={() => void downloadImpactCard(impact)} />;
            })()}

            {summary && summary.failing.length > 0 && (
              <section className="still-failing">
                <h2>Still failing after your approvals</h2>
                <ul>
                  {summary.failing.map((id) => {
                    const r = report.results.find((x) => x.checkId === id);
                    return (
                      <li key={id}>
                        <span>{r?.title ?? id}</span>
                        {r && <span className={`severity ${r.severity}`}>{r.severity}</span>}
                      </li>
                    );
                  })}
                </ul>
              </section>
            )}

            <div className="ship-row">
              <section className="ship-card">
                <h2>Download</h2>
                <p>
                  Changed files from approved patches. Unzip over the repo, check <code>git diff</code>, run your tests, commit.
                </p>
                <button
                  type="button"
                  className="button primary"
                  disabled={approved.length === 0 || downloading}
                  onClick={() => void handleDownload()}
                >
                  {downloading ? "Building…" : approved.length === 0 ? "Approve a patch first" : "Download approved changes"}
                </button>
              </section>
              {!mock && !patchResult.mock && scanId && <PullRequestPanel key={`pr-${scanId}`} scanId={scanId} approved={approved} />}
            </div>

            {demo && <ProofPanel key={scanId} scanId={scanId} approved={approved} mock={mock} results={results} />}
          </section>
        )}
      </main>
    </div>
  );
}
