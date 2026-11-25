import { useEffect, useRef, useState, type ChangeEvent, type FormEvent, type InputHTMLAttributes } from "react";
import type { CheckGroup, CheckResult, FileEdit, GuardViolation, RepoFile } from "../../../../packages/engine/src/types";
import {
  approve,
  checkPatch,
  createDemoScan,
  download,
  generatePatches,
  githubScan,
  isMockSession,
  proveFix,
  uploadScan,
  type AttackPath,
  type AttackReceipt,
  type CheckResponse,
  type ReplayReport,
  type ReplayVerdict,
  type PatchEntry,
  type PatchResponse,
  type ScanResponse,
} from "../api/client";
import { checkHi, ui, type Lang } from "../i18n/hi";
import { zipFiles } from "../zip";

const groupLabels: Record<CheckGroup, string> = {
  "A-delivery": "Delivery",
  "B-monitoring": "Monitoring",
  "C-security": "Security",
  "D-domain": "Domain",
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

function FindingRow({ result, lang }: { result: CheckResult; lang: Lang }) {
  const t = ui[lang];
  const hi = lang === "hi" ? checkHi[result.checkId] : undefined;
  return (
    <details className={`finding-row ${result.passed ? "is-passed" : "is-failed"}`}>
      <summary>
        <span className="finding-name" lang={hi ? "hi" : undefined}>
          {hi?.title ?? result.title}
        </span>
        <span className={`severity ${result.severity}`}>{result.severity}</span>
        <span className={`verdict ${result.passed ? "pass" : "fail"}`} lang={lang}>
          {result.passed ? t.pass : t.fail}
        </span>
      </summary>
      <div className="finding-content">
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
              <p>{finding.explanation}</p>
            </div>
          ))
        )}
        {!result.passed && (
          <p className="fix-mode" lang={lang}>
            {result.mode === "report" ? t.reportOnly : t.patchable}
          </p>
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
  onApprove,
}: {
  entry: PatchEntry;
  scanId: string;
  tamperable: boolean;
  approved: boolean;
  pending: boolean;
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
        <button className="button approve" disabled={!guard.ok || approved || pending} onClick={onApprove}>
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

type Busy = "" | "scan" | "patches";

export function Dashboard() {
  const [report, setReport] = useState<ScanResponse["report"] | null>(null);
  const [scanId, setScanId] = useState("");
  const [mock, setMock] = useState(isMockSession());
  const [busy, setBusy] = useState<Busy>("");
  const [error, setError] = useState("");
  const [notes, setNotes] = useState<string[]>([]);
  const [patchResult, setPatchResult] = useState<PatchResponse | null>(null);
  const [approved, setApproved] = useState<string[]>([]);
  const [approving, setApproving] = useState("");
  const [lang, setLang] = useState<Lang>("en");
  const [repoUrl, setRepoUrl] = useState("");
  const [demo, setDemo] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const demoStarted = useRef(false);

  useEffect(() => {
    // StrictMode runs effects twice in dev; one demo scan is enough.
    if (demoStarted.current) return;
    demoStarted.current = true;
    if (new URLSearchParams(window.location.search).get("demo") === "1") void runScan(createDemoScan, [], true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (report) headingRef.current?.focus();
  }, [report]);

  async function runScan(start: () => Promise<ScanResponse>, nextNotes: string[] = [], isDemo = false) {
    setBusy("scan");
    setDemo(isDemo);
    setError("");
    setNotes(nextNotes);
    setReport(null);
    setScanId("");
    setPatchResult(null);
    setApproved([]);
    try {
      const result = await start();
      setReport(result.report);
      setScanId(result.id);
      setMock(result.mock || isMockSession());
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "The scan did not finish.");
    } finally {
      setBusy("");
    }
  }

  async function handleFiles(event: ChangeEvent<HTMLInputElement>) {
    const input = event.target;
    const list = input.files;
    if (!list?.length) return;
    try {
      const folder = await readFolder(list);
      if (folder.files.length === 0) {
        setNotes(folder.notes);
        setError("No readable text files in that folder.");
        return;
      }
      await runScan(() => uploadScan(folder.name, folder.files), folder.notes);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not read this folder.");
    } finally {
      input.value = "";
    }
  }

  function handleGithub(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const url = repoUrl.trim();
    if (url) void runScan(() => githubScan(url));
  }

  async function handleGenerate() {
    if (!scanId || !report) return;
    setBusy("patches");
    setError("");
    try {
      const result = await generatePatches(scanId, report.repo);
      setPatchResult(result);
      setApproved([]);
      setMock((current) => current || result.mock);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not generate patches.");
    } finally {
      setBusy("");
    }
  }

  async function handleApprove(patchId: string) {
    setApproving(patchId);
    setError("");
    try {
      setApproved(await approve(scanId, patchId));
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not approve this patch.");
    } finally {
      setApproving("");
    }
  }

  async function handleDownload() {
    try {
      const result = await download(scanId);
      const url = URL.createObjectURL(zipFiles(result.files));
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `siidekick-${report?.repo ?? "repo"}-approved.zip`;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "Could not prepare the download.");
    }
  }

  const grouped = report
    ? (Object.keys(groupLabels) as CheckGroup[])
        .map((group) => ({ group, results: report.results.filter((r) => r.group === group) }))
        .filter((entry) => entry.results.length > 0)
    : [];

  const patches = patchResult?.patches ?? [];
  // One tamper button is enough for the demo: the first approvable patch that edits an existing file.
  const tamperId =
    mock || patchResult?.mock ? undefined : patches.find((e) => e.guard.ok && tamperEdits(e.patch.edits))?.patch.id;
  const statusText =
    busy === "scan"
      ? "Scanning files."
      : busy === "patches"
        ? "Generating fixes."
        : report
          ? `Scan finished. ${report.passed} of ${report.total} checks pass. Score ${report.score}.`
          : "";

  return (
    <>
      <header className="dashboard-header">
        <a className="wordmark" href="/" aria-label="Siidekick home">
          Siide<span>kick</span>
        </a>
        <div className="dashboard-tools">
          {mock && <span className="demo-badge">demo data, API offline</span>}
          <a href="/">Back to site</a>
        </div>
      </header>
      <main className="dashboard">
        <p className="visually-hidden" role="status">
          {statusText}
        </p>

        <section className="start-panel" aria-labelledby="scan-title">
          <div>
            <h1 id="scan-title">Review a small repo</h1>
            <p className="muted">
              Paste a public GitHub repo, use the demo shop, or pick a folder. Nothing in your code changes until you
              approve a patch.
            </p>
          </div>
          <div className="start-inputs">
            <form className="repo-form" onSubmit={handleGithub}>
              <label htmlFor="repo-url">Public GitHub repo</label>
              <div>
                <input
                  id="repo-url"
                  type="url"
                  inputMode="url"
                  required
                  placeholder="https://github.com/owner/repo"
                  value={repoUrl}
                  onChange={(event) => setRepoUrl(event.target.value)}
                  aria-describedby="repo-note"
                />
                <button className="button primary" type="submit" disabled={busy !== ""}>
                  Scan repo
                </button>
              </div>
              <small id="repo-note">Only scan repos you own or have permission to scan. No code is run.</small>
            </form>
          <div className="start-actions">
            <button className="button secondary" onClick={() => runScan(createDemoScan, [], true)} disabled={busy !== ""}>
              Scan the demo shop
            </button>
            <button className="button secondary" onClick={() => inputRef.current?.click()} disabled={busy !== ""}>
              Choose a folder
            </button>
            <input
              ref={inputRef}
              className="visually-hidden"
              type="file"
              multiple
              tabIndex={-1}
              aria-hidden="true"
              {...({ webkitdirectory: "", directory: "" } as InputHTMLAttributes<HTMLInputElement>)}
              onChange={handleFiles}
            />
          </div>
          </div>
        </section>

        <div role="alert">{error && <div className="state-box error">{error}</div>}</div>
        {notes.length > 0 && (
          <ul className="notes">
            {notes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        )}
        {busy === "scan" && <div className="state-box">Scanning files…</div>}
        {busy !== "scan" && !report && (
          <div className="empty-state">
            <strong>No scan yet</strong>
            <span>15 checks run on the files you give it. The demo shop takes about a second.</span>
          </div>
        )}

        {report && (
          <>
            <section className="report-panel" aria-labelledby="report-title">
              <div className="report-heading">
                <div>
                  <h2 id="report-title" ref={headingRef} tabIndex={-1}>
                    {report.repo}
                  </h2>
                  {lang === "hi" ? (
                    <p className="passed-total" lang="hi">
                      {report.total} {ui.hi.of} <strong>{report.passed}</strong> {ui.hi.checksPass}
                    </p>
                  ) : (
                    <p className="passed-total">
                      <strong>{report.passed}</strong> of {report.total} checks pass
                    </p>
                  )}
                </div>
                <Score score={report.score} />
              </div>
              <div className="lang-toggle" role="group" aria-label="Explanation language">
                <button type="button" aria-pressed={lang === "en"} onClick={() => setLang("en")}>
                  English
                </button>
                <button type="button" lang="hi" aria-pressed={lang === "hi"} onClick={() => setLang("hi")}>
                  हिन्दी
                </button>
              </div>
              <div className="report-groups">
                {grouped.map(({ group, results }) => (
                  <section key={group} className="group">
                    <h3>
                      <span className="group-letter">{group[0]}</span>
                      {groupLabels[group]}
                    </h3>
                    {results.map((result) => (
                      <FindingRow key={result.checkId} result={result} lang={lang} />
                    ))}
                  </section>
                ))}
              </div>
            </section>

            <section className="patches-panel" aria-labelledby="patches-title">
              <div className="patches-heading">
                <div>
                  <h2 id="patches-title">Proposed fixes</h2>
                  <p className="muted">Each patch only adds lines. The diff guard blocks any patch that deletes or rewrites yours.</p>
                </div>
                <button className="button primary" onClick={handleGenerate} disabled={busy !== ""}>
                  {busy === "patches" ? "Generating…" : patchResult ? "Generate again" : "Generate fixes"}
                </button>
              </div>

              {patchResult && patches.length === 0 && <p className="muted">No patch templates apply to this repo.</p>}

              {patches.map((entry) => (
                <PatchCard
                  key={entry.patch.id}
                  entry={entry}
                  scanId={scanId}
                  tamperable={entry.patch.id === tamperId}
                  approved={approved.includes(entry.patch.id)}
                  pending={approving === entry.patch.id}
                  onApprove={() => handleApprove(entry.patch.id)}
                />
              ))}

              {patchResult && patches.length > 0 && (
                <div className="rescan-result">
                  <div className="rescan-score">
                    <strong>{patchResult.scoreBefore}</strong>
                    <span aria-hidden="true">→</span>
                    <span className="visually-hidden">to</span>
                    <strong>{patchResult.scoreAfter}</strong>
                  </div>
                  <p className="muted">
                    {patchResult.mock
                      ? "Projected score with the guard-passed patches applied. Demo data, not a live rescan."
                      : "Score after a rescan with the guard-passed patches applied. Tests were not run."}
                  </p>
                  <span className={`status-chip ${patchResult.status}`}>
                    {patchResult.status === "rescan-clean" ? "every check passes" : "some checks still fail"}
                  </span>
                  <button className="button secondary" onClick={handleDownload} disabled={approved.length === 0}>
                    {approved.length === 0 ? "Approve a patch to download" : `Download ${plural(approved.length, "approved patch")}`}
                  </button>
                </div>
              )}
            </section>

            {demo && patchResult && patches.length > 0 && (
              <ProofPanel key={scanId} scanId={scanId} approved={approved} mock={mock || patchResult.mock} results={report.results} />
            )}
          </>
        )}
      </main>
    </>
  );
}
