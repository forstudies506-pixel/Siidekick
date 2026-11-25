import { useEffect, useRef, useState, type ChangeEvent, type InputHTMLAttributes } from "react";
import type { CheckGroup, CheckResult, RepoFile } from "../../../../packages/engine/src/types";
import {
  approve,
  createDemoScan,
  download,
  generatePatches,
  isMockSession,
  uploadScan,
  type PatchEntry,
  type PatchResponse,
  type ScanResponse,
} from "../api/client";

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

const plural = (n: number, word: string) => `${n} ${word}${n === 1 ? "" : "s"}`;

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

function FindingRow({ result }: { result: CheckResult }) {
  return (
    <details className={`finding-row ${result.passed ? "is-passed" : "is-failed"}`}>
      <summary>
        <span className="finding-name">{result.title}</span>
        <span className={`severity ${result.severity}`}>{result.severity}</span>
        <span className={`verdict ${result.passed ? "pass" : "fail"}`}>{result.passed ? "pass" : "fail"}</span>
      </summary>
      <div className="finding-content">
        {result.findings.length === 0 ? (
          <p>Nothing to fix here.</p>
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
          <p className="fix-mode">
            {result.mode === "report"
              ? "Reported only: this one needs the owner's own edit."
              : "A guarded patch can be proposed for this."}
          </p>
        )}
        {result.error && <p className="error-text">{result.error}</p>}
      </div>
    </details>
  );
}

const SIGN = { add: "+", del: "−", same: " " } as const;
const SR_SIGN = { add: "added: ", del: "removed: ", same: "" } as const;

function PatchCard({
  entry,
  approved,
  pending,
  onApprove,
}: {
  entry: PatchEntry;
  approved: boolean;
  pending: boolean;
  onApprove: () => void;
}) {
  const { patch, guard, diff } = entry;
  const label = approved ? "Approved" : pending ? "Approving…" : guard.ok ? "Approve patch" : "Blocked: cannot approve";
  return (
    <article className={`patch-card${guard.ok ? "" : " blocked"}`}>
      <div className="patch-meta">
        <div>
          <h3>{patch.title}</h3>
          <p>{patch.reason}</p>
        </div>
        <div className="patch-chips">
          <span className="chip">{patch.class}</span>
          <span className={`guard-verdict ${guard.ok ? "ok" : "bad"}`}>{guard.ok ? "guard passed" : "guard blocked"}</span>
        </div>
      </div>
      <p className="guard-counts">
        <span>+{guard.added} added</span>
        <span>−{guard.removed} removed</span>
      </p>
      {guard.violations.length > 0 && (
        <ul className="violations">
          {guard.violations.map((v, index) => (
            <li key={`${v.reason}-${index}`}>
              <code>{v.reason}</code> in <code>{v.path}</code>
              {v.line && (
                <>
                  {" "}
                  on <code>{v.line}</code>
                </>
              )}
            </li>
          ))}
        </ul>
      )}
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
      <button className="button approve" disabled={!guard.ok || approved || pending} onClick={onApprove}>
        {label}
      </button>
    </article>
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
  const inputRef = useRef<HTMLInputElement>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const demoStarted = useRef(false);

  useEffect(() => {
    // StrictMode runs effects twice in dev; one demo scan is enough.
    if (demoStarted.current) return;
    demoStarted.current = true;
    if (new URLSearchParams(window.location.search).get("demo") === "1") void runScan(createDemoScan);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (report) headingRef.current?.focus();
  }, [report]);

  async function runScan(start: () => Promise<ScanResponse>, nextNotes: string[] = []) {
    setBusy("scan");
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
      const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `siidekick-${report?.repo ?? "repo"}-approved.json`;
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
              Use the demo shop or pick a project folder. Nothing in your code changes until you approve a patch.
            </p>
          </div>
          <div className="start-actions">
            <button className="button primary" onClick={() => runScan(createDemoScan)} disabled={busy !== ""}>
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
            <span>Twelve checks run on the files you give it. The demo shop takes about a second.</span>
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
                  <p className="passed-total">
                    <strong>{report.passed}</strong> of {report.total} checks pass
                  </p>
                </div>
                <Score score={report.score} />
              </div>
              <div className="report-groups">
                {grouped.map(({ group, results }) => (
                  <section key={group} className="group">
                    <h3>
                      <span className="group-letter">{group[0]}</span>
                      {groupLabels[group]}
                    </h3>
                    {results.map((result) => (
                      <FindingRow key={result.checkId} result={result} />
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
          </>
        )}
      </main>
    </>
  );
}
