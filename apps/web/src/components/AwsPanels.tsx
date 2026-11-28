import { useEffect, useRef, useState, type FormEvent } from "react";
import {
  explain,
  getScan,
  openPullRequest,
  startVerify,
  verifyStatus,
  type AiExplanation,
  type Features,
  type Verdict,
  type VerifyStatus,
} from "../api/client";

export const AI_LANGS: { id: string; label: string; native: string }[] = [
  { id: "en", label: "English", native: "English" },
  { id: "hi", label: "Hindi", native: "हिन्दी" },
  { id: "bn", label: "Bengali", native: "বাংলা" },
  { id: "mr", label: "Marathi", native: "मराठी" },
  { id: "ta", label: "Tamil", native: "தமிழ்" },
  { id: "te", label: "Telugu", native: "తెలుగు" },
  { id: "gu", label: "Gujarati", native: "ગુજરાતી" },
  { id: "kn", label: "Kannada", native: "ಕನ್ನಡ" },
];

/** How a vulnerable package gets into the app: your app → express → body-parser → qs. */
export function DependencyChain({ chain }: { chain: string[] }) {
  if (chain.length < 2) return null;
  const steps = ["your app", ...chain];
  return (
    <div className="dep-chain" aria-label={`Dependency path: ${steps.join(", then ")}`}>
      <span className="dep-chain-label">How it gets in</span>
      <ol>
        {steps.map((name, i) => (
          <li key={`${name}-${i}`} className={i === 0 ? "is-app" : i === steps.length - 1 ? "is-vuln" : i === 1 ? "is-direct" : ""}>
            <code>{name}</code>
            {i === 1 && <small>you installed this</small>}
            {i === steps.length - 1 && <small>vulnerable</small>}
          </li>
        ))}
      </ol>
    </div>
  );
}

/** One finding, explained by Amazon Bedrock in the chosen language, checked against the scan's evidence. */
export function AiExplain({ scanId, checkId, index, lang }: { scanId: string; checkId: string; index: number; lang: string }) {
  const [state, setState] = useState<{ busy: boolean; result?: AiExplanation; error?: string; forLang?: string }>({ busy: false });
  const langLabel = AI_LANGS.find((l) => l.id === lang)?.native ?? lang;
  const stale = state.result && state.forLang !== lang;

  async function run() {
    setState({ busy: true });
    try {
      setState({ busy: false, result: await explain(scanId, checkId, index, lang), forLang: lang });
    } catch (e) {
      setState({ busy: false, error: e instanceof Error ? e.message : "The explanation failed." });
    }
  }

  if (!state.result || stale) {
    return (
      <div className="ai-explain is-idle">
        <button type="button" className="button ai-button" disabled={state.busy} onClick={() => void run()}>
          {state.busy ? "Asking Amazon Bedrock…" : `Explain simply in ${langLabel}`}
        </button>
        {state.error && <p className="error-text">{state.error}</p>}

      </div>
    );
  }
  const r = state.result;
  const e = r.explanation;
  const grounded = r.ungrounded.length === 0;
  return (
    <div className={`ai-explain ${grounded ? "" : "is-rejected"}`} lang={r.lang}>
      <div className="ai-head">
        <span className="ai-tag">AI explanation</span>
        <span className="muted">
          Amazon Bedrock · {r.model.replace(/^(apac|us|eu)\./, "")} · {r.cached ? "saved" : `${(r.ms / 1000).toFixed(1)} s`}
        </span>
      </div>
      {!grounded && (
        <p className="error-text" lang="en">
          Rejected: the model mentioned {r.ungrounded.join(", ")}, which the scan evidence does not contain. Rely on the scanner text above.
        </p>
      )}
      <p className="ai-summary">{e.summary}</p>
      {e.impact && (
        <p>
          <strong>What could happen:</strong> {e.impact}
        </p>
      )}
      <p>
        <strong>What to do:</strong> {e.fix}
      </p>
      {e.options.length > 0 && (
        <ul className="ai-options">
          {e.options.map((o, i) => (
            <li key={i}>
              <strong>{o.option}</strong>
              {o.tradeoff && <span> {o.tradeoff}</span>}
            </li>
          ))}
        </ul>
      )}
      {e.unknowns && (
        <p className="ai-unknowns">
          <strong>Not known from the evidence:</strong> {e.unknowns}
        </p>
      )}
      <p className="ai-grounding" lang="en">
        {grounded ? "✓ Every advisory id and version above appears in the scan evidence." : "✗ Failed the evidence check."}
      </p>
    </div>
  );
}

const STATUS_TEXT: Record<Verdict["status"], string> = {
  verified: "Verified",
  inconclusive: "Inconclusive",
  "not-verified": "Not verified",
  regression: "Breaking fix caught",
  error: "Build error",
};

const STAGES = ["Upload before + after to S3", "Step Functions starts the workflow", "CodeBuild: npm install → npm test → npm audit", "Lambda applies the trust rule"];

/** Runs the approved fixes in a throwaway AWS CodeBuild container and shows the trust-rule verdict. */
export function VerifyPanel({
  scanId,
  approved,
  features,
  onStatus,
}: {
  scanId: string;
  approved: string[];
  features: Features | null;
  /** Lets the Impact section chart the build's measurements. */
  onStatus?: (s: VerifyStatus | null) => void;
}) {
  const [jobId, setJobId] = useState<string | null>(null);
  const [status, setStatus] = useState<VerifyStatus | null>(null);
  const [error, setError] = useState("");
  const [starting, setStarting] = useState(false);
  const timer = useRef<number | undefined>(undefined);
  const approvedKey = [...approved].sort().join(",");
  useEffect(() => {
    onStatus?.(status);
  }, [status, onStatus]);

  // Resume the last run for this scan after a reload.
  useEffect(() => {
    let cancelled = false;
    if (!features?.verify) return;
    getScan(scanId)
      .then((s) => {
        const lv = (s as { latestVerify?: { jobId: string; approved: string[] } }).latestVerify;
        if (!cancelled && lv && [...lv.approved].sort().join(",") === approvedKey) setJobId(lv.jobId);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [scanId, features?.verify, approvedKey]);

  useEffect(() => {
    if (!jobId) return;
    let cancelled = false;
    const poll = async () => {
      try {
        const s = await verifyStatus(scanId, jobId);
        if (cancelled) return;
        setStatus(s);
        if (s.state === "running") timer.current = window.setTimeout(poll, 4000);
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : "Could not read the build status.");
      }
    };
    void poll();
    return () => {
      cancelled = true;
      window.clearTimeout(timer.current);
    };
  }, [scanId, jobId]);

  async function run() {
    setError("");
    setStatus(null);
    setStarting(true);
    try {
      const r = await startVerify(scanId);
      setJobId(r.jobId);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not start the build.");
    } finally {
      setStarting(false);
    }
  }

  if (!features?.verify) {
    return (
      <section className="aws-panel">
        <h2>Isolated verification</h2>
        <p className="muted">Runs on the AWS deployment (Step Functions + CodeBuild). This server does not have it.</p>
      </section>
    );
  }
  const v = status?.verdict;
  const elapsed = status?.elapsed ?? 0;
  const activeStage = status?.state === "running" ? (elapsed < 8 ? 1 : 2) : -1;
  return (
    <section className={`aws-panel verify-panel ${v ? `is-${v.status}` : ""}`} aria-labelledby="verify-title" aria-live="polite">
      <div className="aws-panel-head">
        <div>
          <h2 id="verify-title">Prove it on AWS</h2>
        </div>
        <button type="button" className="button primary" disabled={approved.length === 0 || starting || status?.state === "running"} onClick={() => void run()}>
          {approved.length === 0 ? "Approve a fix first" : starting ? "Starting…" : status?.state === "running" ? "Running…" : v ? "Run again" : "Run verification"}
        </button>
      </div>
      <details className="quiet-more">
        <summary>What runs</summary>
        <p className="muted">
          Your original and fixed code each get <code>npm install</code>, your <code>npm test</code> and an independent <code>npm audit</code> in a throwaway
          container, with install scripts off and AWS credentials removed. Verified means the tests pass and the flagged packages are gone.
        </p>
      </details>

      {status?.state === "running" && (
        <ol className="stages">
          {STAGES.map((s, i) => (
            <li key={s} className={i < activeStage ? "done" : i === activeStage ? "active" : ""}>
              {s}
            </li>
          ))}
          <li className="elapsed">{elapsed}s elapsed · usually 1–3 minutes</li>
        </ol>
      )}
      {status?.state === "error" && <p className="error-text">{status.error}</p>}
      {error && <p className="error-text">{error}</p>}

      {v && (
        <div className="verdict-block">
          <div className={`verdict-badge is-${v.status}`}>{STATUS_TEXT[v.status]}</div>
          <p className="verdict-headline">{v.headline}</p>
          <ul className="verdict-checks">
            {v.checks.map((c) => (
              <li key={c.label} className={c.ok === true ? "ok" : c.ok === false ? "bad" : "na"}>
                <span aria-hidden="true">{c.ok === true ? "✓" : c.ok === false ? "✗" : "–"}</span>
                <strong>{c.label}</strong>
                <span className="muted">{c.detail}</span>
              </li>
            ))}
          </ul>
          {v.targets.length > 0 && (
            <table className="verdict-table">
              <caption>Flagged packages, checked by npm audit</caption>
              <thead>
                <tr>
                  <th scope="col">Package</th>
                  <th scope="col">Before</th>
                  <th scope="col">After the fix</th>
                </tr>
              </thead>
              <tbody>
                {v.targets.map((t) => (
                  <tr key={t.name}>
                    <td>
                      <code>{t.name}</code>
                    </td>
                    <td className={t.before ? "bad" : "muted"}>{t.before ?? "not reported"}</td>
                    <td className={t.fixed ? "ok" : "bad"}>{t.fixed ? "clean" : (t.after ?? "unknown")}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          {v.result?.after.tests.ran && v.result.after.tests.tail && (
            <details className="test-tail">
              <summary>Test output after the fix</summary>
              <pre>{v.result.after.tests.tail}</pre>
            </details>
          )}
          <p className="muted small">
            {v.result?.node ? `Node ${v.result.node.replace(/^v/, "")} · npm ${v.result.npm} · ` : ""}finished {new Date(v.finishedAt).toLocaleTimeString()}
            {v.remaining.length > 0 ? ` · ${v.remaining.length} vulnerable package(s) still in the tree` : ""}
          </p>
        </div>
      )}
    </section>
  );
}

/** Opens a pull request with the approved fixes and the verification evidence. The token is used once. */
export function PullRequestPanel({ scanId, approved }: { scanId: string; approved: string[] }) {
  const [repo, setRepo] = useState<string | null | undefined>(undefined);
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [pr, setPr] = useState<{ url: string; number: number } | null>(null);

  useEffect(() => {
    getScan(scanId)
      .then((s) => setRepo((s as { github?: string }).github ?? null))
      .catch(() => setRepo(null));
  }, [scanId]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      setPr(await openPullRequest(scanId, token.trim()));
      setToken("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not open the pull request.");
    } finally {
      setBusy(false);
    }
  }

  if (repo === undefined) return null;
  if (repo === null) {
    return (
      null
    );
  }
  return (
    <section className="aws-panel pr-panel" aria-labelledby="pr-title">
      <h2 id="pr-title">Open a pull request</h2>
      {pr ? (
        <p className="pr-done">
          Opened{" "}
          <a href={pr.url} target="_blank" rel="noreferrer">
            pull request #{pr.number}
          </a>
          . Nothing merges until you approve it.
        </p>
      ) : (
        <form className="pr-form" onSubmit={(e) => void submit(e)}>
          <p className="muted">
            Paste a{" "}
            <a href="https://github.com/settings/personal-access-tokens/new" target="_blank" rel="noreferrer">
              fine-grained token
            </a>{" "}
            for this repo with <strong>Contents</strong>, <strong>Pull requests</strong> and <strong>Workflows</strong> read and write. Used once, never stored.
          </p>
          <label>
            <span className="visually-hidden">GitHub token</span>
            <input
              type="password"
              autoComplete="off"
              spellCheck={false}
              placeholder="github_pat_…"
              value={token}
              onChange={(e) => setToken(e.target.value)}
            />
          </label>
          <button type="submit" className="button primary" disabled={busy || approved.length === 0 || token.trim().length < 20}>
            {approved.length === 0 ? "Approve a fix first" : busy ? "Opening…" : "Open pull request"}
          </button>
          {error && <p className="error-text">{error}</p>}
        </form>
      )}
    </section>
  );
}
