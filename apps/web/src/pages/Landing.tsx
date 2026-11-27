import { useEffect, useState, type FormEvent } from "react";
import { ArrowUpRight } from "lucide-react";
import { SiteHeader } from "../components/SiteHeader";
import { getChecks, type CheckInfo } from "../api/client";
import type { CheckGroup } from "../../../../packages/engine/src/types";

const groupLabels: Record<CheckGroup, string> = {
  "A-delivery": "Delivery",
  "B-monitoring": "Monitoring",
  "C-security": "Security",
  "D-domain": "India",
  "E-states": "States",
  "F-ai": "AI-era",
  "G-enterprise": "Enterprise",
};

// Measured on the live AWS deployment, 28 Nov 2026 (README, docs/BUILD_SUMMARY.md).
const PROOF = { before: 33, after: 62, vulnBefore: 8, vulnAfter: 0, verifiedSeconds: 74, added: 209 };

// Sources: docs/research/BHARAT.md.
const facts = [
  {
    big: "29.44 lakh",
    text: "cyber incidents handled by CERT-In in 2025.",
    source: "PIB, Jan 2026",
    href: "https://static.pib.gov.in/WriteReadData/specificdocs/documents/2026/jan/doc2026123764501.pdf",
  },
  {
    big: "₹250 crore",
    text: "the highest DPDP penalty, for failing to keep reasonable security safeguards.",
    source: "PIB, Nov 2025",
    href: "https://static.pib.gov.in/WriteReadData/specificdocs/documents/2025/nov/doc20251117695301.pdf",
  },
  {
    big: "98%",
    text: "of Indian internet users go online in Indic languages. Security tools still speak English.",
    source: "Kantar–IAMAI, 2024",
    href: "https://www.iamai.in/sites/default/files/research/Kantar_%20IAMAI%20report_2024_.pdf",
  },
];

const flow = [
  ["Scan", "Paste a GitHub repo or upload a folder. 39 checks read the code as text; nothing is run."],
  ["Explain", "Every finding in plain words, in English, Hindi or six more Indian languages."],
  ["Fix", "Small patches that only add lines. A guard refuses anything that deletes your code."],
  ["Prove", "Your original and fixed code run in a throwaway AWS build: install, your tests, an independent audit."],
  ["Ship", "Download the fixes or open a pull request that carries the evidence. You click merge."],
  ["Keep watching", "The GitHub Action scans every pull request and marks findings on the changed lines."],
];

const bharat = [
  ["Payments nobody verified", "A Razorpay payment id trusted without its signature, or a UPI callback that believes “success” from the request."],
  ["Payment and SMS keys in code", "Razorpay, Paytm, PhonePe, Cashfree, PayU and MSG91 keys, named by vendor and moved to environment variables."],
  ["Aadhaar and PAN where they don't belong", "Checksum-validated Aadhaar numbers in code, and identity data written to logs. Always shown masked."],
  ["OTPs handed to attackers", "An OTP returned in the API response, logged, or made with Math.random."],
];

const aiEra = [
  ["Packages that don't exist", "Code assistants invent package names; attackers register them. Every dependency is checked against the registry."],
  ["Server keys in the browser", "A database or payment key behind a NEXT_PUBLIC_ or VITE_ prefix ships to every visitor."],
  ["Firebase or Supabase left open", "Test-mode rules let anyone with the project id read or write every row."],
  ["Login tokens never verified", "decode() trusts whatever a token says, so a forged admin token gets in."],
];

function ScanForm() {
  const [value, setValue] = useState("");
  function submit(e: FormEvent) {
    e.preventDefault();
    const v = value.trim();
    if (v) window.location.assign(`/app?url=${encodeURIComponent(v)}`);
  }
  return (
    <form className="hero-form" onSubmit={submit}>
      <label className="visually-hidden" htmlFor="hero-url">
        GitHub repo address
      </label>
      <input
        id="hero-url"
        type="text"
        inputMode="url"
        autoComplete="url"
        spellCheck={false}
        placeholder="github.com/you/your-app"
        value={value}
        onChange={(e) => setValue(e.target.value)}
      />
      <button className="button primary" type="submit" disabled={!value.trim()}>
        Scan my repo
      </button>
    </form>
  );
}

/** The one bold element: the fake payment, accepted before the fix and rejected after, as measured. */
function ProofLens() {
  return (
    <aside className="lens proof-lens" aria-labelledby="proof-title">
      <h2 id="proof-title">Same request, before and after</h2>
      <p className="pl-sub">A college-fest shop, a fake Razorpay payment, measured live on AWS.</p>
      <pre className="pl-request">
        POST /api/pay/verify{"\n"}
        {"{ "}razorpay_payment_id: <b>"pay_FAKE…"</b>, signature: <b>"forged"</b>{" }"}
      </pre>
      <div className="pl-row is-bad">
        <span className="pl-code">200</span>
        <strong>Fest pass issued</strong>
        <span>Before: no money moved, the shop believed the browser.</span>
      </div>
      <div className="pl-row is-good">
        <span className="pl-code">400</span>
        <strong>Payment not accepted</strong>
        <span>After Siidekick's fix. A real, signed payment still goes through.</span>
      </div>
      <div className="pl-stats">
        <div>
          <strong>
            {PROOF.before} → {PROOF.after}
          </strong>
          <span>security score</span>
        </div>
        <div>
          <strong>
            {PROOF.vulnBefore} → {PROOF.vulnAfter}
          </strong>
          <span>vulnerable packages</span>
        </div>
        <div>
          <strong>{PROOF.verifiedSeconds} s</strong>
          <span>to verified on AWS</span>
        </div>
      </div>
      <div className="pl-foot">
        <a className="button secondary" href="/app?demo=1">
          Replay it on the demo
        </a>
        <small>+{PROOF.added} lines added, none of the owner's deleted.</small>
      </div>
    </aside>
  );
}

type CheckList = { repo: CheckInfo[] };

function LiveChecks() {
  const [list, setList] = useState<CheckList | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let alive = true;
    getChecks()
      .then((r) => alive && setList(r))
      .catch((e: unknown) => alive && setError(e instanceof Error ? e.message : String(e)));
    return () => {
      alive = false;
    };
  }, []);
  if (error) return <p className="checks-state">The check list could not load. {error}</p>;
  if (!list) return <p className="checks-state" aria-live="polite">Loading the checks from the engine…</p>;
  return (
    <div className="check-cols is-single">
      <div className="check-col">
        <div className="check-col-head">
          <h3>Every check a scan runs</h3>
          <span>{list.repo.length}</span>
        </div>
        <p>Read live from the scanner, so this list is always what a scan actually runs.</p>
        <ul>
          {list.repo.map((c) => (
            <li key={c.id}>
              <span className="check-title">{c.title}</span>
              <span className="check-group">{groupLabels[c.group]}</span>
              <span className={`severity ${c.severity}`}>{c.severity}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export function Landing() {
  return (
    <>
      <SiteHeader />
      <main className="landing">
        <section className="hero2" aria-labelledby="hero-title">
          <div className="hero2-copy">
            <h1 id="hero-title">Find the hole before an AI does.</h1>
            <p className="hero2-sub">
              A security engineer for every student, college and small business that ships code without one. Siidekick
              reads your repo, explains each risk in your language, and proves every fix on AWS before you merge it.
            </p>
            <ScanForm />
            <div className="hero2-foot">
              <a href="/app?demo=1">No repo handy? Try the demo shop</a>
              <span>Read as text, never run on our server. No login.</span>
            </div>
          </div>
          <ProofLens />
        </section>

        <section className="facts" aria-label="Why this matters in India">
          {facts.map((f) => (
            <div key={f.big}>
              <strong>{f.big}</strong>
              <p>{f.text}</p>
              <a href={f.href} target="_blank" rel="noreferrer">
                Source: {f.source}
              </a>
            </div>
          ))}
        </section>

        <section className="sect" id="how" aria-labelledby="how-title">
          <div className="sect-head">
            <h2 id="how-title">From a repo to a proven fix</h2>
            <p>
              Scanners stop at a list of warnings. Siidekick goes on to fix what it found, then proves the fix in an
              isolated build before anything reaches your code.
            </p>
          </div>
          <ol className="flow">
            {flow.map(([name, body], i) => (
              <li key={name}>
                <span className="flow-n" aria-hidden="true">
                  {i + 1}
                </span>
                <h3>{name}</h3>
                <p>{body}</p>
              </li>
            ))}
          </ol>
        </section>

        <section className="sect" aria-labelledby="catch-title">
          <div className="sect-head">
            <h2 id="catch-title">Built for the bugs Indian apps actually ship</h2>
            <p>Generic scanners don't know how a UPI callback or an OTP login goes wrong. These checks do.</p>
          </div>
          <div className="catch-grid">
            <div className="catch">
              <h3>Bharat Pack</h3>
              <p>Payments, identity data and OTP logins.</p>
              <ul>
                {bharat.map(([t, b]) => (
                  <li key={t}>
                    <strong>{t}</strong>
                    <span>{b}</span>
                  </li>
                ))}
              </ul>
            </div>
            <div className="catch">
              <h3>Mistakes AI-written code ships</h3>
              <p>The patterns code assistants repeat, and attackers look for first.</p>
              <ul>
                {aiEra.map(([t, b]) => (
                  <li key={t}>
                    <strong>{t}</strong>
                    <span>{b}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </section>

        <section className="sect checks" id="checks" aria-labelledby="checks-title">
          <div className="sect-head">
            <h2 id="checks-title">Nothing hidden</h2>
            <p>Every check, its group and its severity, straight from the engine.</p>
          </div>
          <LiveChecks />
        </section>
      </main>
      <footer className="site-footer">
        <p className="limit-line">Siidekick reduces risk. No tool can promise an app is unhackable, and this one doesn't.</p>
        <div>
          <span>
            Built by <strong>Schrödinger&apos;s Code</strong>, a part of Echelon Systems Architecture. Live on AWS.
          </span>
          <a href="https://github.com/forstudies506-pixel/Siidekick" target="_blank" rel="noreferrer">
            Source on GitHub <ArrowUpRight size={14} aria-hidden="true" />
          </a>
        </div>
      </footer>
    </>
  );
}
