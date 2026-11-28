import { useEffect, useRef, useState, type FormEvent, type ReactNode, type RefObject } from "react";
import { ArrowUpRight } from "lucide-react";
import { SiteHeader } from "../components/SiteHeader";
import { getChecks, type CheckInfo } from "../api/client";
import type { CheckGroup } from "../../../../packages/engine/src/types";
import "../landing.css";

const groupLabels: Record<CheckGroup, string> = {
  "A-delivery": "Delivery",
  "B-monitoring": "Monitoring",
  "C-security": "Security",
  "D-domain": "India",
  "E-states": "States",
  "F-ai": "AI-era",
  "G-enterprise": "Enterprise",
};

// Measured on the live AWS deployment, 28 Nov 2026, against the demo shop (README, docs/BUILD_SUMMARY.md).
const MEASURED = [
  { label: "Security score", before: 33, after: 62, max: 100, better: "up", unit: "/100" },
  { label: "Failing checks", before: 23, after: 12, max: 39, better: "down", unit: "" },
  { label: "Checks that can leak personal data", before: 11, after: 6, max: 39, better: "down", unit: "", note: "DPDP-relevant" },
  { label: "Live attacks that still work", before: 7, after: 1, max: 7, better: "down", unit: "" },
  { label: "Vulnerable packages", before: 8, after: 0, max: 8, better: "down", unit: "", note: "independent npm audit on AWS" },
] as const;

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
    big: "6 hours",
    text: "to report a listed incident to CERT-In. Most small teams have no playbook.",
    source: "CERT-In Directions, 2022",
    href: "https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf",
  },
];

type Diff = { minus?: string[]; plus: string[] };
const bharatFixes: Array<{ title: string; risk: string; diff: Diff }> = [
  {
    title: "UPI and Paytm callbacks",
    risk: "The app believed “TXN_SUCCESS” because the request said so.",
    diff: { minus: ['if (req.body.STATUS === "TXN_SUCCESS") markPaid(order);'], plus: ["if (verifyChecksum(req.body, PAYTM_KEY)) markPaid(order);"] },
  },
  {
    title: "Razorpay payments",
    risk: "A payment id was trusted without its signature: free orders.",
    diff: { minus: ["order.paid = true; // trusted the browser"], plus: ["order.paid = verifyRazorpaySignature(body, process.env.RAZORPAY_KEY_SECRET);"] },
  },
  {
    title: "Aadhaar and PAN in logs",
    risk: "Identity numbers written to log files anyone on the team can read.",
    diff: { minus: ['log("kyc", user.aadhaar);'], plus: ['log("kyc", mask(user.aadhaar)); // XXXX XXXX 1234'] },
  },
  {
    title: "OTP logins",
    risk: "The OTP came back in the API response, and Math.random made it guessable.",
    diff: { minus: ["const otp = Math.floor(Math.random() * 1e6);", "res.json({ sent: true, otp });"], plus: ["const otp = crypto.randomInt(100000, 1000000);", "res.json({ sent: true });"] },
  },
];

const codeFixes: Array<{ title: string; file: string; diff: Diff }> = [
  {
    title: "Secrets moved out of the repo",
    file: "server.js",
    diff: { minus: ['const KEY = "rzp_live_9xK…";'], plus: ["const KEY = process.env.RAZORPAY_KEY;", "// .env.example: RAZORPAY_KEY="] },
  },
  {
    title: "Login tokens verified, not decoded",
    file: "auth.js",
    diff: { minus: ["const user = jwt.decode(token);"], plus: ["const user = jwt.verify(token, process.env.JWT_SECRET);"] },
  },
  {
    title: "CORS limited to your site",
    file: "server.js",
    diff: { minus: ["app.use(cors());"], plus: ["app.use(cors({ origin: process.env.APP_ORIGIN }));"] },
  },
  {
    title: "TLS certificate checks back on",
    file: "client.js",
    diff: { minus: ["rejectUnauthorized: false,"], plus: ["rejectUnauthorized: true,"] },
  },
  {
    title: "An incident playbook for CERT-In",
    file: "SECURITY.md",
    diff: { plus: ["## Report (India)", "Report listed incidents to CERT-In within 6 hours.", "Keep logs for 180 days."] },
  },
];

const flow = [
  ["Scan", "Paste a GitHub repo or upload a folder. 39 checks read the code as text; nothing is run."],
  ["Explain", "Every finding in plain words, in English, Hindi or six more Indian languages."],
  ["Fix", "Small patches that only add lines. A guard refuses anything that deletes your code."],
  ["Prove", "Your original and fixed code run in a throwaway AWS build: install, your tests, an independent audit."],
  ["Ship", "Download the fixes or open a pull request that carries the evidence. You click merge."],
];

const languages = ["English", "हिन्दी", "বাংলা", "मराठी", "தமிழ்", "తెలుగు", "ગુજરાતી", "ಕನ್ನಡ"];

const still = () => typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

/** True once the element has scrolled into view (and stays true). */
function useInView<T extends Element>(threshold = 0.25) {
  const ref = useRef<T>(null);
  const [seen, setSeen] = useState(false);
  useEffect(() => {
    const el = ref.current;
    if (!el || seen) return;
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          setSeen(true);
          io.disconnect();
        }
      },
      { threshold },
    );
    io.observe(el);
    return () => io.disconnect();
  }, [seen, threshold]);
  return [ref, seen] as const;
}

/** True while the element is on screen; used to pause loops nobody can see. */
function useOnScreen<T extends Element>() {
  const ref = useRef<T>(null);
  // Starts true so the hero plays at once; the observer turns it off when scrolled away.
  const [on, setOn] = useState(true);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const io = new IntersectionObserver((entries) => setOn(entries.some((e) => e.isIntersecting)), { threshold: 0.15 });
    io.observe(el);
    return () => io.disconnect();
  }, []);
  return [ref, on] as const;
}

function CountUp({ from, to, run, ms = 1100 }: { from: number; to: number; run: boolean; ms?: number }) {
  const [v, setV] = useState(from);
  useEffect(() => {
    if (!run) return;
    if (still()) {
      setV(to);
      return;
    }
    let raf = 0;
    const t0 = performance.now();
    const tick = (now: number) => {
      const t = Math.min((now - t0) / ms, 1);
      setV(Math.round(from + (to - from) * (1 - (1 - t) ** 3)));
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [run, from, to, ms]);
  return <>{v}</>;
}

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

// ---------- the attack simulator: find, fix, prove, on a loop ----------

const ACTS = ["Find", "Fix", "Prove"] as const;
const ACT_TICKS = [7, 8, 9]; // ticks of 420 ms per act
const TICK_MS = 420;
const BOARD = 14;
const FIX_LINES = [
  'import { createHmac, timingSafeEqual } from "node:crypto";',
  'const expected = createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)',
  "  .update(`${order_id}|${razorpay_payment_id}`).digest(\"hex\");",
  "if (!timingSafeEqual(Buffer.from(expected), Buffer.from(signature)))",
  '  return res.status(400).json({ error: "Payment not verified" });',
];

function AttackSim() {
  const [ref, onScreen] = useOnScreen<HTMLDivElement>();
  const [{ act, tick }, setPos] = useState({ act: 0, tick: 0 });
  const [hold, setHold] = useState(false);
  const reduce = still();

  useEffect(() => {
    if (reduce || !onScreen || hold) return;
    const id = window.setInterval(() => {
      setPos((p) => (p.tick + 1 < ACT_TICKS[p.act] ? { act: p.act, tick: p.tick + 1 } : { act: (p.act + 1) % ACTS.length, tick: 0 }));
    }, TICK_MS);
    return () => window.clearInterval(id);
  }, [onScreen, hold, reduce]);

  const t = reduce ? 99 : tick;
  const pick = (i: number) => {
    setPos({ act: i, tick: reduce ? 0 : ACT_TICKS[i] - 1 });
    setHold(true);
    window.setTimeout(() => setHold(false), 5000);
  };
  const progress = reduce ? 1 : Math.min(1, (tick + 1) / ACT_TICKS[act]);
  const red = act === 0 ? Math.min(BOARD, Math.max(0, (t - 2) * 3)) : act === 1 ? BOARD : Math.max(0, BOARD - Math.max(0, t - 2) * 3);
  const score = act === 2 ? Math.min(62, 33 + Math.max(0, t - 2) * 5) : 33;

  return (
    <div ref={ref} className="lens lx-sim" aria-label="Simulated attack on a demo shop, then the fix">
      <div className="sim-tabs" role="tablist" aria-label="Attack, fix, proof">
        {ACTS.map((name, i) => (
          <button key={name} type="button" role="tab" aria-selected={act === i} onClick={() => pick(i)}>
            <span className="sim-n">{i + 1}</span>
            {name}
            <span className="sim-bar" style={{ transform: `scaleX(${act === i ? progress : act > i ? 1 : 0})` }} />
          </button>
        ))}
      </div>

      <div className="sim-stage">
        {/* act 1: the attack lands */}
        <section className={`sim-act ${act === 0 ? "is-on" : ""}`} aria-hidden={act !== 0}>
          <p className="sim-caption">A college-fest shop. Someone sends a forged Razorpay payment.</p>
          <pre className="sim-req">
            <span className={t >= 0 ? "ln is-in" : "ln"}>POST /api/pay/verify</span>
            <span className={t >= 1 ? "ln is-in" : "ln"}>
              {"{ "}razorpay_payment_id: <b>"pay_FAKE…"</b>, signature: <b>"forged"</b>
              {" }"}
            </span>
          </pre>
          <div className={`sim-res is-bad ${t >= 2 ? "is-in" : ""}`}>
            <span className="sim-code">200</span>
            <div>
              <strong>Fest pass issued</strong>
              <span>No money moved. The shop believed the browser.</span>
            </div>
          </div>
          <ul className={`sim-leak ${t >= 4 ? "is-in" : ""}`}>
            <li>Order marked paid</li>
            <li>₹0 received</li>
            <li>7 live attacks work on this shop</li>
          </ul>
        </section>

        {/* act 2: the fix */}
        <section className={`sim-act ${act === 1 ? "is-on" : ""}`} aria-hidden={act !== 1}>
          <p className="sim-caption">Siidekick drafts a patch that only adds lines.</p>
          <div className="sim-diff">
            <div className="sim-file">routes/pay.js</div>
            {FIX_LINES.map((l, i) => (
              <code key={l} className={`d-plus ${t >= i + 1 ? "is-in" : ""}`}>
                <span aria-hidden="true">+</span>
                {l}
              </code>
            ))}
          </div>
          <div className={`sim-chips ${t >= 6 ? "is-in" : ""}`}>
            <span className="chip-ok">Diff guard: 0 of your lines deleted</span>
            <span className="chip-ok">Rescanned</span>
          </div>
        </section>

        {/* act 3: the proof */}
        <section className={`sim-act ${act === 2 ? "is-on" : ""}`} aria-hidden={act !== 2}>
          <p className="sim-caption">The same forged request, replayed against the fixed shop on AWS.</p>
          <div className={`sim-res is-good ${t >= 1 ? "is-in" : ""}`}>
            <span className="sim-code">400</span>
            <div>
              <strong>Payment not accepted</strong>
              <span>A real, signed payment still goes through.</span>
            </div>
          </div>
          <div className="sim-proof">
            <div className="sim-gauge" aria-label={`Security score ${score} out of 100`}>
              <svg viewBox="0 0 120 120" aria-hidden="true">
                <circle cx="60" cy="60" r="50" className="g-track" />
                <circle cx="60" cy="60" r="50" className="g-fill" style={{ strokeDashoffset: 314 - (314 * score) / 100 }} />
              </svg>
              <strong>{score}</strong>
              <span>score</span>
            </div>
            <div className={`sim-verified ${t >= 6 ? "is-in" : ""}`}>
              <strong>Verified on AWS in 74 s</strong>
              <span>Your tests pass · npm audit 8 → 0</span>
            </div>
          </div>
        </section>
      </div>

      <div className="sim-board" aria-hidden="true">
        {Array.from({ length: BOARD }, (_, i) => (
          <span key={i} className={i < red ? "is-red" : act === 2 || (act === 0 && t < 2) ? "is-green" : ""} style={{ ["--i" as string]: i }} />
        ))}
        <small>{act === 2 ? "checks turning green" : act === 0 && t >= 2 ? "checks failing" : "39 checks"}</small>
      </div>
    </div>
  );
}

// ---------- measured impact as paired bars ----------

function ImpactGraphs() {
  const [ref, seen] = useInView<HTMLDivElement>(0.2);
  return (
    <div ref={ref} className={`lx-impact ${seen ? "is-seen" : ""}`}>
      {MEASURED.map((m, i) => (
        <div className="pane lx-metric" key={m.label} style={{ ["--d" as string]: `${i * 90}ms` }}>
          <p className="lx-metric-label">
            {m.label}
            {"note" in m && m.note ? <small>{m.note}</small> : null}
          </p>
          <p className="lx-metric-num">
            <span className="was">{m.before}</span>
            <span className="arrow" aria-hidden="true">
              →
            </span>
            <strong>
              <CountUp from={m.before} to={m.after} run={seen} />
            </strong>
            <span className="unit">{m.unit}</span>
          </p>
          <div className="lx-bars" aria-hidden="true">
            <span className="bar before" style={{ transform: `scaleX(${seen ? m.before / m.max : 0})` }} />
            <span className="bar after" style={{ transform: `scaleX(${seen ? Math.max(m.after / m.max, 0.004) : 0})` }} />
          </div>
        </div>
      ))}
      <div className="pane lx-metric lx-metric-wide" style={{ ["--d" as string]: `${MEASURED.length * 90}ms` }}>
        <p className="lx-metric-label">What stayed safe</p>
        <ul className="lx-keep">
          <li>
            <strong>0</strong> of the owner's lines deleted <small>(+209 added)</small>
          </li>
          <li>
            <strong>4 / 4</strong> of the shop's own tests still pass
          </li>
          <li>
            <strong>74 s</strong> from approval to verified on AWS
          </li>
        </ul>
      </div>
    </div>
  );
}

// ---------- a diff that writes itself when it scrolls into view ----------

function LiveDiff({ diff, run, file }: { diff: Diff; run: boolean; file?: string }) {
  const lines = [...(diff.minus ?? []).map((l) => ["minus", l] as const), ...diff.plus.map((l) => ["plus", l] as const)];
  return (
    <div className={`lx-diff ${run ? "is-run" : ""}`}>
      {file && <div className="lx-file">{file}</div>}
      {lines.map(([kind, l], i) => (
        <code key={`${kind}-${i}`} className={`d-${kind}`} style={{ ["--d" as string]: `${i * 160 + 200}ms` }}>
          <span aria-hidden="true">{kind === "plus" ? "+" : "−"}</span>
          {l}
        </code>
      ))}
    </div>
  );
}

function BharatCard({ fix, i }: { fix: (typeof bharatFixes)[number]; i: number }) {
  const [ref, seen] = useInView<HTMLDivElement>(0.4);
  return (
    <div ref={ref} className={`lx-bcard ${seen ? "is-seen" : ""}`} style={{ ["--d" as string]: `${i * 110}ms` }}>
      <h3>{fix.title}</h3>
      <p>{fix.risk}</p>
      <LiveDiff diff={fix.diff} run={seen} />
    </div>
  );
}

function FixCard({ fix, i }: { fix: (typeof codeFixes)[number]; i: number }) {
  const [ref, seen] = useInView<HTMLDivElement>(0.4);
  return (
    <div ref={ref} className={`pane lx-fcard ${seen ? "is-seen" : ""}`} style={{ ["--d" as string]: `${i * 90}ms` }}>
      <h3>{fix.title}</h3>
      <LiveDiff diff={fix.diff} run={seen} file={fix.file} />
    </div>
  );
}

function LanguageRoll() {
  const [ref, on] = useOnScreen<HTMLParagraphElement>();
  const [i, setI] = useState(1);
  useEffect(() => {
    if (!on || still()) return;
    const id = window.setInterval(() => setI((n) => (n + 1) % languages.length), 1400);
    return () => window.clearInterval(id);
  }, [on]);
  return (
    <p ref={ref} className="lx-langs">
      Every finding explained in
      <span className="lx-lang-slot" aria-live="off">
        {languages.map((l, n) => (
          <span key={l} className={n === i ? "is-on" : ""} lang={n === 0 ? "en" : undefined}>
            {l}
          </span>
        ))}
      </span>
    </p>
  );
}

function Reveal({ children, className = "", as = "section", ...rest }: { children: ReactNode; className?: string; as?: "section" | "div"; id?: string; "aria-labelledby"?: string }) {
  const [ref, seen] = useInView<HTMLElement>(0.15);
  const Tag = as as "section";
  return (
    <Tag ref={ref as RefObject<HTMLElement>} className={`lx-reveal ${seen ? "is-seen" : ""} ${className}`} {...rest}>
      {children}
    </Tag>
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
      <main className="landing lx">
        <section className="lx-hero" aria-labelledby="hero-title">
          <div className="lx-hero-copy">
            <h1 id="hero-title">Catch the breach before it ships.</h1>
            <p className="lx-sub">Making Cybersecurity accessible to all.</p>
            <p className="lx-pitch">
              Siidekick reads your repo, explains every risk in your language, writes the fix, and proves it on AWS before you
              merge. Built for the students, colleges and small businesses that ship without a security team.
            </p>
            <ScanForm />
            <div className="hero2-foot">
              <a href="/app?demo=1">No repo handy? Try the demo shop</a>
              <span>Read as text, never run on our server. No login.</span>
            </div>
          </div>
          <AttackSim />
        </section>

        <Reveal className="sect" aria-labelledby="impact-title">
          <div className="lx-head">
            <h2 id="impact-title">What one scan changed</h2>
            <p>Measured on the live AWS deployment against the demo shop. Nothing here is estimated.</p>
          </div>
          <ImpactGraphs />
        </Reveal>

        <Reveal className="sect lx-bharat" aria-labelledby="bharat-title">
          <div className="lens lx-bharat-lens">
            <div className="lx-head">
              <h2 id="bharat-title">Built for the bugs Indian apps actually ship</h2>
              <p>Generic scanners don't know how a UPI callback or an OTP login goes wrong. The Bharat Pack does.</p>
            </div>
            <div className="lx-bgrid">
              {bharatFixes.map((f, i) => (
                <BharatCard key={f.title} fix={f} i={i} />
              ))}
            </div>
            <div className="lx-bfoot">
              <LanguageRoll />
              <div className="lx-law">
                <span>
                  <strong>DPDP Act</strong> rows that can leak personal data are tagged
                </span>
                <span>
                  <strong>CERT-In</strong> 6-hour reporting playbook added for you
                </span>
              </div>
            </div>
          </div>
        </Reveal>

        <Reveal className="sect" aria-labelledby="stakes-title">
          <div className="lx-head">
            <h2 id="stakes-title">Why it matters in India</h2>
          </div>
          <div className="lx-facts">
            {facts.map((f, i) => (
              <div key={f.big} className="pane lx-fact" style={{ ["--d" as string]: `${i * 100}ms` }}>
                <strong>{f.big}</strong>
                <p>{f.text}</p>
                <a href={f.href} target="_blank" rel="noreferrer">
                  Source: {f.source}
                </a>
              </div>
            ))}
          </div>
        </Reveal>

        <Reveal className="sect" aria-labelledby="fixes-title">
          <div className="lx-head">
            <h2 id="fixes-title">And the everyday holes, fixed the same way</h2>
            <p>Small patches that only add lines, checked by a guard that refuses to delete your code.</p>
          </div>
          <div className="lx-fixes">
            {codeFixes.map((f, i) => (
              <FixCard key={f.title} fix={f} i={i} />
            ))}
          </div>
        </Reveal>

        <Reveal className="sect" id="how" aria-labelledby="how-title">
          <div className="lx-head">
            <h2 id="how-title">From a repo to a proven fix</h2>
          </div>
          <ol className="lx-flow">
            {flow.map(([name, body], i) => (
              <li key={name} style={{ ["--d" as string]: `${i * 90}ms` }}>
                <span className="flow-n" aria-hidden="true">
                  {i + 1}
                </span>
                <h3>{name}</h3>
                <p>{body}</p>
              </li>
            ))}
          </ol>
        </Reveal>

        <Reveal className="sect checks" id="checks" aria-labelledby="checks-title">
          <div className="lx-head">
            <h2 id="checks-title">Nothing hidden</h2>
            <p>Every check, its group and its severity, straight from the engine.</p>
          </div>
          <LiveChecks />
        </Reveal>

        <section className="lx-cta" aria-label="Start">
          <div className="lens lx-cta-lens">
            <h2>Catch yours before it ships.</h2>
            <ScanForm />
            <a href="/app?demo=1">Or watch it fix the demo shop</a>
          </div>
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
