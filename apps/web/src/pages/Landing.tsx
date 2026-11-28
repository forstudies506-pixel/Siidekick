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

const ACT_TICKS = [7, 8, 9]; // steps per act, advanced by scroll
const BOARD = 14;
const FIX_LINES = [
  'import { createHmac, timingSafeEqual } from "node:crypto";',
  'const expected = createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)',
  "  .update(`${order_id}|${razorpay_payment_id}`).digest(\"hex\");",
  "if (!timingSafeEqual(Buffer.from(expected), Buffer.from(signature)))",
  '  return res.status(400).json({ error: "Payment not verified" });',
];

const STAGES = [
  {
    kicker: "1 · Find",
    title: "The attack lands.",
    body: "A college-fest shop takes Razorpay payments. Someone forges one. The shop believes the browser and hands out a free pass.",
  },
  {
    kicker: "2 · Fix",
    title: "Siidekick writes the patch.",
    body: "It checks the payment signature with HMAC. The patch only adds lines, and a guard refuses anything that deletes your code.",
  },
  {
    kicker: "3 · Prove",
    title: "Proven on AWS before you merge.",
    body: "The fixed shop runs in a throwaway AWS build. The same forged request now fails, real payments still work, your tests still pass.",
  },
] as const;

/** One act of the simulation, drawn for a given act and tick (both driven by scroll). */
function SimVisual({ act, t }: { act: number; t: number }) {
  const score = act === 2 ? Math.min(62, 33 + Math.max(0, t - 2) * 5) : 33;
  return (
    <div className="sim-stage">
      <section className={`sim-act ${act === 0 ? "is-on" : ""}`} aria-hidden={act !== 0}>
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

      <section className={`sim-act ${act === 1 ? "is-on" : ""}`} aria-hidden={act !== 1}>
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

      <section className={`sim-act ${act === 2 ? "is-on" : ""}`} aria-hidden={act !== 2}>
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
  );
}

/**
 * The opening: the title sits centred; scrolling morphs it into a large glass pane whose story advances with the
 * scroll (find, fix, prove). One scroll listener writes a few CSS variables per frame; React only re-renders when
 * the act or step changes.
 */
function StoryHero() {
  const ref = useRef<HTMLElement>(null);
  const [pos, setPos] = useState({ act: -1, t: 0 });
  const reduce = still();

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (reduce) {
      el.style.setProperty("--m", "1");
      el.style.setProperty("--r", "1");
      setPos({ act: 2, t: 99 });
      return;
    }
    let frame = 0;
    let last = "";
    const update = () => {
      frame = 0;
      const r = el.getBoundingClientRect();
      const total = Math.max(1, r.height - window.innerHeight);
      const p = Math.min(1, Math.max(0, -r.top / total));
      const m = Math.min(1, Math.max(0, (p - 0.04) / 0.18));
      const rail = Math.min(1, Math.max(0, (p - 0.26) / 0.62));
      el.style.setProperty("--m", m.toFixed(4));
      el.style.setProperty("--r", rail.toFixed(4));
      let act = -1;
      let t = 0;
      if (p >= 0.24) {
        const span = 0.22;
        act = Math.min(2, Math.floor((p - 0.24) / span));
        const local = Math.min(1, (p - 0.24 - act * span) / (span * 0.8));
        t = Math.floor(local * ACT_TICKS[act]);
      }
      const key = `${act}:${t}`;
      if (key !== last) {
        last = key;
        setPos({ act, t });
      }
    };
    // Scroll events already arrive once per rendered frame, so update straight away: no extra frame of lag.
    const onScroll = () => update();
    update();
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onScroll);
    return () => {
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onScroll);
      cancelAnimationFrame(frame);
    };
  }, [reduce]);

  const act = Math.max(0, pos.act);
  const red = pos.act < 0 ? 0 : pos.act === 0 ? Math.min(BOARD, Math.max(0, (pos.t - 2) * 3)) : pos.act === 1 ? BOARD : Math.max(0, BOARD - Math.max(0, pos.t - 2) * 3);

  return (
    <section ref={ref} className="story" aria-labelledby="hero-title">
      <div className="story-sticky">
        <div className="story-intro">
          <h1 id="hero-title">Catch the breach before it ships.</h1>
          <p className="lx-sub">Making Cybersecurity accessible to all.</p>
          <ScanForm />
          <div className="hero2-foot">
            <a href="/app?demo=1">No repo handy? Try the demo shop</a>
            <span>Read as text, never run on our server. No login.</span>
          </div>
        </div>

        <div className="story-pane" aria-label="Simulated attack on a demo shop, then the fix">
          <ol className="sp-rail" aria-hidden="true">
            <span className="sp-line">
              <span />
            </span>
            {STAGES.map((st, i) => (
              <li key={st.kicker} className={pos.act >= i ? "is-on" : ""}>
                <span className="sp-node">{i + 1}</span>
                {st.kicker.split(" · ")[1]}
              </li>
            ))}
          </ol>
          <div className="sp-body">
            <div className="sp-copy">
              {STAGES.map((st, i) => (
                <div key={st.kicker} className={`sp-text ${act === i ? "is-on" : ""}`} aria-hidden={act !== i}>
                  <p className="sp-kicker">{st.kicker}</p>
                  <h2>{st.title}</h2>
                  <p>{st.body}</p>
                </div>
              ))}
            </div>
            <div className="sp-visual">
              <SimVisual act={act} t={pos.act < 0 ? -1 : pos.t} />
            </div>
          </div>
          <div className="sim-board" aria-hidden="true">
            {Array.from({ length: BOARD }, (_, i) => (
              <span key={i} className={i < red ? "is-red" : pos.act === 2 || (pos.act === 0 && pos.t < 2) ? "is-green" : ""} style={{ ["--i" as string]: i }} />
            ))}
            <small>{pos.act === 2 ? "checks turning green" : pos.act >= 0 && red > 0 ? "checks failing" : "39 checks"}</small>
          </div>
        </div>

        <p className="story-hint" aria-hidden="true">
          Scroll to watch an attack get caught
        </p>
      </div>
    </section>
  );
}

// ---------- bugs flow into Siidekick and come out fixed: connected lines drawn on scroll ----------

const PIPE_BUGS = [
  { name: "Forged Razorpay payment", out: "Auto-fixed" },
  { name: "UPI callback trusted", out: "Auto-fixed" },
  { name: "OTP in the API response", out: "Auto-fixed" },
  { name: "Secret key in the repo", out: "Auto-fixed" },
  { name: "Login token never verified", out: "Auto-fixed" },
  { name: "SQL built from user input", out: "Explained, you decide" },
] as const;

function Pipeline() {
  const [ref, seen] = useInView<HTMLDivElement>(0.3);
  const svg = useRef<SVGSVGElement>(null);
  const [onRef, on] = useOnScreen<HTMLDivElement>();
  useEffect(() => {
    const s = svg.current;
    if (!s) return;
    if (on && !still()) s.unpauseAnimations();
    else s.pauseAnimations();
  }, [on]);
  const ys = PIPE_BUGS.map((_, i) => 60 + i * 80);
  return (
    <div ref={onRef}>
      <div ref={ref} className={`lx-pipe ${seen ? "is-seen" : ""}`}>
        <svg ref={svg} viewBox="0 0 1200 520" role="img" aria-label="Six bugs flow into Siidekick: five come out auto-fixed, one explained for you to decide; all are verified on AWS.">
          {ys.map((y, i) => (
            <path key={`in-${i}`} id={`pipe-in-${i}`} className="pipe-line" style={{ ["--d" as string]: `${i * 120}ms` }} pathLength={1} d={`M 330 ${y} C 470 ${y}, 470 260, 560 260`} />
          ))}
          <path id="pipe-out" className="pipe-line pipe-out" style={{ ["--d" as string]: "900ms" }} pathLength={1} d="M 700 260 C 800 260, 820 260, 900 260" />
          {ys.map((_, i) => (
            <circle key={`dot-${i}`} r="4" className="pipe-dot">
              <animateMotion dur="2.6s" begin={`${i * 0.35}s`} repeatCount="indefinite">
                <mpath href={`#pipe-in-${i}`} />
              </animateMotion>
            </circle>
          ))}
          <circle r="5" className="pipe-dot is-out">
            <animateMotion dur="1.4s" repeatCount="indefinite">
              <mpath href="#pipe-out" />
            </animateMotion>
          </circle>
        </svg>
        <ul className="pipe-bugs">
          {PIPE_BUGS.map((b, i) => (
            <li key={b.name} style={{ top: `${(ys[i] / 520) * 100}%`, ["--d" as string]: `${i * 120 + 700}ms` }}>
              <span className={`pipe-state ${b.out === "Auto-fixed" ? "is-fixed" : "is-human"}`} aria-hidden="true" />
              <span>
                {b.name}
                <small>{b.out}</small>
              </span>
            </li>
          ))}
        </ul>
        <div className="pipe-core">
          <strong>Siidekick</strong>
          <span>39 checks · diff guard · rescan</span>
        </div>
        <div className="pipe-end">
          <strong>Verified on AWS</strong>
          <span>tests pass · audit clean · 74 s</span>
        </div>
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
        <StoryHero />

        <Reveal className="sect" aria-labelledby="impact-title">
          <div className="lx-head">
            <h2 id="impact-title">What one scan changed</h2>
            <p>Measured on the live AWS deployment against the demo shop. Nothing here is estimated.</p>
          </div>
          <ImpactGraphs />
        </Reveal>

        <Reveal className="sect" aria-labelledby="pipe-title">
          <div className="lx-head">
            <h2 id="pipe-title">Every bug, traced to its fix</h2>
            <p>What came out of the demo shop's scan: each problem flows through the checks and the diff guard, and leaves fixed or explained.</p>
          </div>
          <Pipeline />
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
