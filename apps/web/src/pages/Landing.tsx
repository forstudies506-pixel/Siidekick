import { useEffect, useRef, useState, type FormEvent } from "react";
import { ArrowRight, ArrowUpRight } from "lucide-react";
import { SiteHeader } from "../components/SiteHeader";
import { getChecks, type CheckInfo } from "../api/client";
import type { CheckGroup } from "../../../../packages/engine/src/types";

const groupLabels: Record<CheckGroup, string> = {
  "A-delivery": "Delivery",
  "B-monitoring": "Monitoring",
  "C-security": "Security",
  "D-domain": "Domain",
  "E-states": "States",
  "F-ai": "AI-era",
  "G-enterprise": "Enterprise",
};

// The AI-era checks the engine ships (group F-ai). Ids match packages/engine.
const aiRisks = [
  {
    id: "hallucinated-package",
    where: "Repo",
    title: "A dependency that does not exist",
    body: "Code assistants invent package names. Attackers register those names and wait for the install. Every dependency is checked against the public registry.",
  },
  {
    id: "client-exposed-secrets",
    where: "Repo",
    title: "Server keys shipped to the browser",
    body: "A database or payment key behind a NEXT_PUBLIC_ or VITE_ prefix lands in the bundle anyone can download.",
  },
  {
    id: "baas-open-rules",
    where: "Repo",
    title: "Firebase or Supabase left open",
    body: "Test-mode rules let anyone with the project id read or write every row. Generated starters often never close them.",
  },
  {
    id: "jwt-misuse",
    where: "Repo",
    title: "Login tokens read but never verified",
    body: "decode() trusts whatever a token says. A forged token that claims to be an admin gets in.",
  },
];

const steps = [
  ["Scan", "Paste a GitHub repo or upload your project folder. The code is read file by file and never run on our server."],
  ["Explain", "Each failing check says what is wrong, why it matters to you, and where it is, in plain words, in your language."],
  ["Approve", "Fixes arrive as add-only patches. The diff guard refuses any that deletes or rewrites your code. Nothing lands until you approve."],
  ["Prove", "Your original and fixed code run in a throwaway AWS build: install, your own tests, an independent audit. Verified means proven."],
];

/** Dots that brighten under the pointer. Draws once, then only when the pointer moves. */
function DotField() {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const canvas = ref.current;
    const ctx = canvas?.getContext("2d");
    if (!canvas || !ctx) return;
    const still = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const gap = 26;
    let w = 0;
    let h = 0;
    let px = -9999;
    let py = -9999;
    let frame = 0;

    const draw = () => {
      frame = 0;
      ctx.clearRect(0, 0, w, h);
      for (let y = gap / 2; y < h; y += gap) {
        for (let x = gap / 2; x < w; x += gap) {
          const near = Math.max(0, 1 - Math.hypot(x - px, y - py) / 180);
          ctx.fillStyle = near > 0 ? `rgba(236,205,140,${0.12 + near * 0.7})` : "rgba(255,255,255,0.07)";
          const r = 1 + near * 1.4;
          ctx.fillRect(x - r / 2, y - r / 2, r, r);
        }
      }
    };
    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = canvas.clientWidth;
      h = canvas.clientHeight;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      draw();
    };
    const move = (e: PointerEvent) => {
      const r = canvas.getBoundingClientRect();
      px = e.clientX - r.left;
      py = e.clientY - r.top;
      if (!frame) frame = requestAnimationFrame(draw);
    };
    const leave = () => {
      px = py = -9999;
      if (!frame) frame = requestAnimationFrame(draw);
    };

    const ro = new ResizeObserver(resize);
    ro.observe(canvas);
    const host = canvas.parentElement;
    if (!still && host) {
      host.addEventListener("pointermove", move);
      host.addEventListener("pointerleave", leave);
    }
    return () => {
      ro.disconnect();
      cancelAnimationFrame(frame);
      host?.removeEventListener("pointermove", move);
      host?.removeEventListener("pointerleave", leave);
    };
  }, []);
  return <canvas ref={ref} className="dot-field" aria-hidden="true" />;
}

function ScanForm() {
  const [value, setValue] = useState("");
  function submit(e: FormEvent) {
    e.preventDefault();
    const v = value.trim();
    if (!v) return;
    window.location.assign(`/app?url=${encodeURIComponent(v)}`);
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
        placeholder="github.com/you/app"
        value={value}
        onChange={(e) => setValue(e.target.value)}
      />
      <button className="button primary" type="submit" disabled={!value.trim()}>
        Scan <ArrowRight size={18} aria-hidden="true" />
      </button>
    </form>
  );
}

type CheckList = { repo: CheckInfo[] };

function CheckColumn({ title, note, items }: { title: string; note: string; items: CheckInfo[] }) {
  return (
    <div className="check-col">
      <div className="check-col-head">
        <h3>{title}</h3>
        <span>{items.length}</span>
      </div>
      <p>{note}</p>
      <ul>
        {items.map((c) => (
          <li key={c.id}>
            <span className="check-title">{c.title}</span>
            <span className="check-group">{groupLabels[c.group]}</span>
            <span className={`severity ${c.severity}`}>{c.severity}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

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
      <CheckColumn title="In your code" note="Source, config and dependencies, read file by file." items={list.repo} />
    </div>
  );
}

export function Landing() {
  return (
    <>
      <SiteHeader />
      <main className="landing">
        <section className="hero" aria-labelledby="hero-title">
          <DotField />
          <div className="hero-inner">
            <h1 id="hero-title">
              Find the hole <br />
              before an <em>AI</em> does.
            </h1>
            <p className="hero-sub">
              Paste your GitHub repo. Siidekick reads the code the way an attacker would, explains each risk in your
              language, and hands you a fix it has proven works.
            </p>
            <ScanForm />
            <div className="hero-foot">
              <a className="text-link" href="/app?demo=1">
                No repo handy? Scan the demo shop <ArrowRight size={16} aria-hidden="true" />
              </a>
              <span>Your code is read as text, never run on our server. No login needed.</span>
            </div>
          </div>
        </section>

        <section className="ai-era" aria-labelledby="ai-title">
          <div className="section-intro">
            <h2 id="ai-title">Code an AI wrote. Attacks an AI runs.</h2>
            <p>
              Attack tooling is now point-and-click, and generated code ships the same mistakes again and again. These
              are the ones Siidekick looks for that older scanners were not built to catch.
            </p>
          </div>
          <ol className="risk-list">
            {aiRisks.map((r, i) => (
              <li key={r.id}>
                <span className="risk-num">{String(i + 1).padStart(2, "0")}</span>
                <div>
                  <h3>{r.title}</h3>
                  <p>{r.body}</p>
                </div>
                <span className="risk-where">{r.where}</span>
              </li>
            ))}
          </ol>
        </section>

        <section className="how" id="how" aria-labelledby="how-title">
          <div className="section-intro">
            <h2 id="how-title">
              We never <span className="underline">replace</span> your code.
            </h2>
            <p>Fixes only add lines. A guard checks every patch before you see it, and you decide what lands.</p>
          </div>
          <ol className="steps">
            {steps.map(([name, body], i) => (
              <li key={name}>
                <span className="step-num">{i + 1}</span>
                <h3>{name}</h3>
                <p>{body}</p>
              </li>
            ))}
          </ol>
        </section>

        <section className="checks" id="checks" aria-labelledby="checks-title">
          <div className="section-intro">
            <h2 id="checks-title">Every check, straight from the engine.</h2>
            <p>This list is read live from the scanner, so it is always what a scan actually runs.</p>
          </div>
          <LiveChecks />
        </section>
      </main>
      <footer className="site-footer">
        <p className="limit-line">Siidekick reduces risk. No tool can promise an app is unhackable, and this one does not.</p>
        <div>
          <span>Live on Vercel. AWS Lambda build in the repo.</span>
          <a href="https://github.com/forstudies506-pixel/Siidekick" target="_blank" rel="noreferrer">
            Source on GitHub <ArrowUpRight size={14} aria-hidden="true" />
          </a>
        </div>
      </footer>
    </>
  );
}
