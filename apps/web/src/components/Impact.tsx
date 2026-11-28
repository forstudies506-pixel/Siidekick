/**
 * The Impact section: what changed, drawn from real data only. A chart renders when its data exists
 * (scan, approvals, CodeBuild run) and says what is missing otherwise; nothing is estimated.
 *
 * Encoding is the same everywhere: Before = blue, After = amber (validated for the dark surface with the
 * dataviz validator: lightness band, chroma, CVD and contrast all pass). Status red/green appears only in the
 * dependency graph, always with a text label.
 */
import { useRef, useState, type ReactNode } from "react";
import type { CheckResult, Severity } from "../../../../packages/engine/src/types";
import type { ApprovedSummary, PatchEntry, VerifyStatus } from "../api/client";

const BEFORE = "#7d8494";
const AFTER = "#5fb892";

type Report = { score: number; repo: string; results: CheckResult[] };

// ---------- shared pieces ----------

interface Tip {
  x: number;
  y: number;
  text: string;
}

/** One tooltip per chart: marks call show() on hover/focus. */
function useTip() {
  const [tip, setTip] = useState<Tip | null>(null);
  const box = useRef<HTMLDivElement>(null);
  const show = (e: React.MouseEvent | React.FocusEvent, text: string) => {
    const r = box.current?.getBoundingClientRect();
    const t = (e.target as Element).getBoundingClientRect();
    if (!r) return;
    const x = "clientX" in e && e.clientX ? e.clientX - r.left : t.left + t.width / 2 - r.left;
    const y = "clientY" in e && e.clientY ? e.clientY - r.top : t.top - r.top;
    setTip({ x, y, text });
  };
  const hide = () => setTip(null);
  const layer = tip ? (
    <div className="viz-tip" role="status" style={{ left: tip.x, top: tip.y }}>
      {tip.text}
    </div>
  ) : null;
  return { box, show, hide, layer };
}

function Legend({ items }: { items: Array<{ label: string; color: string }> }) {
  return (
    <ul className="viz-legend">
      {items.map((i) => (
        <li key={i.label}>
          <span className="viz-swatch" style={{ background: i.color }} aria-hidden="true" />
          {i.label}
        </li>
      ))}
    </ul>
  );
}

function ChartCard({
  title,
  headline,
  source,
  children,
  table,
  empty,
  wide,
  note,
}: {
  wide?: boolean;
  /** A caveat shown under the chart, e.g. why two sources disagree. */
  note?: ReactNode;
  title: string;
  headline?: ReactNode;
  source: string;
  children?: ReactNode;
  table?: { head: string[]; rows: Array<Array<string | number>> };
  empty?: string;
}) {
  if (empty) return null;
  return (
    <section className={`viz-card${wide ? " is-wide" : ""}`}>
      <div className="viz-head">
        <h3>{title}</h3>
        {headline && <p className="viz-headline">{headline}</p>}
      </div>
      {children}
      {note && <p className="viz-note">{note}</p>}
      <div className="viz-foot">
        {(
          <details className="viz-table">
            <summary>How it's measured</summary>
            <p className="viz-source">{source}</p>
            {table && (
            <table>
              <thead>
                <tr>
                  {table.head.map((h) => (
                    <th key={h} scope="col">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {table.rows.map((r, i) => (
                  <tr key={i}>
                    {r.map((c, j) => (j === 0 ? <th key={j} scope="row">{c}</th> : <td key={j}>{c}</td>))}
                  </tr>
                ))}
              </tbody>
            </table>
            )}
          </details>
        )}
      </div>
    </section>
  );
}

/** Grouped vertical bars: one group per category, Before and After side by side, 2px gap, rounded data ends. */
function PairedBars({ groups, label }: { groups: Array<{ name: string; before: number; after: number | null }>; label: string }) {
  const { box, show, hide, layer } = useTip();
  const W = 520;
  const H = 210;
  const pad = { l: 34, r: 8, t: 22, b: 30 };
  const max = Math.max(1, ...groups.flatMap((g) => [g.before, g.after ?? 0]));
  const step = max <= 5 ? 1 : max <= 10 ? 2 : Math.ceil(max / 5);
  const top = Math.ceil(max / step) * step;
  const y = (v: number) => pad.t + (H - pad.t - pad.b) * (1 - v / top);
  const gw = (W - pad.l - pad.r) / groups.length;
  const bw = Math.min(28, gw / 3);
  const ticks = Array.from({ length: top / step + 1 }, (_, i) => i * step);
  const bar = (x: number, v: number, color: string, tip: string, key: string) => {
    const h = Math.max(0, y(0) - y(v));
    const r = Math.min(4, h / 2, bw / 2);
    // Rounded at the data end only, square on the baseline.
    const d = h <= 0 ? "" : `M${x},${y(0)} V${y(v) + r} Q${x},${y(v)} ${x + r},${y(v)} H${x + bw - r} Q${x + bw},${y(v)} ${x + bw},${y(v) + r} V${y(0)} Z`;
    return (
      <g key={key}>
        {d && <path d={d} fill={color} />}
        <rect
          x={x - 3}
          y={pad.t}
          width={bw + 6}
          height={H - pad.t - pad.b}
          fill="transparent"
          tabIndex={0}
          aria-label={tip}
          onMouseMove={(e) => show(e, tip)}
          onFocus={(e) => show(e, tip)}
          onMouseLeave={hide}
          onBlur={hide}
        />
        <text x={x + bw / 2} y={y(v) - 6} textAnchor="middle" className="viz-value">
          {v}
        </text>
      </g>
    );
  };
  return (
    <div className="viz-plot" ref={box}>
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={label}>
        {ticks.map((t) => (
          <g key={t}>
            <line x1={pad.l} x2={W - pad.r} y1={y(t)} y2={y(t)} className={t === 0 ? "viz-base" : "viz-gridline"} />
            <text x={pad.l - 8} y={y(t) + 4} textAnchor="end" className="viz-axis">
              {t}
            </text>
          </g>
        ))}
        {groups.map((g, i) => {
          const cx = pad.l + gw * i + gw / 2;
          const x1 = g.after === null ? cx - bw / 2 : cx - bw - 1;
          return (
            <g key={g.name}>
              {bar(x1, g.before, BEFORE, `${g.name}, before: ${g.before}`, "b")}
              {g.after !== null && bar(cx + 1, g.after, AFTER, `${g.name}, after: ${g.after}`, "a")}
              <text x={cx} y={H - 10} textAnchor="middle" className="viz-axis">
                {g.name}
              </text>
            </g>
          );
        })}
      </svg>
      {layer}
    </div>
  );
}

// ---------- 1. score ----------

function ScoreChart({ before, after, ideal }: { before: number; after: number | null; ideal: number | null }) {
  const { box, show, hide, layer } = useTip();
  const W = 520;
  const rows = [
    { label: "Before", value: before, color: BEFORE },
    ...(after !== null ? [{ label: "With your approved fixes", value: after, color: AFTER }] : []),
  ];
  const x = (v: number) => 8 + (W - 16) * (v / 100);
  return (
    <div className="viz-plot" ref={box}>
      <svg viewBox={`0 0 ${W} ${rows.length * 46 + 26}`} role="img" aria-label={`Security score before ${before}${after !== null ? `, after ${after}` : ""} out of 100`}>
        {rows.map((r, i) => {
          const yy = 8 + i * 46;
          return (
            <g key={r.label}>
              <text x={8} y={yy + 10} className="viz-axis">
                {r.label}
              </text>
              <rect x={8} y={yy + 18} width={W - 16} height={14} rx={4} className="viz-track" />
              <rect x={8} y={yy + 18} width={Math.max(8, x(r.value) - 8)} height={14} rx={4} fill={r.color} />
              <rect
                x={8}
                y={yy + 14}
                width={W - 16}
                height={22}
                fill="transparent"
                tabIndex={0}
                aria-label={`${r.label}: ${r.value} out of 100`}
                onMouseMove={(e) => show(e, `${r.label}: ${r.value} / 100`)}
                onFocus={(e) => show(e, `${r.label}: ${r.value} / 100`)}
                onMouseLeave={hide}
                onBlur={hide}
              />
              <text x={W - 8} y={yy + 10} textAnchor="end" className="viz-value strong">
                {r.value}
              </text>
            </g>
          );
        })}
        {ideal !== null && (
          <g>
            <line x1={x(ideal)} x2={x(ideal)} y1={18} y2={rows.length * 46 + 2} className="viz-marker" />
            <text x={Math.min(x(ideal), W - 8)} y={rows.length * 46 + 18} textAnchor={x(ideal) > W - 140 ? "end" : "middle"} className="viz-axis">
              {ideal} if every guard-passed fix is approved
            </text>
          </g>
        )}
      </svg>
      {layer}
    </div>
  );
}

// ---------- 4. dependency graph ----------

interface DepNode {
  name: string;
  depth: number;
  vulnerable: boolean;
  parent?: string;
}

function DepGraph({ chains, fixed, verified }: { chains: string[][]; fixed: Set<string>; verified: boolean }) {
  const [view, setView] = useState<"before" | "after">("before");
  const { box, show, hide, layer } = useTip();
  // Merge chains into a tree keyed by path, so a package reached two ways appears where it is reached.
  const nodes = new Map<string, DepNode>();
  const vulnerable = new Set(chains.map((c) => c[c.length - 1]));
  for (const c of chains) {
    c.forEach((name, i) => {
      const key = c.slice(0, i + 1).join(">");
      if (!nodes.has(key)) nodes.set(key, { name, depth: i + 1, vulnerable: vulnerable.has(name) && i === c.length - 1, parent: i ? c.slice(0, i).join(">") : "app" });
      else if (i === c.length - 1) nodes.get(key)!.vulnerable = true;
    });
  }
  const byDepth = new Map<number, string[]>();
  for (const [k, n] of nodes) byDepth.set(n.depth, [...(byDepth.get(n.depth) ?? []), k]);
  const depthMax = Math.max(1, ...byDepth.keys());
  const rowsMax = Math.max(1, ...[...byDepth.values()].map((v) => v.length));
  const NW = 132;
  const NH = 34;
  const colGap = 56;
  const rowGap = 12;
  const W = 24 + (depthMax + 1) * (NW + colGap);
  const H = 16 + rowsMax * (NH + rowGap);
  const pos = new Map<string, { x: number; y: number }>();
  pos.set("app", { x: 12, y: H / 2 - NH / 2 });
  for (const [d, keys] of byDepth) {
    const total = keys.length * (NH + rowGap) - rowGap;
    keys.forEach((k, i) => pos.set(k, { x: 12 + d * (NW + colGap), y: H / 2 - total / 2 + i * (NH + rowGap) }));
  }
  const state = (n: DepNode): "vuln" | "clean" | "pending" | "plain" => {
    if (!n.vulnerable) return "plain";
    if (view === "before") return "vuln";
    return fixed.has(n.name) ? "clean" : "vuln";
  };
  const fixedCount = [...vulnerable].filter((v) => fixed.has(v)).length;
  return (
    <div className="viz-plot" ref={box}>
      <div className="seg viz-toggle" role="group" aria-label="Show the dependency tree">
        <button type="button" aria-pressed={view === "before"} onClick={() => setView("before")}>
          Before
        </button>
        <button type="button" aria-pressed={view === "after"} disabled={!verified} onClick={() => setView("after")} title={verified ? undefined : "Run verification to see the fixed tree"}>
          After {verified ? `(${fixedCount}/${vulnerable.size} clean)` : "(needs verification)"}
        </button>
      </div>
      <div className="viz-scroll">
        <svg viewBox={`0 0 ${W} ${H}`} width={W} height={H} role="img" aria-label={`Dependency paths to ${vulnerable.size} vulnerable packages, ${view} the fix`}>
          {[...nodes.entries()].map(([k, n]) => {
            const a = pos.get(n.parent ?? "app")!;
            const b = pos.get(k)!;
            const x1 = a.x + NW;
            const y1 = a.y + NH / 2;
            const x2 = b.x;
            const y2 = b.y + NH / 2;
            const mx = (x1 + x2) / 2;
            return <path key={`e-${k}`} d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`} className="viz-edge" />;
          })}
          <g>
            <rect x={pos.get("app")!.x} y={pos.get("app")!.y} width={NW} height={NH} rx={6} className="dep-node is-app" />
            <text x={pos.get("app")!.x + NW / 2} y={pos.get("app")!.y + NH / 2 + 4} textAnchor="middle" className="dep-label">
              your app
            </text>
          </g>
          {[...nodes.entries()].map(([k, n]) => {
            const p = pos.get(k)!;
            const s = state(n);
            const tip =
              s === "plain"
                ? `${n.name}: brings in a vulnerable package`
                : s === "vuln"
                  ? `${n.name}: vulnerable${view === "after" ? " (still reported by npm audit)" : ""}`
                  : `${n.name}: clean after the fix (npm audit)`;
            return (
              <g key={k} tabIndex={0} aria-label={tip} onMouseMove={(e) => show(e, tip)} onFocus={(e) => show(e, tip)} onMouseLeave={hide} onBlur={hide}>
                <rect x={p.x} y={p.y} width={NW} height={NH} rx={6} className={`dep-node is-${s}`} />
                <text x={p.x + 10} y={p.y + 15} className="dep-label">
                  {n.name.length > 17 ? `${n.name.slice(0, 16)}…` : n.name}
                </text>
                <text x={p.x + 10} y={p.y + 27} className={`dep-state is-${s}`}>
                  {s === "vuln" ? "✕ vulnerable" : s === "clean" ? "✓ clean" : n.depth === 1 ? "you installed this" : "pulled in"}
                </text>
              </g>
            );
          })}
        </svg>
      </div>
      {layer}
    </div>
  );
}

// ---------- 5. change footprint ----------

function Footprint({ rows }: { rows: Array<{ title: string; added: number; removed: number }> }) {
  const { box, show, hide, layer } = useTip();
  const max = Math.max(1, ...rows.map((r) => r.added + r.removed));
  return (
    <div className="viz-plot footprint" ref={box}>
      {rows.map((r) => {
        const tip = `${r.title}: +${r.added} added, −${r.removed} replaced`;
        return (
          <div key={r.title} className="fp-row" tabIndex={0} aria-label={tip} onMouseMove={(e) => show(e, tip)} onFocus={(e) => show(e, tip)} onMouseLeave={hide} onBlur={hide}>
            <span className="fp-title">{r.title}</span>
            <span className="fp-bar">
              <span className="fp-add" style={{ width: `${(r.added / max) * 100}%`, background: AFTER }} />
              {r.removed > 0 && <span className="fp-rem" style={{ width: `${Math.max(1.5, (r.removed / max) * 100)}%`, background: BEFORE }} />}
            </span>
            <span className="fp-num">
              +{r.added}
              {r.removed > 0 ? ` / −${r.removed}` : ""}
            </span>
          </div>
        );
      })}
      {layer}
    </div>
  );
}

// ---------- 6. timeline ----------

function Timeline({ segs }: { segs: Array<{ label: string; ms: number; color: string }> }) {
  const { box, show, hide, layer } = useTip();
  const total = segs.reduce((a, s) => a + s.ms, 0);
  let acc = 0;
  return (
    <div className="viz-plot" ref={box}>
      <div className="tl-bar" role="img" aria-label={segs.map((s) => `${s.label} ${(s.ms / 1000).toFixed(1)} s`).join(", ")}>
        {segs.map((s) => {
          const left = (acc / total) * 100;
          acc += s.ms;
          const tip = `${s.label}: ${(s.ms / 1000).toFixed(1)} s`;
          return (
            <span
              key={s.label}
              className="tl-seg"
              tabIndex={0}
              aria-label={tip}
              style={{ left: `${left}%`, width: `${(s.ms / total) * 100}%`, background: s.color }}
              onMouseMove={(e) => show(e, tip)}
              onFocus={(e) => show(e, tip)}
              onMouseLeave={hide}
              onBlur={hide}
            />
          );
        })}
      </div>
      <div className="tl-scale">
        <span>0 s</span>
        <span>{(total / 1000).toFixed(0)} s</span>
      </div>
      <Legend items={segs.map((s) => ({ label: `${s.label} · ${(s.ms / 1000).toFixed(1)} s`, color: s.color }))} />
      {layer}
    </div>
  );
}

// ---------- 7. build metrics ----------

function MetricPair({ label, unit, before, after, fmt }: { label: string; unit: string; before: number; after: number; fmt: (v: number) => string }) {
  const max = Math.max(before, after, 1);
  const delta = after - before;
  const pct = before ? Math.round((delta / before) * 100) : 0;
  const shown = fmt(Math.abs(delta));
  const tiny = delta !== 0 && Number(shown) === 0;
  const word =
    delta === 0
      ? "no change"
      : tiny
        ? `under ${fmt(0.1 * (unit.trim() === "s" ? 1000 : unit.trim() === "MB" ? 1024 : 1)).replace(/^0$/, "1")}${unit} ${delta > 0 ? "more" : "less"}`
        : `${delta > 0 ? "+" : "−"}${shown}${unit} (${delta > 0 ? "+" : "−"}${Math.abs(pct)}%)`;
  return (
    <div className="mp">
      <p className="mp-label">{label}</p>
      {[
        ["Before", before, BEFORE],
        ["After", after, AFTER],
      ].map(([l, v, c]) => (
        <div key={l as string} className="mp-row">
          <span className="mp-name">{l as string}</span>
          <span className="mp-track">
            <span className="mp-fill" style={{ width: `${((v as number) / max) * 100}%`, background: c as string }} />
          </span>
          <span className="mp-val">
            {fmt(v as number)}
            {unit}
          </span>
        </div>
      ))}
      <p className="mp-delta">{word}</p>
    </div>
  );
}

// ---------- the section ----------

const SEVS: Severity[] = ["critical", "high", "medium", "low"];

export interface ImpactData {
  report: Report;
  summary: ApprovedSummary | null;
  idealScore: number | null;
  approvedPatches: PatchEntry[];
  verify: VerifyStatus | null;
}

/** Numbers the impact card and the charts share, so they can never disagree. */
export function impactNumbers(d: ImpactData) {
  const failing = (r: CheckResult) => !r.passed && !r.skipped;
  const sevOf = new Map(d.report.results.map((r) => [r.checkId, r.severity]));
  const beforeSev = SEVS.map((s) => d.report.results.filter((r) => failing(r) && r.severity === s).length);
  const afterSev = d.summary ? SEVS.map((s) => d.summary!.failing.filter((id) => sevOf.get(id) === s).length) : null;
  const v = d.verify?.state === "done" ? d.verify.verdict ?? null : null;
  const res = v?.result;
  const auditBefore = res?.before.audit?.ok ? res.before.audit.counts ?? null : null;
  const auditAfter = res?.after.audit?.ok ? res.after.audit.counts ?? null : null;
  const added = d.approvedPatches.reduce((a, p) => a + p.guard.added, 0);
  const removed = d.approvedPatches.reduce((a, p) => a + p.guard.removed, 0);
  // Wall-clock of the run, never less than the step times the build measured itself (clocks can differ).
  const steps = (m?: { installMs?: number; testMs?: number; auditMs?: number }) => (m?.installMs ?? 0) + (m?.testMs ?? 0) + (m?.auditMs ?? 0);
  const timedMs = steps(res?.before.metrics) + steps(res?.after.metrics);
  const totalMs = v && d.verify ? Math.max(Date.parse(v.finishedAt) - Date.parse(d.verify.startedAt), timedMs) : null;
  return { beforeSev, afterSev, verdict: v, auditBefore, auditAfter, added, removed, totalMs };
}

export function ImpactSection(props: ImpactData & { onCard: () => void }) {
  const d = props;
  const n = impactNumbers(d);
  const after = d.summary?.score ?? null;
  const chains = (d.report.results.find((r) => r.checkId === "dependency-audit")?.findings ?? [])
    .map((f) => f.chain)
    .filter((c): c is string[] => Array.isArray(c) && c.length > 0);
  const fixed = new Set((n.verdict?.targets ?? []).filter((t) => t.fixed).map((t) => t.name));
  const res = n.verdict?.result;
  const mb = res?.before.metrics;
  const ma = res?.after.metrics;
  const auditSevs = ["critical", "high", "moderate", "low"];
  const auditTotal = (c: Record<string, number> | null) => (c ? auditSevs.reduce((a, s) => a + (c[s] ?? 0), 0) : 0);
  const depStillFailing = d.summary?.failing.includes("dependency-audit") ?? false;
  const buildCleared = !!n.auditAfter && auditTotal(n.auditAfter) === 0 && !!res?.lockfileRefreshed;
  const lockNote =
    depStillFailing && buildCleared ? (
      <>
        The rescan still counts “Dependency vulnerability audit” because it reads your current package-lock.json. The CodeBuild run installed the fix,
        refreshed the lockfile and found 0 vulnerable packages; commit that lockfile (the pull request includes it) and this check passes.
      </>
    ) : undefined;

  // Timeline segments from measured times only; the remainder is everything the build did not time itself.
  let segs: Array<{ label: string; ms: number; color: string }> = [];
  if (n.totalMs && res) {
    const part = (m: typeof mb, side: "Before" | "After", shades: [string, string, string]) =>
      [
        { label: `${side}: npm install`, ms: m?.installMs ?? 0, color: shades[0] },
        { label: `${side}: tests`, ms: m?.testMs ?? 0, color: shades[1] },
        { label: `${side}: npm audit`, ms: m?.auditMs ?? 0, color: shades[2] },
      ].filter((s) => s.ms > 0);
    const b = part(mb, "Before", [BEFORE, "#9aa0ae", "#b9bdc8"]);
    const a = part(ma, "After", [AFTER, "#82c9a9", "#a8dac2"]);
    const timed = [...b, ...a].reduce((x, s) => x + s.ms, 0);
    const rest = n.totalMs - timed;
    segs = [...(rest > 0 ? [{ label: "Queue, container start, upload & trust rule", ms: rest, color: "#4a4a52" }] : []), ...b, ...a];
  }
  const wallMs = segs.reduce((x, s) => x + s.ms, 0);

  const needsVerify = "Run the isolated verification below to measure this. Nothing here is estimated.";
  const kb = (v: number) => (v >= 1024 ? (v / 1024).toFixed(1) : String(v));
  const sec = (v: number) => (v / 1000).toFixed(1);

  return (
    <section className="impact" aria-labelledby="impact-title">
      <div className="impact-head">
        <div>
          <h2 id="impact-title">Impact</h2>
        </div>
        <div className="impact-actions">
          <Legend items={[{ label: "Before", color: BEFORE }, { label: "After", color: AFTER }]} />
          <button type="button" className="button" onClick={props.onCard}>
            Download impact card
          </button>
        </div>
      </div>

      {!res && <p className="impact-pending">Run the AWS verification above to add vulnerable packages, run time and build metrics.</p>}
      <div className="viz-grid">
        <ChartCard
          title="Security score"
          headline={
            after !== null ? (
              <>
                {d.report.score} → <strong>{after}</strong> <span className="muted">(+{after - d.report.score})</span>
              </>
            ) : undefined
          }
          source="Rescan of the repo with only your approved fixes applied."
          table={{ head: ["", "Score"], rows: [["Before", d.report.score], ...(after !== null ? [["After", after] as [string, number]] : []), ...(d.idealScore !== null ? [["All guard-passed fixes", d.idealScore] as [string, number]] : [])] }}
        >
          <ScoreChart before={d.report.score} after={after} ideal={d.idealScore} />
        </ChartCard>

        <ChartCard
          title="Failing checks by severity"
          headline={
            n.afterSev ? (
              <>
                {n.beforeSev.reduce((a, b) => a + b, 0)} → <strong>{n.afterSev.reduce((a, b) => a + b, 0)}</strong> failing checks
              </>
            ) : undefined
          }
          source="Siidekick's 36 checks, before and after your approvals."
          note={lockNote}
          table={{ head: ["Severity", "Before", "After"], rows: SEVS.map((s, i) => [s, n.beforeSev[i], n.afterSev ? n.afterSev[i] : "—"]) }}
        >
          <PairedBars label="Failing checks by severity, before and after" groups={SEVS.map((s, i) => ({ name: s, before: n.beforeSev[i], after: n.afterSev ? n.afterSev[i] : null }))} />
        </ChartCard>

        <ChartCard
          title="Vulnerable packages (npm audit)"
          headline={
            n.auditBefore && n.auditAfter ? (
              <>
                {auditTotal(n.auditBefore)} → <strong>{auditTotal(n.auditAfter)}</strong> vulnerable packages
              </>
            ) : undefined
          }
          source="Independent check run in AWS CodeBuild on both copies (npm audit, a different advisory source from the scan)."
          empty={n.auditBefore && n.auditAfter ? undefined : needsVerify}
          table={n.auditBefore && n.auditAfter ? { head: ["Severity", "Before", "After"], rows: auditSevs.map((s) => [s, n.auditBefore![s] ?? 0, n.auditAfter![s] ?? 0]) } : undefined}
        >
          {n.auditBefore && n.auditAfter && (
            <PairedBars label="npm audit vulnerable packages by severity, before and after" groups={auditSevs.map((s) => ({ name: s, before: n.auditBefore![s] ?? 0, after: n.auditAfter![s] ?? 0 }))} />
          )}
        </ChartCard>

        <ChartCard
          title="Verification run on AWS"
          headline={segs.length ? <>{n.verdict?.status === "verified" ? "Verified" : "Finished"} in {Math.round(wallMs / 1000)} s</> : undefined}
          source="Step Functions → CodeBuild → Lambda. Step times measured inside the build; the rest is queue, start-up and upload."
          empty={segs.length ? undefined : needsVerify}
          table={{ head: ["Stage", "Seconds"], rows: segs.map((s) => [s.label, sec(s.ms)]) }}
        >
          {segs.length > 0 && <Timeline segs={segs} />}
        </ChartCard>

        <ChartCard
          wide
          title="How vulnerable packages get in"
          headline={chains.length ? <>{chains.length} vulnerable packages, {chains.filter((c) => c.length > 1).length} of them pulled in by another package</> : undefined}
          source="Dependency paths rebuilt from package-lock.json; 'clean' comes from npm audit after the fix."
          empty={chains.length ? undefined : "No vulnerable dependencies were found in this repo."}
          table={chains.length ? { head: ["Package", "Path", "After the fix"], rows: chains.map((c) => [c[c.length - 1], ["your app", ...c].join(" → "), n.verdict ? (fixed.has(c[c.length - 1]) ? "clean" : "still vulnerable") : "not verified yet"]) } : undefined}
        >
          {chains.length > 0 && <DepGraph chains={chains} fixed={fixed} verified={!!n.verdict} />}
        </ChartCard>

        <ChartCard
          title="What changed in your code"
          headline={
            d.approvedPatches.length ? (
              <>
                +{n.added} / −{n.removed} lines across {d.approvedPatches.length} fixes
              </>
            ) : undefined
          }
          source="From the diff guard. Removed lines are only the ones a fix declares (a key moved to an env var, a version bump)."
          empty={d.approvedPatches.length ? undefined : "Approve fixes to see their footprint."}
          table={{ head: ["Fix", "Added", "Removed"], rows: d.approvedPatches.map((p) => [p.patch.title, p.guard.added, p.guard.removed]) }}
        >
          <Footprint rows={d.approvedPatches.map((p) => ({ title: p.patch.title, added: p.guard.added, removed: p.guard.removed }))} />
        </ChartCard>

        <ChartCard
          title="Build metrics"
          headline={mb && ma ? <>Measured on both copies in CodeBuild</> : undefined}
          source="Each value is exactly what it says. Some get bigger after a fix (newer versions can pull in more packages); that is shown, not hidden."
          empty={mb && ma && mb.packages !== undefined ? undefined : needsVerify}
          table={
            mb && ma
              ? {
                  head: ["Metric", "Before", "After"],
                  rows: [
                    ["Installed packages", mb.packages ?? "—", ma.packages ?? "—"],
                    ["node_modules size (MB)", mb.nodeModulesKb !== undefined ? kb(mb.nodeModulesKb) : "—", ma.nodeModulesKb !== undefined ? kb(ma.nodeModulesKb) : "—"],
                    ["npm install (s)", mb.installMs !== undefined ? sec(mb.installMs) : "—", ma.installMs !== undefined ? sec(ma.installMs) : "—"],
                    ["Test run (s)", mb.testMs !== undefined ? sec(mb.testMs) : "—", ma.testMs !== undefined ? sec(ma.testMs) : "—"],
                  ],
                }
              : undefined
          }
        >
          {mb && ma && (
            <div className="mp-grid">
              {mb.packages !== undefined && ma.packages !== undefined && <MetricPair label="Installed packages" unit="" before={mb.packages} after={ma.packages} fmt={(v) => String(v)} />}
              {mb.nodeModulesKb !== undefined && ma.nodeModulesKb !== undefined && (
                <MetricPair label="node_modules size" unit=" MB" before={mb.nodeModulesKb} after={ma.nodeModulesKb} fmt={(v) => (v / 1024).toFixed(1)} />
              )}
              {mb.installMs !== undefined && ma.installMs !== undefined && <MetricPair label="npm install time" unit=" s" before={mb.installMs} after={ma.installMs} fmt={sec} />}
              {mb.testMs !== undefined && ma.testMs !== undefined && <MetricPair label="Test run time" unit=" s" before={mb.testMs} after={ma.testMs} fmt={sec} />}
            </div>
          )}
        </ChartCard>
      </div>
    </section>
  );
}

// ---------- 8. impact card ----------

/** Draws a 1200×630 PNG with the shared numbers. Only figures that exist are drawn. */
export async function downloadImpactCard(d: ImpactData): Promise<void> {
  const n = impactNumbers(d);
  const after = d.summary?.score ?? null;
  await document.fonts?.ready;
  const c = document.createElement("canvas");
  c.width = 1200;
  c.height = 630;
  const g = c.getContext("2d")!;
  const font = (w: number, s: number, mono = false) => `${w} ${s}px ${mono ? '"JetBrains Mono", monospace' : '"Schibsted Grotesk", Arial, sans-serif'}`;
  g.fillStyle = "#09090a";
  g.fillRect(0, 0, 1200, 630);
  g.fillStyle = "#111113";
  g.fillRect(40, 40, 1120, 550);
  g.strokeStyle = "#ffffff26";
  g.strokeRect(40.5, 40.5, 1119, 549);

  g.fillStyle = "#f5f5f4";
  g.font = font(700, 30);
  g.fillText("Siide", 80, 104);
  const w = g.measureText("Siide").width;
  g.fillStyle = "#eccd8c";
  g.fillText("kick", 80 + w, 104);
  g.fillStyle = "#8e8e96";
  g.font = font(500, 22, true);
  g.fillText(d.report.repo.length > 48 ? `${d.report.repo.slice(0, 47)}…` : d.report.repo, 80, 144);

  g.fillStyle = "#8e8e96";
  g.font = font(500, 20);
  g.fillText("SECURITY SCORE", 80, 222);
  g.font = font(700, 120);
  g.fillStyle = BEFORE;
  g.fillText(String(d.report.score), 80, 344);
  let x = 80 + g.measureText(String(d.report.score)).width + 24;
  if (after !== null) {
    g.fillStyle = "#8e8e96";
    g.font = font(500, 64);
    g.fillText("→", x, 330);
    x += g.measureText("→").width + 24;
    g.fillStyle = AFTER;
    g.font = font(700, 120);
    g.fillText(String(after), x, 344);
  }

  const stats: Array<[string, string]> = [];
  if (n.auditBefore && n.auditAfter) {
    const t = (c2: Record<string, number>) => ["critical", "high", "moderate", "low"].reduce((a, s) => a + (c2[s] ?? 0), 0);
    stats.push([`${t(n.auditBefore)} → ${t(n.auditAfter)}`, "vulnerable packages"]);
  }
  if (d.approvedPatches.length) stats.push([String(d.approvedPatches.length), "fixes approved"]);
  if (d.approvedPatches.length) stats.push([`+${n.added} / −${n.removed}`, "lines changed"]);
  if (n.verdict && n.totalMs) stats.push([`${Math.round(n.totalMs / 1000)} s`, n.verdict.status === "verified" ? "verified on AWS" : `AWS run: ${n.verdict.status}`]);
  stats.slice(0, 4).forEach(([big, small], i) => {
    const sx = 80 + i * 262;
    g.fillStyle = "#f5f5f4";
    g.font = font(700, 38);
    g.fillText(big, sx, 450);
    g.fillStyle = "#8e8e96";
    g.font = font(500, 20);
    g.fillText(small, sx, 482);
  });

  g.fillStyle = "#8e8e96";
  g.font = font(500, 18);
  g.fillText("Schrödinger's Code · a part of Echelon Systems Architecture", 80, 552);
  g.textAlign = "right";
  const now = new Date();
  g.fillText(`${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}`, 1120, 552);

  const blob: Blob | null = await new Promise((r) => c.toBlob(r, "image/png"));
  if (!blob) return;
  const href = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = href;
  a.download = `siidekick-impact-${d.report.repo.replace(/[^\w.-]+/g, "-")}.png`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(href), 1000);
}
