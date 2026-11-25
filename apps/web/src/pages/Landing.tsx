import { ArrowRight, GitBranch } from "lucide-react";
import { SiteHeader } from "../components/SiteHeader";

const checks = [
  ["A", "Delivery", "Secrets", "high"],
  ["A", "Delivery", "Dependency audit", "low"],
  ["B", "Monitoring", "Health / readiness", "medium"],
  ["C", "Security", "SQL concatenation", "high"],
  ["C", "Security", "Security headers", "medium"],
  ["C", "Security", "Open CORS", "medium"],
  ["C", "Security", "Auth on endpoints", "high"],
  ["C", "Security", "Rate limiting", "medium"],
  ["D", "Domain", "Data validation", "medium"],
  ["E", "States", "Heavy UI animation", "low"],
  ["F", "AI", "AI boundary", "medium"],
  ["G", "Enterprise", "Audit trail", "low"],
] as const;

export function Landing() {
  return (
    <>
      <SiteHeader />
      <main>
        <section className="hero">
          <div className="hero-copy">
            <p className="eyebrow">Repository risk review</p>
            <h1>
              We <span className="underlined">never</span> replace your code.
            </h1>
            <p className="hero-sub">
              Siidekick scans a small website repo, explains each risk plainly,
              and proposes patches only your team can approve.
            </p>
            <div className="hero-actions">
              <a className="button primary" href="/app?demo=1">
                Scan the demo shop <ArrowRight size={18} aria-hidden="true" />
              </a>
              <a className="button secondary" href="/app">
                Upload a repo
              </a>
            </div>
          </div>

          <div className="diff-card" aria-label="Example guarded diff">
            <div className="diff-head">
              <span><GitBranch size={15} aria-hidden="true" /> src/app.js</span>
              <span className="diff-status">review</span>
            </div>
            <div className="diff-line add">
              <span>+</span>
              <code>require('./security')(app);</code>
            </div>
            <div className="diff-line del">
              <span>−</span>
              <code>- app.get('/admin/users', …)</code>
            </div>
            <div className="guard-stamp">BLOCKED BY DIFF GUARD</div>
          </div>
        </section>

        <section className="process" id="how" aria-labelledby="process-title">
          <h2 id="process-title">How it works</h2>
          <ol className="process-strip">
            {["Scan", "Explain", "Patch", "Guard", "You approve", "Rescan"].map(
              (label, index) => (
                <li key={label}>
                  <span>{String(index + 1).padStart(2, "0")}</span>
                  <strong>{label}</strong>
                </li>
              ),
            )}
          </ol>
        </section>

        <section className="checks" aria-labelledby="checks-title">
          <div className="section-heading">
            <p className="eyebrow">Coverage</p>
            <h2 id="checks-title">What it checks</h2>
          </div>
          <div className="checks-table" role="table" aria-label="Twelve checks">
            {checks.map(([group, category, title, severity]) => (
              <div className="check-row" role="row" key={title}>
                <span className="group-chip" role="cell">{group}</span>
                <span role="cell">{category}</span>
                <strong role="cell">{title}</strong>
                <span className={`severity ${severity}`} role="cell">{severity}</span>
              </div>
            ))}
          </div>
        </section>

        <section className="audience" aria-labelledby="audience-title">
          <p className="eyebrow">Built for small teams</p>
          <h2 id="audience-title">Who it's for</h2>
          <p>
            Indian student founders, college clubs and fest sites, small shops,
            and NGOs: anyone who needs a useful first review before a real
            security professional takes a deeper look.
          </p>
          <p className="limit-line">
            Siidekick reduces avoidable risk. It does not certify or guarantee security.
          </p>
        </section>
      </main>
      <footer>
        <div>
          <strong>Built on AWS</strong>
          <span>Lambda · API Gateway · DynamoDB · S3 · CloudFront</span>
        </div>
        <a href="https://github.com/forstudies506-pixel/Siidekick">
          GitHub ↗
        </a>
      </footer>
    </>
  );
}
