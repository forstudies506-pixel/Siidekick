import { ArrowRight, GitBranch } from "lucide-react";
import { SiteHeader } from "../components/SiteHeader";

// Mirrors packages/engine/src/registry.ts (group, title, severity). Keep the two in step.
const checks = [
  ["A", "Delivery", "README", "low"],
  ["A", "Delivery", "CI workflow", "medium"],
  ["B", "Monitoring", "Health endpoint", "low"],
  ["B", "Monitoring", "Error handler", "medium"],
  ["B", "Monitoring", "Incident playbook", "low"],
  ["C", "Security", "Secrets in the repo", "critical"],
  ["C", "Security", "Auth on admin routes", "critical"],
  ["C", "Security", "String-built SQL", "critical"],
  ["C", "Security", "Security headers", "high"],
  ["C", "Security", "Rate limit on login", "high"],
  ["C", "Security", "Dependency audit (OSV)", "high"],
  ["C", "Security", "Input validation", "high"],
  ["C", "Security", "Open CORS", "medium"],
  ["C", "Security", "Firewall rules", "medium"],
  ["E", "States", "Heavy UI animation", "low"],
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
                Paste a GitHub repo
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
              <code>app.get('/admin/users', …)</code>
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
          <div className="checks-table" role="table" aria-label="15 checks">
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
