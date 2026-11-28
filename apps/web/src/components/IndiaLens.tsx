import type { CheckResult } from "../../../../packages/engine/src/types";
import { BHARAT_CHECKS, CERTIN_CHECKS, DPDP_CHECKS, SOURCES } from "../bharat";

/**
 * The India lens at the top of Findings: how many failing checks touch personal data (DPDP Act), whether the
 * repo is ready for CERT-In's 6-hour rule, and what the India-specific checks found. Context, not legal advice.
 */
export function IndiaLens({ results, afterFailing }: { results: CheckResult[]; afterFailing: string[] | null }) {
  const failing = results.filter((r) => !r.passed && !r.skipped);
  const dpdp = failing.filter((r) => DPDP_CHECKS.has(r.checkId));
  const dpdpAfter = afterFailing ? afterFailing.filter((id) => DPDP_CHECKS.has(id)).length : null;
  const certinOk = !failing.some((r) => CERTIN_CHECKS.has(r.checkId));
  const certinFixed = afterFailing ? !afterFailing.some((id) => CERTIN_CHECKS.has(id)) : false;
  const bharat = failing.filter((r) => BHARAT_CHECKS.has(r.checkId));
  const bharatFindings = bharat.reduce((n, r) => n + r.findings.length, 0);

  return (
    <section className="india-lens" aria-labelledby="india-lens-title">
      <h2 id="india-lens-title" className="il-title">Under Indian rules</h2>
      <div className="il-grid">
        <div className={`il-item ${dpdp.length ? "is-bad" : "is-ok"}`}>
          <p className="il-big">
            {dpdp.length}
            {dpdpAfter !== null && dpdpAfter !== dpdp.length && (
              <>
                {" "}
                → <strong>{dpdpAfter}</strong>
              </>
            )}
          </p>
          <p className="il-label">checks risk personal data (DPDP)</p>
          <div className="il-text il-more"><p>
            The DPDP Act's highest penalty, up to ₹250 crore, is for failing to keep <em>reasonable security safeguards</em> (DPDP Rules notified
            14 November 2025). Rows tagged <span className="law-tag">DPDP</span> are these.{" "}
            <a href={SOURCES.dpdp} target="_blank" rel="noreferrer">
              Source (PIB)
            </a>
          </p></div>
        </div>
        <div className={`il-item ${certinOk || certinFixed ? "is-ok" : "is-bad"}`}>
          <p className="il-big">{certinOk ? "Ready" : certinFixed ? "Fixed" : "Not ready"}</p>
          <p className="il-label">for CERT-In's 6-hour report</p>
          <div className="il-text il-more"><p>
            CERT-In's 2022 Directions require listed incidents to be reported within 6 hours, with logs kept 180 days.{" "}
            {certinOk
              ? "This repo has an incident playbook."
              : certinFixed
                ? "Your approved fixes add an incident playbook with an India reporting section."
                : "There is no incident playbook; Siidekick's fix adds one with an India reporting section."}{" "}
            <a href={SOURCES.certin} target="_blank" rel="noreferrer">
              Source (CERT-In)
            </a>
          </p></div>
        </div>
        <div className={`il-item ${bharat.length ? "is-bad" : "is-ok"}`}>
          <p className="il-big">{bharatFindings}</p>
          <p className="il-label">payment, Aadhaar or OTP problems</p>
          <div className="il-text il-more"><p>
            {bharat.length
              ? `${[...new Set(bharat.flatMap((r) => r.findings.map((f) => f.title)))].slice(0, 4).join(" · ")}.`
              : "No unverified Razorpay, Paytm or UPI payments, no Aadhaar or PAN in code or logs, no leaked OTPs."}
          </p></div>
        </div>
      </div>
      <details className="il-why">
        <summary>Why these matter</summary>
        <p className="il-note">Context to help you prioritise, not legal advice.</p>
      </details>
    </section>
  );
}
