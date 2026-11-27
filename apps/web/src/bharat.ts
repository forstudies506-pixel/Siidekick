/**
 * The India lens on a scan: which failing checks touch personal data or accounts (what the DPDP Act's
 * "reasonable security safeguards" are about) and whether the repo is ready for CERT-In's 6-hour rule.
 * Facts and links come from docs/research/BHARAT.md. This is context, not legal advice: whether a club
 * or shop is a Data Fiduciary is a legal question the scan cannot answer.
 */

/** Checks whose failure can expose personal data or hand over accounts. */
export const DPDP_CHECKS = new Set([
  "secrets-in-repo",
  "auth-on-endpoints",
  "sql-string-concat",
  "nosql-injection",
  "xss",
  "path-traversal",
  "ssrf",
  "open-cors",
  "rate-limit",
  "baas-open-rules",
  "jwt-misuse",
  "client-exposed-secrets",
  "payment-verification",
  "indian-pii",
  "otp-safety",
]);

/** A written incident process is what makes a 6-hour report possible. */
export const CERTIN_CHECKS = new Set(["incident-playbook"]);

/** The India-specific checks (engine group D-domain). */
export const BHARAT_CHECKS = new Set(["payment-verification", "indian-pii", "otp-safety"]);

export const SOURCES = {
  dpdp: "https://static.pib.gov.in/WriteReadData/specificdocs/documents/2025/nov/doc20251117695301.pdf",
  certin: "https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf",
};
