import type { Check } from "../types.js";
import { secretsInRepo } from "./secrets.js";
import { securityHeaders } from "./security-headers.js";
import { rateLimitCheck } from "./rate-limit.js";
import { openCors } from "./open-cors.js";
import { authOnEndpoints } from "./auth-on-endpoints.js";
import { sqlStringConcat } from "./sql-string-concat.js";
import { dependencyAudit } from "./dependency-audit.js";
import { dataflowChecks } from "./dataflow.js";
import { weakCrypto, insecureConfig } from "./hardening.js";
import { dockerfileSecurity, ciSecurity, iacSecurity } from "./config-files.js";
import { pythonSecurity } from "./python.js";
import { supplyChain } from "./supply-chain.js";

/** Group C security checks. One file per check (or family), add it here. */
import { bharatChecks } from "./bharat.js";

export const securityChecks: Check[] = [
  secretsInRepo,
  securityHeaders,
  rateLimitCheck,
  openCors,
  authOnEndpoints,
  sqlStringConcat,
  dependencyAudit,
  // Data flow: request input reaching dangerous calls (analysis/taint.ts)
  ...dataflowChecks,
  // Code that is unsafe on its own
  weakCrypto,
  insecureConfig,
  pythonSecurity,
  // Files around the code: containers, CI, cloud templates, dependency sources
  dockerfileSecurity,
  ciSecurity,
  iacSecurity,
  supplyChain,
  // India-specific: payments, Aadhaar/PAN, OTP logins (checks/bharat.ts)
  ...bharatChecks,
];
