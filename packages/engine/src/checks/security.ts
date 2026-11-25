import type { Check } from "../types.js";
import { secretsInRepo } from "./secrets.js";
import { securityHeaders } from "./security-headers.js";
import { rateLimitCheck } from "./rate-limit.js";
import { openCors } from "./open-cors.js";

/** Group C security checks. Owner: opencode (WS-engine-security). One file per check, add it here. */
export const securityChecks: Check[] = [secretsInRepo, securityHeaders, rateLimitCheck, openCors];
