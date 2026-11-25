import type { Check } from "../types.js";
import { secretsInRepo } from "./secrets.js";

/** Group C security checks. Owner: opencode (WS-engine-security). One file per check, add it here. */
export const securityChecks: Check[] = [secretsInRepo];
