import type { Check } from "../types.js";
import { baasOpenRules } from "./baas-open-rules.js";
import { clientExposedSecrets } from "./client-exposed-secrets.js";
import { hallucinatedPackage } from "./hallucinated-package.js";
import { jwtMisuse } from "./jwt-misuse.js";

/** Group F: risks that AI-written code brings in. Owner: Claude. One file per check, add it here. */
export const aiChecks: Check[] = [hallucinatedPackage, clientExposedSecrets, baasOpenRules, jwtMisuse];
