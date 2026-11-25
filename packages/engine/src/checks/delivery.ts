import type { Check } from "../types.js";
import { readme } from "./readme.js";
import { ciWorkflow } from "./ci-workflow.js";
import { healthEndpoint } from "./health-endpoint.js";
import { errorHandler } from "./error-handler.js";
import { uiHeavyAnimation } from "./ui-heavy-animation.js";
import { inputValidation } from "./input-validation.js";
import { firewallRules } from "./firewall-rules.js";
import { incidentPlaybook } from "./incident-playbook.js";

/** Groups A/B/E delivery, monitoring and UI checks. Owner: kilo (WS-engine-delivery). One file per check, add it here. */
export const deliveryChecks: Check[] = [readme, ciWorkflow, healthEndpoint, errorHandler, uiHeavyAnimation, inputValidation, firewallRules, incidentPlaybook];
