import type { Check, Finding, Patch } from "../types.js";
import { CODE_EXT } from "../util.js";

const SKIP_PATH = /(^|\/)(test|tests|__tests__)(\/|$)|\.(test|spec)\.[jt]sx?$/;
const READS_INPUT = /\breq\.(body|query)\b/;
const VALIDATION_HELPER = /\bvalidate\(|\.parse\(|\.safeParse\(|\.validate\(|celebrate\(|checkSchema\(|\bbody\(/;
const MIDDLEWARE_PATH = "middleware/validate.js";

function isScannable(path: string): boolean {
  return CODE_EXT.test(path) && !SKIP_PATH.test(path);
}

function firstInputLine(content: string): number | undefined {
  const lines = content.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (READS_INPUT.test(lines[i])) return i + 1;
  }
  return undefined;
}

const VALIDATE_JS = `"use strict";

function isEmail(value) {
  return typeof value === "string" && /^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$/.test(value);
}

function validate(shape) {
  return function validateMiddleware(req, res, next) {
    for (const [field, type] of Object.entries(shape)) {
      const value = req.body && req.body[field];
      let ok = true;
      if (type === "string") ok = typeof value === "string";
      else if (type === "number") ok = typeof value === "number" && Number.isFinite(value);
      else if (type === "boolean") ok = typeof value === "boolean";
      else if (type === "email") ok = isEmail(value);
      if (!ok) {
        return res.status(400).json({ error: "invalid input", field });
      }
    }
    next();
  };
}

module.exports = { validate };
module.exports.validate = validate;
`;

export const inputValidation: Check = {
  id: "input-validation",
  group: "C-security",
  title: "Route reads request input without validation",
  severity: "high",
  mode: "template",

  detect({ repo }): Finding[] {
    // The helper alone protects nothing, so a route only passes once it calls validate() (or another validator).
    const findings: Finding[] = [];
    for (const f of repo.files) {
      if (!isScannable(f.path)) continue;
      if (!READS_INPUT.test(f.content)) continue;
      if (VALIDATION_HELPER.test(f.content)) continue;
      const line = firstInputLine(f.content);
      if (line === undefined) continue;
      findings.push({
        checkId: "input-validation",
        title: "Route reads request body or query without validation",
        severity: "high",
        file: f.path,
        line,
        explanation: "The route trusts raw input from the caller. Add `validate({ field: \"string\" })` middleware to each route that reads `req.body` or `req.query`, e.g. `app.post(\"/login\", validate({ email: \"email\" }), handler)`.",
      });
    }
    return findings;
  },

  fix({ repo }): Patch | null {
    if (repo.files.some((f) => f.path === MIDDLEWARE_PATH)) return null;
    let vulnerable = false;
    for (const f of repo.files) {
      if (isScannable(f.path) && READS_INPUT.test(f.content) && !VALIDATION_HELPER.test(f.content)) {
        vulnerable = true;
        break;
      }
    }
    if (!vulnerable) return null;
    return {
      id: "input-validation-1",
      checkId: "input-validation",
      title: "Add input validation middleware",
      class: "additive",
      reason: "Adds a shared validation middleware. Routes still need the owner to wire `validate({...})` into each input-reading route; Siidekick does not edit route files.",
      edits: [{ kind: "create", path: MIDDLEWARE_PATH, content: VALIDATE_JS }],
    };
  },
};
