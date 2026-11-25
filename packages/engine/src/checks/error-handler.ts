import type { Check, FileEdit, Finding, Patch } from "../types.js";
import { serverShape } from "../util.js";

const ERROR_HANDLER_SIG = /\(\s*err\s*,\s*req\s*,\s*res\s*,\s*next\s*\)/;
const EXPORT_OR_LISTEN = /module\.exports\s*=\s*app|app\.listen\(/;

const ERROR_HANDLER_JS = `module.exports = function errorHandler(err, req, res, next) {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong' });
};
`;

export const errorHandler: Check = {
  id: "error-handler",
  group: "B-monitoring",
  title: "Error handler",
  severity: "medium",
  mode: "auto",

  skip({ repo }) {
    return serverShape(repo.files).node ? null : "No Node.js HTTP server found. This check reads Express-style error middleware.";
  },

  detect({ repo }): Finding[] {
    if (repo.files.some((f) => ERROR_HANDLER_SIG.test(f.content))) return [];
    return [{
      checkId: "error-handler",
      title: "No error-handling middleware",
      severity: "medium",
      explanation: "Without a four-argument error handler, unhandled errors can leak details or leave requests hanging.",
    }];
  },

  fix({ repo }): Patch | null {
    if (repo.files.some((f) => ERROR_HANDLER_SIG.test(f.content))) return null;
    const target = repo.files.find((f) => EXPORT_OR_LISTEN.test(f.content));
    if (!target) return null;
    const before = target.content;
    const lines = before.split("\n");
    let insertAt = -1;
    for (let i = 0; i < lines.length; i++) {
      if (EXPORT_OR_LISTEN.test(lines[i])) { insertAt = i; break; }
    }
    if (insertAt === -1) return null;
    lines.splice(insertAt, 0, "app.use(require('./errorHandler'));");
    const after = lines.join("\n");
    const edits: FileEdit[] = [{ kind: "modify", path: target.path, before, after }];
    if (!repo.files.some((f) => f.path === "errorHandler.js")) {
      edits.unshift({ kind: "create", path: "errorHandler.js", content: ERROR_HANDLER_JS });
    }
    return {
      id: "error-handler-1",
      checkId: "error-handler",
      title: "Add error handler middleware",
      class: "additive",
      reason: "Catches unhandled errors, logs them server-side, and returns a generic 500 to the client.",
      edits,
    };
  },
};
