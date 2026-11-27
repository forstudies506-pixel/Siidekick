/* eslint-disable @typescript-eslint/no-explicit-any */
import { dirname, posix } from "node:path";
import type { RepoFile, RepoSnapshot } from "../types.js";
import { analysable, children, isFunction, lineOf, memberPath, parseFile, snippet, stringValue } from "./ast.js";

/**
 * Data-flow (taint) analysis for JavaScript and TypeScript.
 *
 * It follows attacker-controlled input (request query, body, params, headers, cookies, Lambda events,
 * the browser URL) through variables, string building, destructuring and function calls, including
 * calls into other files of the repo, and reports when it reaches a dangerous call ("sink"): a shell
 * command, a SQL string, a file path, an outgoing URL and so on. Sanitisers on the way (Number(),
 * path.basename(), escapeHtml(), a schema parse …) stop the flow for the sinks they protect.
 *
 * It is a static analysis: nothing is executed. It over-approximates inside a function (order of
 * statements is ignored), resolves calls one name deep, and cannot see flows through frameworks
 * it does not model, so a clean result means "no flow found", never "no flaw".
 */

export type FlowCategory =
  | "sql"
  | "nosql"
  | "command"
  | "code"
  | "path"
  | "ssrf"
  | "redirect"
  | "xss"
  | "deserialize"
  | "prototype"
  | "regex";

type N = any;

interface Taint {
  /** Where the input came from, as written: req.query.file, event.body, location.search … */
  source: string;
  sourceFile: string;
  sourceLine: number;
  /** The value may be an object or array, not only a string (JSON bodies, qs-parsed queries). */
  objectCapable: boolean;
  /** Sinks this value has been sanitised for. */
  clean: Set<FlowCategory>;
  /** Fixed text the value starts with, when it was built as "literal" + input. */
  prefix: string;
  /** Set while summarising a function: the parameter this taint stands for. */
  param?: number;
  /** Functions the value passed through, for the evidence trail. */
  via: string[];
}

export interface Flow {
  category: FlowCategory;
  /** Where the input reaches the dangerous call. */
  file: string;
  line: number;
  sink: string;
  source: string;
  sourceFile: string;
  sourceLine: number;
  /** Functions in between, outermost first, e.g. ["runQuery (lib/db.js:4)"]. */
  via: string[];
  /** Extra words for the finding, e.g. "the whole command comes from the request". */
  detail?: string;
}

export interface FlowStats {
  filesParsed: number;
  filesFailed: number;
  functionsSummarised: number;
}

// ---------------------------------------------------------------------------------------------
// Sources

const SOURCE_PATHS: { re: RegExp; objectCapable: boolean }[] = [
  { re: /^(req|request)\.(body|query)(\.|$)/, objectCapable: true },
  { re: /^(req|request)\.(params|headers|cookies|signedCookies|files|file|hostname|url|originalUrl|path|baseUrl|subdomains)(\.|$)/, objectCapable: false },
  { re: /^ctx\.(request\.)?(body|query)(\.|$)/, objectCapable: true },
  { re: /^ctx\.(params|headers|cookies|url|path|querystring|originalUrl|href)(\.|$)/, objectCapable: false },
  { re: /^(event|evt)\.(body|queryStringParameters|multiValueQueryStringParameters|pathParameters|headers|rawPath|rawQueryString)(\.|$)/, objectCapable: false },
  { re: /^(window\.|document\.)?location\.(search|hash|href|pathname)$/, objectCapable: false },
  { re: /^document\.(URL|documentURI|referrer|cookie|baseURI)$/, objectCapable: false },
  { re: /^window\.name$/, objectCapable: false },
];

const SOURCE_CALLS: { re: RegExp; objectCapable: boolean }[] = [
  { re: /^(req|request)\.(get|header|param)$/, objectCapable: false },
  { re: /^(req|request)\.(json|formData|text)$/, objectCapable: true },
  { re: /\.searchParams\.(get|getAll)$/, objectCapable: false },
  { re: /^c\.req\.(query|queries|param|header|json|parseBody|formData|text)$/, objectCapable: true },
];

function sourceFromPath(path: string | null): { objectCapable: boolean } | null {
  if (!path) return null;
  for (const s of SOURCE_PATHS) if (s.re.test(path)) return { objectCapable: s.objectCapable };
  return null;
}

// ---------------------------------------------------------------------------------------------
// Modules and callees

interface Binding {
  module: string;
  /** "*" for the whole module object (namespace, CommonJS require, default import). */
  name: string;
}

function normModule(spec: string): { module: string; name?: string } {
  let m = spec.replace(/^node:/, "");
  if (m === "fs/promises") m = "fs";
  if (m === "timers/promises") m = "timers";
  const lodashSingle = /^lodash[./](\w+)$/.exec(m);
  if (lodashSingle) return { module: "lodash", name: lodashSingle[1] };
  if (m === "lodash-es") m = "lodash";
  return { module: m };
}

function requireSpec(n: N): string | null {
  if (n?.type === "CallExpression" && n.callee.type === "Identifier" && n.callee.name === "require" && n.arguments.length === 1) {
    return stringValue(n.arguments[0]);
  }
  if (n?.type === "AwaitExpression" && n.argument?.type === "ImportExpression") return stringValue(n.argument.source);
  if (n?.type === "AwaitExpression" && n.argument?.type === "CallExpression" && n.argument.callee.type === "Import") return stringValue(n.argument.arguments[0]);
  return null;
}

function collectImports(ast: N): Map<string, Binding> {
  const map = new Map<string, Binding>();
  const visit = (n: N) => {
    if (n.type === "ImportDeclaration") {
      const norm = normModule(n.source.value);
      for (const s of n.specifiers) {
        if (s.type === "ImportDefaultSpecifier" || s.type === "ImportNamespaceSpecifier") {
          map.set(s.local.name, { module: norm.module, name: norm.name ?? "*" });
        } else if (s.type === "ImportSpecifier") {
          const imported = s.imported.type === "Identifier" ? s.imported.name : s.imported.value;
          map.set(s.local.name, { module: norm.module, name: imported === "default" ? norm.name ?? "*" : imported });
        }
      }
    } else if (n.type === "VariableDeclarator") {
      let init = n.init;
      let member: string | null = null;
      // require('fs').promises, require('x').y
      while (init && (init.type === "MemberExpression" || init.type === "OptionalMemberExpression") && !init.computed && init.property.type === "Identifier") {
        member = member ? `${init.property.name}.${member}` : init.property.name;
        init = init.object;
      }
      const spec = requireSpec(init);
      if (spec !== null) {
        const norm = normModule(spec);
        const base = member && member !== "promises" && member !== "default" ? member : norm.name ?? "*";
        if (n.id.type === "Identifier") map.set(n.id.name, { module: norm.module, name: base });
        else if (n.id.type === "ObjectPattern") {
          for (const p of n.id.properties) {
            if (p.type !== "ObjectProperty") continue;
            const key = p.key.type === "Identifier" ? p.key.name : stringValue(p.key);
            const local = p.value.type === "Identifier" ? p.value.name : p.value.type === "AssignmentPattern" && p.value.left.type === "Identifier" ? p.value.left.name : null;
            if (key && local) map.set(local, { module: norm.module, name: base === "*" ? key : `${base}.${key}` });
          }
        }
      }
    }
    for (const c of children(n)) visit(c);
  };
  visit(ast.program);
  return map;
}

/** Canonical name of what a call invokes: "child_process.exec", "fs.readFile", "global.eval", or the raw member path. */
function calleeName(callee: N, imports: Map<string, Binding>): string | null {
  if (!callee) return null;
  if (callee.type === "Identifier") {
    const b = imports.get(callee.name);
    if (b) return b.name === "*" ? b.module : `${b.module}.${b.name}`;
    if (callee.name === "_") return "lodash";
    return `global.${callee.name}`;
  }
  if (callee.type === "MemberExpression" || callee.type === "OptionalMemberExpression") {
    // require('child_process').exec(...)
    const spec = requireSpec(callee.object);
    if (spec !== null && !callee.computed && callee.property.type === "Identifier") return `${normModule(spec).module}.${callee.property.name}`;
    const path = memberPath(callee);
    if (!path) return null;
    const [root, ...rest] = path.split(".");
    const b = imports.get(root);
    let name: string;
    if (b) name = [b.module, ...(b.name === "*" ? [] : [b.name]), ...rest].join(".");
    else if (root === "_") name = ["lodash", ...rest].join(".");
    else if (root === "window" || root === "globalThis" || root === "global") name = ["global", ...rest].join(".");
    else if (JS_GLOBALS.has(root)) name = `global.${path}`;
    else name = path;
    return name.replace(/\.promises\./, ".");
  }
  return null;
}

/** Built-in objects, so JSON.parse resolves to global.JSON.parse whatever the file imports. */
const JS_GLOBALS = new Set(["JSON", "Math", "Number", "String", "Object", "Array", "Buffer", "Promise", "Reflect", "Date", "URL", "URLSearchParams", "document", "location", "console", "process", "crypto", "Intl"]);

/** The identifier a call chain hangs from: res in res.status(500).send(x). */
function chainRoot(n: N): string | null {
  let cur = n;
  for (let i = 0; i < 20 && cur; i++) {
    if (cur.type === "Identifier") return cur.name;
    if (cur.type === "ThisExpression") return "this";
    if (cur.type === "MemberExpression" || cur.type === "OptionalMemberExpression") cur = cur.object;
    else if (cur.type === "CallExpression" || cur.type === "OptionalCallExpression") cur = cur.callee;
    else if (cur.type === "TSNonNullExpression" || cur.type === "ParenthesizedExpression") cur = cur.expression;
    else return null;
  }
  return null;
}

function methodName(callee: N): string | null {
  if ((callee?.type === "MemberExpression" || callee?.type === "OptionalMemberExpression") && !callee.computed && callee.property.type === "Identifier") {
    return callee.property.name;
  }
  return null;
}

// ---------------------------------------------------------------------------------------------
// Sanitisers

const ALL: FlowCategory[] = ["sql", "nosql", "command", "code", "path", "ssrf", "redirect", "xss", "deserialize", "prototype", "regex"];

/** Calls whose result carries no attacker text at all (numbers, booleans, dates). */
const NEUTRAL_CALLS = /^(global\.(parseInt|parseFloat|Number|Boolean|isNaN|isFinite|Date)|global\.Math\.\w+|uuid\.validate|validator\.is\w+|lodash\.(toNumber|toInteger|toSafeInteger|isEqual|size)|(global\.)?crypto\.\w+|(fs|fs-extra|graceful-fs)\.\w+|global\.Object\.keys|global\.Array\.isArray)$/;
const NEUTRAL_METHODS = new Set(["includes", "startsWith", "endsWith", "test", "indexOf", "lastIndexOf", "charCodeAt", "codePointAt", "localeCompare", "some", "every", "has", "length", "findIndex", "toFixed", "valueOf", "getTime", "compare"]);

const CLEANERS: { re: RegExp; clean: FlowCategory[] }[] = [
  { re: /^(connection|conn|pool|db|mysql|mysql2|sqlstring|SqlString|client|knex)\.(escape|escapeId|format)$|^pg-format$|(^|\.)(escapeLiteral|escapeIdentifier)$/, clean: ["sql"] },
  { re: /^(escape-html|escape-goat\.\w+|html-escaper\.escape|sanitize-html|xss|dompurify\.sanitize|isomorphic-dompurify\.sanitize)$|(^|\.)(escape|escapeHtml|escapeHTML|htmlEscape|encodeHTML|escapeXml|xss|filterXSS|sanitizeHtml|DOMPurify\.sanitize|he\.(encode|escape)|validator\.escape|lodash\.escape|entities\.encode\w*)$/, clean: ["xss"] },
  { re: /^global\.(encodeURIComponent)$/, clean: ["xss", "path", "redirect", "ssrf", "command", "sql"] },
  { re: /^global\.encodeURI$/, clean: ["xss"] },
  { re: /^(path\.basename|sanitize-filename|global\.sanitizeFilename|global\.sanitizePath)$/, clean: ["path", "command"] },
  { re: /(^|\.)(mongoSanitize|sanitize|mongo-sanitize|global\.String)$/, clean: ["nosql", "prototype"] },
  { re: /(^|\.)(escapeRegExp|escapeRegex|escapeStringRegexp|escape-string-regexp|lodash\.escapeRegExp)$/, clean: ["regex"] },
  { re: /^(shell-quote\.quote|shell-escape|shellescape|global\.shellEscape|global\.quote)$/, clean: ["command"] },
];

/** Schema validation results: typed values, so no operator objects or prototype keys get through. */
const SCHEMA_METHODS = new Set(["parse", "safeParse", "parseAsync", "safeParseAsync", "validate", "validateSync", "validateAsync", "cast", "assert"]);
const NOT_SCHEMA_RECEIVERS = /^(JSON|qs|querystring|url|path|yaml|YAML|js-yaml|Date|csv|papa|Papa|cheerio|marked|xml2js|parser|toml|ini|semver|cookie|mime|contentType|bytes|ms|dotenv)$/;

function withClean(t: Taint, cats: FlowCategory[]): Taint {
  const clean = new Set(t.clean);
  for (const c of cats) clean.add(c);
  return { ...t, clean };
}

// ---------------------------------------------------------------------------------------------
// Sinks

interface SinkHit {
  category: FlowCategory;
  taint: Taint;
  detail?: string;
}

const FS_PATH_FNS = new Set([
  "readFile", "readFileSync", "createReadStream", "writeFile", "writeFileSync", "appendFile", "appendFileSync", "createWriteStream",
  "unlink", "unlinkSync", "rm", "rmSync", "readdir", "readdirSync", "stat", "statSync", "lstat", "lstatSync", "access", "accessSync",
  "existsSync", "open", "openSync", "copyFile", "copyFileSync", "rename", "renameSync", "mkdir", "mkdirSync", "rmdir", "rmdirSync",
  "truncate", "truncateSync", "chmod", "chmodSync", "symlink", "symlinkSync", "opendir", "opendirSync", "realpath", "realpathSync", "cp", "cpSync",
]);
const FS_MODULES = new Set(["fs", "fs-extra", "graceful-fs"]);
const HTTP_CLIENTS = /^(global\.fetch|node-fetch|cross-fetch|isomorphic-fetch|undici\.(fetch|request|stream)|axios(\.(get|post|put|patch|delete|head|options|request))?|got(\.(get|post|put|patch|delete|head|stream))?|request(\.(get|post|put|patch|del|delete|head))?|superagent\.(get|post|put|patch|del|delete|head)|needle(\.(get|post|put|patch|delete|head|request))?|ky(\.(get|post|put|patch|delete|head))?|https?\.(get|request))$/;
const SQL_METHODS_ANY = new Set(["query", "execute", "raw", "whereRaw", "havingRaw", "orderByRaw", "joinRaw", "groupByRaw", "$queryRawUnsafe", "$executeRawUnsafe", "unsafe", "sql"]);
const SQL_METHODS_SHAPED = new Set(["run", "all", "get", "exec", "prepare", "each", "many", "one", "oneOrNone", "none", "any", "manyOrNone"]);
const SQL_SHAPE = /\b(SELECT\b[\s\S]*\bFROM|INSERT\s+INTO|UPDATE\b[\s\S]+\bSET|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE|CREATE\s+TABLE|WHERE\b|ORDER\s+BY|UNION\s+SELECT)\b/i;
const NOSQL_METHODS = new Set(["find", "findOne", "findOneAndUpdate", "findOneAndDelete", "findOneAndReplace", "findOneAndRemove", "updateOne", "updateMany", "deleteOne", "deleteMany", "replaceOne", "countDocuments", "count", "exists", "where", "remove", "update"]);
const PROTO_FNS = /^lodash\.(merge|mergeWith|defaultsDeep|set|setWith|zipObjectDeep)$|^(merge|deepmerge|deep-extend|defaults-deep|mixin-deep|set-value|dot-prop\.set|object-path\.set|merge-deep|deepExtend)$|^global\.(deepMerge|mergeDeep|deepExtend)$/;
const RES_ROOT = /^(res|response|resp|reply|ctx|h)$/;

function leadingLiteral(n: N): string {
  if (!n) return "";
  if (n.type === "StringLiteral") return n.value;
  if (n.type === "TemplateLiteral") return n.quasis[0]?.value.cooked ?? "";
  if (n.type === "BinaryExpression" && n.operator === "+") return leadingLiteral(n.left);
  return "";
}

/** Text of every literal piece of a built string, to test for SQL shape. */
function literalText(n: N): string {
  if (!n) return "";
  if (n.type === "StringLiteral") return n.value;
  if (n.type === "TemplateLiteral") return n.quasis.map((q: N) => q.value.cooked ?? "").join(" ");
  if (n.type === "BinaryExpression" && n.operator === "+") return `${literalText(n.left)} ${literalText(n.right)}`;
  return "";
}

const FIXED_HOST = /^[a-z][a-z0-9+.-]*:\/\/[^/?#${}]+[/?#]/i;
const SAFE_RELATIVE = /^\/[^/\\]/;

// ---------------------------------------------------------------------------------------------
// Function summaries (calls into other functions, also across files)

interface SummarySink {
  param: number;
  category: FlowCategory;
  file: string;
  line: number;
  sink: string;
  detail?: string;
  via: string[];
}

interface Summary {
  name: string;
  file: string;
  line: number;
  sinks: SummarySink[];
  /** Parameters whose taint flows into the return value. */
  returns: Set<number>;
}

// ---------------------------------------------------------------------------------------------
// Environments

class Env {
  readonly vars = new Map<string, Taint | null>();
  constructor(readonly parent?: Env) {}
  lookup(name: string): Taint | null | undefined {
    if (this.vars.has(name)) return this.vars.get(name);
    return this.parent?.lookup(name);
  }
  declare(name: string, t: Taint | null): void {
    const cur = this.vars.get(name);
    if (t || cur === undefined) this.vars.set(name, t ?? cur ?? null);
  }
  assign(name: string, t: Taint | null): void {
    if (!t) return;
    let e: Env | undefined = this;
    while (e) {
      if (e.vars.has(name)) {
        e.vars.set(name, e.vars.get(name) ?? t);
        return;
      }
      e = e.parent;
    }
    this.vars.set(name, t);
  }
}

// ---------------------------------------------------------------------------------------------
// The analyser for one file

interface FileCtx {
  file: RepoFile;
  ast: N;
  imports: Map<string, Binding>;
  /** Package majors from package.json, e.g. js-yaml → 3. */
  majors: Map<string, number>;
}

class FileAnalysis {
  private envs = new WeakMap<object, Env>();
  readonly flows: Flow[] = [];
  readonly summarySinks: SummarySink[] = [];
  readonly returns = new Set<number>();

  constructor(
    private readonly fc: FileCtx,
    private readonly summaries: (callee: N, fc: FileCtx) => Summary | null,
    /** Summarising this function: its parameters are tainted as param:i. */
    private readonly target: N | null = null,
  ) {}

  run(): void {
    const top = new Env();
    // Two passes: values assigned later in a function (loops, hoisting) are seen on the second.
    // A summary walks only its own function; the main pass walks the whole file.
    const root = this.target ?? this.fc.ast.program;
    this.visit(root, top, false);
    this.visit(root, top, true);
  }

  private envFor(node: N, parent: Env): Env {
    let e = this.envs.get(node);
    if (!e) {
      e = new Env(parent);
      this.envs.set(node, e);
    }
    return e;
  }

  private record(category: FlowCategory, node: N, taint: Taint, report: boolean, detail?: string, sink?: string): void {
    if (!report) return;
    if (taint.clean.has(category)) return;
    const sinkText = sink ?? snippet(this.fc.file.content, node);
    if (taint.param !== undefined) {
      if (this.target) this.summarySinks.push({ param: taint.param, category, file: this.fc.file.path, line: lineOf(node), sink: sinkText, detail, via: taint.via });
      return;
    }
    if (this.target) return; // real sources inside a summarised function are reported by the main pass
    this.flows.push({
      category,
      file: this.fc.file.path,
      line: lineOf(node),
      sink: sinkText,
      source: taint.source,
      sourceFile: taint.sourceFile,
      sourceLine: taint.sourceLine,
      via: taint.via,
      detail,
    });
  }

  private visit(node: N, env: Env, report: boolean): void {
    if (!node || typeof node.type !== "string") return;

    if (isFunction(node)) {
      const fenv = this.envFor(node, env);
      const isTarget = node === this.target;
      node.params.forEach((p: N, i: number) => {
        if (isTarget) {
          const t: Taint = { source: `param:${i}`, sourceFile: this.fc.file.path, sourceLine: lineOf(p), objectCapable: true, clean: new Set(), prefix: "", param: i, via: [] };
          this.bindPattern(p, t, fenv, null);
        } else {
          this.bindPattern(p, null, fenv, null);
        }
      });
      for (const c of children(node)) if (!node.params.includes(c)) this.visit(c, fenv, report);
      if (node.type === "ArrowFunctionExpression" && node.expression && isTarget) this.noteReturn(node.body, fenv);
      return;
    }

    switch (node.type) {
      case "VariableDeclarator": {
        this.visit(node.init, env, report);
        const t = node.init ? this.taintOf(node.init, env) : null;
        this.bindPattern(node.id, t, env, node.init ?? null);
        return;
      }
      case "AssignmentExpression": {
        this.visit(node.right, env, report);
        this.visit(node.left, env, report);
        const t = this.taintOf(node.right, env);
        const left = node.left;
        if (left.type === "Identifier") env.assign(left.name, t);
        else if (left.type === "ObjectPattern" || left.type === "ArrayPattern") this.bindPattern(left, t, env, node.right, true);
        else if (left.type === "MemberExpression" || left.type === "OptionalMemberExpression") {
          this.assignSink(node, t, env, report);
          const root = chainRoot(left);
          if (root && t && root !== "this" && !RES_ROOT.test(root)) env.assign(root, { ...t, objectCapable: true });
        }
        return;
      }
      case "ForOfStatement":
      case "ForInStatement": {
        this.visit(node.right, env, report);
        const t = this.taintOf(node.right, env);
        const decl = node.left.type === "VariableDeclaration" ? node.left.declarations[0]?.id : node.left;
        if (decl) this.bindPattern(decl, node.type === "ForOfStatement" ? t : t ? { ...t, objectCapable: false } : null, env, null, node.left.type !== "VariableDeclaration");
        this.visit(node.body, env, report);
        return;
      }
      case "CatchClause": {
        if (node.param) this.bindPattern(node.param, null, env, null);
        this.visit(node.body, env, report);
        return;
      }
      case "ReturnStatement": {
        this.visit(node.argument, env, report);
        if (this.target) this.noteReturn(node.argument, env);
        return;
      }
      case "CallExpression":
      case "OptionalCallExpression":
      case "NewExpression": {
        for (const c of children(node)) this.visit(c, env, report);
        this.callSink(node, env, report);
        return;
      }
      case "JSXAttribute": {
        for (const c of children(node)) this.visit(c, env, report);
        if (node.name?.name === "dangerouslySetInnerHTML" && node.value?.type === "JSXExpressionContainer") {
          const obj = node.value.expression;
          const html = obj?.type === "ObjectExpression" ? obj.properties.find((p: N) => p.type === "ObjectProperty" && (p.key.name === "__html" || p.key.value === "__html")) : null;
          const t = html ? this.taintOf(html.value, env) : null;
          if (t) this.record("xss", node, t, report, "rendered as raw HTML through dangerouslySetInnerHTML");
        }
        return;
      }
      case "ObjectProperty": {
        for (const c of children(node)) this.visit(c, env, report);
        const key = node.key?.type === "Identifier" ? node.key.name : stringValue(node.key);
        if (key === "$where") {
          const t = this.taintOf(node.value, env);
          if (t) this.record("nosql", node, t, report, "a $where clause runs JavaScript inside the database");
        }
        return;
      }
      default:
        for (const c of children(node)) this.visit(c, env, report);
    }
  }

  private noteReturn(arg: N, env: Env): void {
    const t = arg ? this.taintOf(arg, env) : null;
    if (t?.param !== undefined) this.returns.add(t.param);
  }

  /** Bind the names in a declaration pattern. `init` lets `const { query } = req` see that query is input. */
  private bindPattern(p: N, t: Taint | null, env: Env, init: N | null, assign = false): void {
    if (!p) return;
    const set = (name: string, v: Taint | null) => (assign ? env.assign(name, v) : env.declare(name, v));
    switch (p.type) {
      case "Identifier":
        set(p.name, t);
        return;
      case "AssignmentPattern":
        this.bindPattern(p.left, t ?? this.taintOf(p.right, env), env, init, assign);
        return;
      case "RestElement":
        this.bindPattern(p.argument, t, env, null, assign);
        return;
      case "ArrayPattern":
        for (const el of p.elements) if (el) this.bindPattern(el, t ? { ...t } : null, env, null, assign);
        return;
      case "ObjectPattern": {
        const base = init ? memberPath(init) : null;
        for (const prop of p.properties) {
          if (prop.type === "RestElement") {
            this.bindPattern(prop.argument, t, env, null, assign);
            continue;
          }
          const key = prop.key?.type === "Identifier" ? prop.key.name : stringValue(prop.key);
          let pt = t;
          if (!pt && base && key) {
            const src = sourceFromPath(`${base}.${key}`);
            if (src) pt = this.newTaint(`${base}.${key}`, prop, src.objectCapable);
          }
          if (prop.value?.type === "ObjectPattern" && base && key && !t) {
            // const { body: { name } } = req
            const nested = sourceFromPath(`${base}.${key}`);
            this.bindPattern(prop.value, nested ? this.newTaint(`${base}.${key}`, prop, nested.objectCapable) : null, env, null, assign);
          } else {
            this.bindPattern(prop.value, pt, env, null, assign);
          }
        }
        return;
      }
      case "TSParameterProperty":
        this.bindPattern(p.parameter, t, env, init, assign);
        return;
      default:
        return;
    }
  }

  private newTaint(source: string, node: N, objectCapable: boolean): Taint {
    return { source, sourceFile: this.fc.file.path, sourceLine: lineOf(node), objectCapable, clean: new Set(), prefix: "", via: [] };
  }

  /** The taint an expression carries, or null when it carries no attacker input. */
  taintOf(n: N, env: Env): Taint | null {
    if (!n) return null;
    switch (n.type) {
      case "Identifier": {
        const v = env.lookup(n.name);
        return v ?? null;
      }
      case "MemberExpression":
      case "OptionalMemberExpression": {
        const path = memberPath(n);
        const src = sourceFromPath(path);
        if (src) return this.newTaint(path!, n, src.objectCapable);
        if (!n.computed && n.property.type === "Identifier" && NEUTRAL_METHODS.has(n.property.name)) return null;
        const base = this.taintOf(n.object, env);
        return base ? { ...base, prefix: "" } : null;
      }
      case "CallExpression":
      case "OptionalCallExpression":
        return this.callTaint(n, env);
      case "NewExpression": {
        const name = calleeName(n.callee, this.fc.imports);
        if (name === "global.Date" || name === "global.Number" || name === "global.Boolean") return null;
        return this.unionArgs(n.arguments, env);
      }
      case "TemplateLiteral": {
        for (const e of n.expressions) {
          const t = this.taintOf(e, env);
          if (t) return { ...t, prefix: n.quasis[0]?.value.cooked ?? "" };
        }
        return null;
      }
      case "TaggedTemplateExpression": {
        const tag = memberPath(n.tag) ?? "";
        const t = this.taintOf(n.quasi, env);
        if (t && /(^|\.)(sql|SQL|Prisma\.sql|sqlTag|raw)$/.test(tag) && !/\.raw$|^raw$/.test(tag)) return withClean(t, ["sql"]);
        return t;
      }
      case "BinaryExpression": {
        if (n.operator !== "+") return null;
        const l = this.taintOf(n.left, env);
        const r = this.taintOf(n.right, env);
        const t = l ?? r;
        if (!t) return null;
        const prefix = n.left.type === "StringLiteral" ? n.left.value + (l ? "" : leadingLiteral(n.right)) : leadingLiteral(n);
        return { ...t, prefix: prefix || (l ? l.prefix : "") };
      }
      case "LogicalExpression":
        return this.taintOf(n.left, env) ?? this.taintOf(n.right, env);
      case "ConditionalExpression":
        return this.taintOf(n.consequent, env) ?? this.taintOf(n.alternate, env);
      case "ArrayExpression":
      case "ObjectExpression": {
        const parts = n.type === "ArrayExpression" ? n.elements : n.properties.map((p: N) => (p.type === "ObjectProperty" ? p.value : p.type === "SpreadElement" ? p.argument : null));
        for (const p of parts) {
          const t = p ? this.taintOf(p, env) : null;
          if (t) return { ...t, objectCapable: true, prefix: "" };
        }
        return null;
      }
      case "AwaitExpression":
      case "SpreadElement":
      case "YieldExpression":
        return this.taintOf(n.argument, env);
      case "TSAsExpression":
      case "TSSatisfiesExpression":
      case "TSNonNullExpression":
      case "TSTypeAssertion":
      case "ParenthesizedExpression":
        return this.taintOf(n.expression, env);
      case "SequenceExpression":
        return this.taintOf(n.expressions[n.expressions.length - 1], env);
      case "AssignmentExpression":
        return this.taintOf(n.right, env);
      default:
        return null;
    }
  }

  private unionArgs(args: N[], env: Env): Taint | null {
    for (const a of args) {
      const t = this.taintOf(a, env);
      if (t) return { ...t, prefix: "" };
    }
    return null;
  }

  private callTaint(n: N, env: Env): Taint | null {
    const callee = n.callee;
    const path = memberPath(callee);
    if (path) for (const s of SOURCE_CALLS) if (s.re.test(path)) return this.newTaint(`${path}()`, n, s.objectCapable);
    const name = calleeName(callee, this.fc.imports) ?? "";
    const method = methodName(callee);

    if (NEUTRAL_CALLS.test(name)) return null;
    if (method && NEUTRAL_METHODS.has(method)) return null;

    // JSON.parse turns a body string into an object an attacker shapes.
    if (name === "global.JSON.parse") {
      const t = this.taintOf(n.arguments[0], env);
      return t ? { ...t, objectCapable: true, prefix: "" } : null;
    }
    // JSON text: quotes and backslashes are escaped and it is served as JSON, so it is not HTML.
    if (name === "global.JSON.stringify") {
      const t = this.taintOf(n.arguments[0], env);
      return t ? withClean({ ...t, objectCapable: false, prefix: "" }, ["xss", "redirect"]) : null;
    }
    if (name === "global.String") {
      const t = this.taintOf(n.arguments[0], env);
      return t ? withClean({ ...t, objectCapable: false }, ["nosql", "prototype"]) : null;
    }
    for (const c of CLEANERS) {
      if (c.re.test(name) || (method && c.re.test(method))) {
        const t = this.unionArgs(n.arguments, env) ?? (callee.type === "MemberExpression" ? this.taintOf(callee.object, env) : null);
        return t ? withClean(t, c.clean) : null;
      }
    }
    if (method && SCHEMA_METHODS.has(method) && callee.type === "MemberExpression") {
      const recv = memberPath(callee.object) ?? "";
      const root = recv.split(".")[0];
      if (!NOT_SCHEMA_RECEIVERS.test(root) && !NOT_SCHEMA_RECEIVERS.test(recv)) {
        const t = this.unionArgs(n.arguments, env);
        return t ? withClean({ ...t, objectCapable: false }, ["nosql", "prototype", "deserialize"]) : null;
      }
    }
    // x.replace(/[^a-z0-9]/g, "") keeps only safe characters.
    if (method === "replace" || method === "replaceAll") {
      const re = n.arguments[0];
      if (re?.type === "RegExpLiteral" && re.pattern.startsWith("[^") && re.flags.includes("g") && !/[/.\\]/.test(re.pattern.replace(/\\[wdsWDS]/g, ""))) {
        return null;
      }
    }

    // A call into a summarised function: its return carries the argument's taint.
    const summary = this.summaries(callee, this.fc);
    if (summary) {
      for (const i of summary.returns) {
        const t = this.taintOf(n.arguments[i], env);
        if (t) return { ...t, via: [...t.via, `${summary.name} (${summary.file}:${summary.line})`] };
      }
      return null;
    }

    // String methods and anything else unknown: the result carries what went in.
    const recv = callee.type === "MemberExpression" || callee.type === "OptionalMemberExpression" ? this.taintOf(callee.object, env) : null;
    if (recv) return { ...recv, prefix: method === "concat" || method === "trim" || method === "toString" ? recv.prefix : "" };
    return this.unionArgs(n.arguments, env);
  }

  // -- sinks --------------------------------------------------------------------------------

  private assignSink(node: N, t: Taint | null, env: Env, report: boolean): void {
    const left = node.left;
    const prop = !left.computed && left.property.type === "Identifier" ? left.property.name : stringValue(left.property);
    const path = memberPath(left) ?? "";
    if (t) {
      if (prop === "innerHTML" || prop === "outerHTML" || prop === "srcdoc") this.record("xss", node, t, report, `written to ${prop}, which the browser parses as HTML`);
      if (/^(ctx|this)\.body$/.test(path) && node.right.type !== "ObjectExpression" && !/^(req|request|ctx(\.request)?)\.(body|query)$/.test(t.source)) this.record("xss", node, t, report, "sent back as the response body");
      if (/^(window\.|document\.)?location(\.href)?$/.test(path) && !SAFE_RELATIVE.test(t.prefix) && !FIXED_HOST.test(t.prefix)) {
        this.record("redirect", node, t, report, "the browser navigates to an address taken from the input");
      }
    }
    // obj[a][b] = c with all three from input: the classic prototype pollution gadget.
    if (left.computed && (left.object.type === "MemberExpression" && left.object.computed)) {
      const k1 = this.taintOf(left.object.property, env);
      const k2 = this.taintOf(left.property, env);
      if (k1 && k2 && t && !k1.clean.has("prototype")) this.record("prototype", node, k1, report, "keys from the input are used as nested property names, so __proto__ or constructor can be set");
    }
  }

  private callSink(n: N, env: Env, report: boolean): void {
    const callee = n.callee;
    const name = calleeName(callee, this.fc.imports) ?? "";
    const method = methodName(callee);
    const args: N[] = n.arguments ?? [];
    const arg = (i: number) => this.taintOf(args[i], env);
    const root = chainRoot(callee);
    const hit = (category: FlowCategory, t: Taint | null, detail?: string) => {
      if (t) this.record(category, n, t, report, detail);
    };

    // Calls into summarised functions: report the sinks their parameters reach.
    const summary = this.summaries(callee, this.fc);
    if (summary) {
      for (const s of summary.sinks) {
        const t = arg(s.param);
        if (!t || t.clean.has(s.category)) continue;
        const via = [...t.via, `${summary.name} (${summary.file}:${summary.line})`, ...s.via];
        if (t.param !== undefined) {
          if (this.target && report) this.summarySinks.push({ ...s, param: t.param, via });
        } else if (!this.target && report) {
          this.flows.push({ category: s.category, file: s.file, line: s.line, sink: s.sink, source: t.source, sourceFile: t.sourceFile, sourceLine: t.sourceLine, via, detail: s.detail });
        }
      }
    }

    // --- command injection
    if (/^(child_process\.(exec|execSync)|shelljs\.exec|execa\.command(Sync)?|execa\.execaCommand(Sync)?|global\.execSync)$/.test(name)) {
      hit("command", arg(0), "the input becomes part of a shell command");
    } else if (/^child_process\.(spawn|spawnSync|execFile|execFileSync|fork)$/.test(name) || /^execa(\.execa|\.sync)?$/.test(name)) {
      const opts = args.find((a: N) => a?.type === "ObjectExpression");
      const shell = opts?.properties.some((p: N) => p.type === "ObjectProperty" && (p.key.name === "shell" || p.key.value === "shell") && !(p.value.type === "BooleanLiteral" && !p.value.value));
      const cmd = arg(0);
      if (cmd) hit("command", cmd, "the input chooses which program runs");
      else if (shell) hit("command", arg(1), "arguments from the input run through a shell (shell: true)");
    }

    // --- code injection
    if (name === "global.eval" || name === "global.Function" || /^vm\.(runInThisContext|runInNewContext|runInContext|compileFunction|Script)$/.test(name)) {
      const t = name === "global.Function" ? this.unionArgs(args, env) : arg(0);
      hit("code", t, "the input is run as JavaScript");
    } else if ((name === "global.setTimeout" || name === "global.setInterval") && args[0] && !isFunction(args[0])) {
      const t = arg(0);
      if (t && args[0].type !== "Identifier") hit("code", t, "a string passed to setTimeout is run as JavaScript");
    } else if (name === "global.require" && args[0] && args[0].type !== "StringLiteral") {
      hit("code", arg(0), "the input decides which module is loaded and run");
    }

    // --- path traversal
    const fsName = /^([\w-]+)\.(\w+)$/.exec(name);
    if (fsName && FS_MODULES.has(fsName[1]) && FS_PATH_FNS.has(fsName[2])) {
      const t = arg(0) ?? (/^(copyFile|copyFileSync|rename|renameSync|symlink|symlinkSync|cp|cpSync)$/.test(fsName[2]) ? arg(1) : null);
      hit("path", t, "the input chooses which file on the server is read or written");
    } else if (method && root && RES_ROOT.test(root) && (method === "sendFile" || method === "download")) {
      const opts = args[1]?.type === "ObjectExpression" ? args[1] : null;
      const hasRoot = opts?.properties.some((p: N) => p.type === "ObjectProperty" && (p.key.name === "root" || p.key.value === "root"));
      if (!hasRoot) hit("path", arg(0), `res.${method} is given a path from the input without a root folder`);
    }

    // --- SSRF
    if (HTTP_CLIENTS.test(name)) {
      let t = arg(0);
      let prefix = t ? (leadingLiteral(args[0]) || t.prefix) : "";
      if (!t && args[0]?.type === "ObjectExpression") {
        const u = args[0].properties.find((p: N) => p.type === "ObjectProperty" && ["url", "uri", "host", "hostname", "baseURL"].includes(p.key.name ?? p.key.value));
        if (u) {
          t = this.taintOf(u.value, env);
          prefix = t ? leadingLiteral(u.value) || t.prefix : "";
        }
      }
      if (t && !FIXED_HOST.test(prefix)) hit("ssrf", t, "the server sends a request to an address taken from the input");
    }

    // --- open redirect
    if (method && root && RES_ROOT.test(root)) {
      if (method === "redirect" && args.length > 0) {
        const last = args[args.length - 1];
        const t = this.taintOf(last, env);
        const prefix = t ? leadingLiteral(last) || t.prefix : "";
        if (t && !SAFE_RELATIVE.test(prefix) && !FIXED_HOST.test(prefix)) hit("redirect", t, "the user is sent to an address taken from the input");
      } else if (method === "location") {
        const t = arg(0);
        if (t && !SAFE_RELATIVE.test(leadingLiteral(args[0]) || t.prefix) && !FIXED_HOST.test(leadingLiteral(args[0]) || t.prefix)) hit("redirect", t, "the Location header comes from the input");
      } else if ((method === "setHeader" || method === "header" || method === "set") && /^location$/i.test(stringValue(args[0]) ?? "")) {
        const t = arg(1);
        if (t && !SAFE_RELATIVE.test(leadingLiteral(args[1]) || t.prefix)) hit("redirect", t, "the Location header comes from the input");
      }
    }

    // --- reflected XSS
    if (method && root && /^(res|response|resp|reply)$/.test(root) && (method === "send" || method === "write" || method === "end")) {
      const t = arg(0);
      const a0 = args[0];
      const wholeObject = t !== null && /^(req|request|ctx(\.request)?)\.(body|query)$/.test(t.source) && (a0?.type === "Identifier" || a0?.type === "MemberExpression");
      if (t && !wholeObject && a0?.type !== "ObjectExpression" && a0?.type !== "ArrayExpression") hit("xss", t, `res.${method} returns the input as HTML`);
    }
    if (method === "render" && root && RES_ROOT.test(root)) hit("path", arg(0), "the input chooses which template file is rendered");
    if (/^(global\.)?document\.writeln?$/.test(name)) hit("xss", arg(0), "document.write parses the input as HTML");
    if (method === "insertAdjacentHTML") hit("xss", arg(1), "insertAdjacentHTML parses the input as HTML");
    if (method && root && /^(\$|jQuery)$/.test(root) && ["html", "append", "prepend", "after", "before", "replaceWith"].includes(method)) hit("xss", arg(0), `jQuery .${method}() parses the input as HTML`);

    // --- SQL injection (string-built queries reaching a database call)
    if (method && (SQL_METHODS_ANY.has(method) || SQL_METHODS_SHAPED.has(method)) && !/^(child_process|global\.RegExp)/.test(name) && args[0] && args[0].type !== "RegExpLiteral") {
      const recvRoot = root ?? "";
      const notDb = /^(re|regex|regexp|pattern|cache|map|headers|params|searchParams|url|res|response|req|request|app|router|axios|http|https|client\.get)$/i.test(recvRoot) || /^(axios|got|request|superagent|needle|ky|node-fetch|undici)\b/.test(name);
      const t = arg(0);
      if (t && !notDb) {
        const shaped = SQL_SHAPE.test(literalText(args[0])) || SQL_SHAPE.test(t.prefix);
        if (SQL_METHODS_ANY.has(method) || shaped) {
          const whole = args[0].type === "Identifier" || args[0].type === "MemberExpression" ? !shaped : false;
          hit("sql", t, whole ? "the query text comes from the input" : "the input is pasted into the SQL text instead of passed as a parameter");
        }
      }
    }

    // --- NoSQL operator injection
    if (method && NOSQL_METHODS.has(method) && args[0] && !isFunction(args[0])) {
      const usesMongo = [...this.fc.imports.values()].some((b) => /^(mongoose|mongodb|monk|mongoist|@typegoose\/typegoose)$/.test(b.module)) || /^[A-Z]/.test(root ?? "") || /(collection|db|model)/i.test(root ?? "");
      const t = arg(0);
      if (usesMongo && t && t.objectCapable && !t.clean.has("nosql")) {
        const viaBody = /^(req|request|ctx)\.(body|query)|^ctx\.request|json\(\)|^c\.req|JSON|event\.body/.test(t.source) || t.param !== undefined;
        if (viaBody) hit("nosql", t, "a JSON or query-string object can carry operators such as $ne or $gt into the filter");
      }
    }

    // --- unsafe deserialisation
    if (/^(node-serialize|serialize-to-js|funcster|cryo)\.(unserialize|deserialize|parse)$/.test(name)) {
      hit("deserialize", arg(0), "this deserialiser can run functions embedded in the input");
    } else if (/^js-yaml\.load$/.test(name) && (this.fc.majors.get("js-yaml") ?? 4) < 4) {
      hit("deserialize", arg(0), "js-yaml 3 load() can build JavaScript functions from the input; use safeLoad or upgrade to v4");
    }

    // --- prototype pollution
    if (PROTO_FNS.test(name)) {
      const t = /\.(set|setWith)$|^set-value$|^dot-prop\.set$|^object-path\.set$/.test(name) ? arg(1) : this.unionArgs(args.slice(1), env);
      if (t && t.objectCapable !== false) hit("prototype", t, "merging input into an object can set __proto__ and change every object in the app");
    } else if ((name === "jquery.extend" || (root && /^(\$|jQuery)$/.test(root) && method === "extend")) && args[0]?.type === "BooleanLiteral" && args[0].value) {
      hit("prototype", this.unionArgs(args.slice(2), env), "a deep $.extend of input can set __proto__");
    }

    // --- regular expression injection (ReDoS)
    if (name === "global.RegExp") hit("regex", arg(0), "the input becomes a regular expression, so one crafted pattern can hang the server");
  }
}

// ---------------------------------------------------------------------------------------------
// Repo-level driver

function packageMajors(repo: RepoSnapshot): Map<string, number> {
  const majors = new Map<string, number>();
  for (const f of repo.files) {
    if (!/(^|\/)package\.json$/.test(f.path) || /node_modules\//.test(f.path)) continue;
    try {
      const pkg = JSON.parse(f.content) as Record<string, Record<string, string> | undefined>;
      for (const sec of ["dependencies", "devDependencies"]) {
        for (const [name, spec] of Object.entries(pkg[sec] ?? {})) {
          const m = /(\d+)/.exec(String(spec));
          if (m && !majors.has(name)) majors.set(name, Number(m[1]));
        }
      }
    } catch {
      /* a broken manifest is another check's problem */
    }
  }
  return majors;
}

function resolveRelative(from: string, spec: string, files: Set<string>): string | null {
  if (!spec.startsWith(".")) return null;
  const base = posix.normalize(posix.join(dirname(from).replace(/\\/g, "/"), spec));
  const stem = base.replace(/\.(c|m)?js$/, "");
  const candidates = [base, `${base}.js`, `${base}.ts`, `${base}.mjs`, `${base}.cjs`, `${base}.jsx`, `${base}.tsx`, `${stem}.ts`, `${stem}.tsx`, `${base}/index.js`, `${base}/index.ts`];
  for (const c of candidates) if (files.has(c.replace(/^\.\//, ""))) return c.replace(/^\.\//, "");
  return null;
}

/** Named functions in a file, keyed by the name callers use (and "default" for module.exports = fn). */
function namedFunctions(ast: N): Map<string, N> {
  const out = new Map<string, N>();
  const visit = (n: N) => {
    if (!n || typeof n.type !== "string") return;
    if (n.type === "FunctionDeclaration" && n.id) out.set(n.id.name, n);
    else if (n.type === "VariableDeclarator" && n.id.type === "Identifier" && n.init && isFunction(n.init)) out.set(n.id.name, n.init);
    else if (n.type === "AssignmentExpression" && isFunction(n.right)) {
      const p = memberPath(n.left);
      if (p === "module.exports" || p === "exports.default") out.set("default", n.right);
      else if (p && /^(module\.)?exports\.\w+$/.test(p)) out.set(p.split(".").pop()!, n.right);
    } else if (n.type === "ExportDefaultDeclaration" && isFunction(n.declaration)) out.set("default", n.declaration);
    else if ((n.type === "ObjectMethod" || n.type === "ClassMethod") && n.key?.type === "Identifier" && !out.has(n.key.name)) out.set(n.key.name, n);
    else if (n.type === "ObjectProperty" && n.key?.type === "Identifier" && isFunction(n.value) && !out.has(n.key.name)) out.set(n.key.name, n.value);
    for (const c of children(n)) visit(c);
  };
  visit(ast.program);
  return out;
}

const repoCache = new WeakMap<RepoSnapshot, { flows: Flow[]; stats: FlowStats }>();

/** Every taint flow in the repo. Cached per snapshot, so all data-flow checks share one analysis. */
export function analyseRepo(repo: RepoSnapshot): { flows: Flow[]; stats: FlowStats } {
  const cached = repoCache.get(repo);
  if (cached) return cached;
  const majors = packageMajors(repo);
  const paths = new Set(repo.files.map((f) => f.path));
  const ctxs = new Map<string, FileCtx>();
  let failed = 0;
  for (const f of repo.files) {
    if (!analysable(f)) continue;
    const ast = parseFile(f);
    if (!ast) {
      failed++;
      continue;
    }
    ctxs.set(f.path, { file: f, ast, imports: collectImports(ast), majors });
  }

  const fnsByFile = new Map<string, Map<string, N>>();
  for (const [p, fc] of ctxs) fnsByFile.set(p, namedFunctions(fc.ast));
  const summaries = new Map<N, Summary>();

  const lookup = (callee: N, fc: FileCtx): Summary | null => {
    let file = fc.file.path;
    let name: string | null = null;
    if (callee?.type === "Identifier") {
      if (fnsByFile.get(file)?.has(callee.name)) name = callee.name;
      else {
        const b = fc.imports.get(callee.name);
        const target = b ? resolveRelative(file, b.module, paths) : null;
        if (target) {
          file = target;
          name = b!.name === "*" ? "default" : b!.name;
        }
      }
    } else if ((callee?.type === "MemberExpression" || callee?.type === "OptionalMemberExpression") && !callee.computed && callee.property.type === "Identifier") {
      const obj = callee.object;
      if (obj.type === "Identifier") {
        const b = fc.imports.get(obj.name);
        const target = b && b.name === "*" ? resolveRelative(file, b.module, paths) : null;
        if (target) {
          file = target;
          name = callee.property.name;
        }
      } else if (obj.type === "ThisExpression" && fnsByFile.get(file)?.has(callee.property.name)) {
        name = callee.property.name;
      }
    }
    if (!name) return null;
    const fn = fnsByFile.get(file)?.get(name);
    return fn ? summaries.get(fn) ?? null : null;
  };

  // Summaries, twice, so a wrapper of a wrapper is resolved.
  let summarised = 0;
  for (let round = 0; round < 2; round++) {
    for (const [p, fns] of fnsByFile) {
      const fc = ctxs.get(p)!;
      for (const [name, fn] of fns) {
        if (!fn.params?.length) continue;
        const a = new FileAnalysis(fc, lookup, fn);
        a.run();
        const prev = summaries.get(fn);
        if (!prev) summarised++;
        const dedup = new Map<string, SummarySink>();
        for (const s of a.summarySinks) dedup.set(`${s.param}|${s.category}|${s.file}|${s.line}`, s);
        summaries.set(fn, { name, file: p, line: lineOf(fn), sinks: [...dedup.values()], returns: a.returns });
      }
    }
  }

  const flows: Flow[] = [];
  const seen = new Set<string>();
  for (const fc of ctxs.values()) {
    const a = new FileAnalysis(fc, lookup);
    a.run();
    for (const f of a.flows) {
      const key = `${f.category}|${f.file}|${f.line}|${f.source}`;
      if (seen.has(key)) continue;
      seen.add(key);
      flows.push(f);
    }
  }
  flows.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
  const result = { flows, stats: { filesParsed: ctxs.size, filesFailed: failed, functionsSummarised: summarised } };
  repoCache.set(repo, result);
  return result;
}

export const FLOW_CATEGORIES = ALL;
