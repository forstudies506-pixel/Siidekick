import { parse } from "@babel/parser";
import type { File, Node } from "@babel/types";
import type { RepoFile } from "../types.js";
import { TEST_FILE, VENDOR } from "../util.js";

/**
 * Parsing for the data-flow checks. Every JS/TS file is parsed once per content (cached), with error
 * recovery so one bad line does not hide the rest of the file. Nothing is executed.
 */

export const PARSEABLE = /\.(c|m)?(j|t)sx?$/;
/** Files that are generated or vendored are not the owner's code. */
const GENERATED = /(^|\/)[^/]*\.min\.(c|m)?js$|(^|\/)[^/]*\.bundle\.js$/;
const MAX_PARSE_BYTES = 1024 * 1024;

const cache = new Map<string, File | null>();
const CACHE_MAX = 4000;

function looksMinified(content: string): boolean {
  if (content.length < 5000) return false;
  const lines = content.split("\n").length;
  return content.length / lines > 400;
}

/** True for files the analyser reads: owner source, not vendored, built, minified or test code. */
export function analysable(f: RepoFile): boolean {
  return (
    PARSEABLE.test(f.path) &&
    !VENDOR.test(f.path) &&
    !TEST_FILE.test(f.path) &&
    !GENERATED.test(f.path) &&
    f.path.split("/").every((seg) => !seg.endsWith(".d.ts")) &&
    f.content.length <= MAX_PARSE_BYTES &&
    !looksMinified(f.content)
  );
}

/** Parse a file to a Babel AST, or null when even error recovery cannot read it. */
export function parseFile(f: RepoFile): File | null {
  const key = `${f.path}\u0000${f.content.length}\u0000${f.content}`;
  const hit = cache.get(key);
  if (hit !== undefined) return hit;
  const ts = /\.(c|m)?tsx?$/.test(f.path);
  const jsx = /x$/.test(f.path) || (!ts && /<[A-Za-z][\w.]*[\s/>]/.test(f.content));
  const plugins: NonNullable<Parameters<typeof parse>[1]>["plugins"] = ["decorators-legacy", "classProperties", "topLevelAwait", "importAttributes"];
  if (ts) plugins.push("typescript");
  if (jsx) plugins.push("jsx");
  let ast: File | null = null;
  for (const sourceType of ["module", "script"] as const) {
    try {
      ast = parse(f.content, { sourceType, errorRecovery: true, allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true, plugins });
      break;
    } catch {
      ast = null;
    }
  }
  if (cache.size >= CACHE_MAX) cache.delete(cache.keys().next().value as string);
  cache.set(key, ast);
  return ast;
}

const SKIP_KEYS = new Set(["type", "start", "end", "loc", "range", "extra", "leadingComments", "trailingComments", "innerComments", "comments", "tokens"]);

/** The child nodes of a node, in source order. */
export function children(node: Node): Node[] {
  const out: Node[] = [];
  for (const key of Object.keys(node)) {
    if (SKIP_KEYS.has(key)) continue;
    const v = (node as unknown as Record<string, unknown>)[key];
    if (Array.isArray(v)) {
      for (const c of v) if (c && typeof c === "object" && typeof (c as Node).type === "string") out.push(c as Node);
    } else if (v && typeof v === "object" && typeof (v as Node).type === "string") {
      out.push(v as Node);
    }
  }
  return out;
}

export function isFunction(n: Node): boolean {
  return (
    n.type === "FunctionDeclaration" ||
    n.type === "FunctionExpression" ||
    n.type === "ArrowFunctionExpression" ||
    n.type === "ObjectMethod" ||
    n.type === "ClassMethod" ||
    n.type === "ClassPrivateMethod"
  );
}

/** Dotted text of a member chain: req.query.id, window.location.search, a["b"].c → a.b.c; null for computed parts. */
export function memberPath(n: Node | null | undefined): string | null {
  if (!n) return null;
  switch (n.type) {
    case "Identifier":
      return n.name;
    case "ThisExpression":
      return "this";
    case "MemberExpression":
    case "OptionalMemberExpression": {
      const obj = memberPath(n.object);
      if (obj === null) return null;
      if (!n.computed && n.property.type === "Identifier") return `${obj}.${n.property.name}`;
      if (n.property.type === "StringLiteral") return `${obj}.${n.property.value}`;
      if (n.computed) return `${obj}.[]`;
      if (n.property.type === "PrivateName") return `${obj}.#${n.property.id.name}`;
      return null;
    }
    case "TSNonNullExpression":
    case "TSAsExpression":
    case "TSSatisfiesExpression":
    case "ParenthesizedExpression":
      return memberPath(n.expression);
    default:
      return null;
  }
}

/** 1-based line of a node. */
export function lineOf(n: Node): number {
  return n.loc?.start.line ?? 1;
}

/** Source text of a node, cut to `max` characters on one line. */
export function snippet(content: string, n: Node, max = 120): string {
  const text = content.slice(n.start ?? 0, n.end ?? 0).replace(/\s+/g, " ").trim();
  return text.length > max ? text.slice(0, max - 1) + "…" : text;
}

/** The string value of a literal module specifier, e.g. require("fs") or import "fs". */
export function stringValue(n: Node | null | undefined): string | null {
  if (!n) return null;
  if (n.type === "StringLiteral") return n.value;
  if (n.type === "TemplateLiteral" && n.expressions.length === 0) return n.quasis[0]?.value.cooked ?? null;
  return null;
}
