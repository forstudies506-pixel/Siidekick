/** "sk_live_abcdef123456" -> "sk_l…3456 (20 chars)". Never log a full secret. */
export function redact(secret: string): string {
  if (secret.length <= 8) return `${"*".repeat(secret.length)} (${secret.length} chars)`;
  return `${secret.slice(0, 4)}…${secret.slice(-4)} (${secret.length} chars)`;
}

/** 1-based line number of a character offset. */
export function lineAt(content: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset && i < content.length; i++) if (content.charCodeAt(i) === 10) line++;
  return line;
}

export const CODE_EXT = /\.(c|m)?(j|t)sx?$/;
/** Prose files: a README that mentions helmet or ufw is not the protection itself. */
export const DOC_EXT = /\.(md|mdx|markdown|txt|rst|adoc)$/i;

/** Split the arguments of the call whose '(' sits just before `from`; stops at its closing ')'. */
export function callArgs(content: string, from: number): string[] {
  const args: string[] = [];
  let buf = "";
  let depth = 0;
  let quote: string | null = null;
  let esc = false;
  for (let i = from; i < content.length; i++) {
    const ch = content[i];
    if (quote !== null) {
      buf += ch;
      if (esc) esc = false;
      else if (ch === "\\") esc = true;
      else if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === "`") {
      quote = ch;
      buf += ch;
      continue;
    }
    if (ch === "(" || ch === "[" || ch === "{") {
      depth++;
      buf += ch;
      continue;
    }
    if (ch === ")" || ch === "]" || ch === "}") {
      if (depth === 0 && ch === ")") {
        args.push(buf);
        return args;
      }
      if (depth > 0) depth--;
      buf += ch;
      continue;
    }
    if (ch === "," && depth === 0) {
      args.push(buf);
      buf = "";
      continue;
    }
    buf += ch;
  }
  return args; // unterminated call: no usable handler list
}
