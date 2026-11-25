/** Small, dependency-free readers for the HTML a live site returns. Never executes anything. */

export interface Tag {
  name: string;
  attrs: Record<string, string>;
  /** Text between the opening and closing tag, for <script> and <style> only. */
  body?: string;
  /** Character offset of the tag in the document. */
  index: number;
}

const ATTR = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/g;

export function parseAttrs(raw: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const m of raw.matchAll(ATTR)) {
    const name = m[1].toLowerCase();
    if (!(name in out)) out[name] = m[2] ?? m[3] ?? m[4] ?? "";
  }
  return out;
}

/** Comments hide markup the browser ignores; blank them so offsets stay true. */
function stripComments(html: string): string {
  return html.replace(/<!--[\s\S]*?-->/g, (c) => " ".repeat(c.length));
}

/** Every opening tag of the given names, with scripts and styles carrying their inline body. */
export function tags(html: string, names: string[]): Tag[] {
  const clean = stripComments(html);
  const lower = clean.toLowerCase();
  const out: Tag[] = [];
  const re = new RegExp(`<(${names.join("|")})\\b([^>]*)>`, "gi");
  for (const m of clean.matchAll(re)) {
    const name = m[1].toLowerCase();
    const tag: Tag = { name, attrs: parseAttrs(m[2]), index: m.index! };
    if (name === "script" || name === "style") {
      const start = m.index! + m[0].length;
      const end = lower.indexOf(`</${name}`, start);
      tag.body = end === -1 ? "" : html.slice(start, end);
    }
    out.push(tag);
  }
  return out;
}

/** Resolve a URL attribute against the page; null when it is not http(s). */
export function resolve(ref: string, base: string): URL | null {
  try {
    const u = new URL(ref.trim(), base);
    return u.protocol === "http:" || u.protocol === "https:" ? u : null;
  } catch {
    return null;
  }
}

/** Split a Set-Cookie value into its name and lower-cased attributes. Never returns the value. */
export function cookieShape(header: string): { name: string; flags: Map<string, string> } {
  const [pair, ...rest] = header.split(";");
  const name = pair.split("=")[0].trim();
  const flags = new Map<string, string>();
  for (const part of rest) {
    const [k, ...v] = part.split("=");
    if (k.trim()) flags.set(k.trim().toLowerCase(), v.join("=").trim().toLowerCase());
  }
  return { name, flags };
}

/** Parse a CSP into directive -> source list. */
export function parseCsp(policy: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const part of policy.split(";")) {
    const [dir, ...sources] = part.trim().split(/\s+/);
    if (dir && !out.has(dir.toLowerCase())) out.set(dir.toLowerCase(), sources);
  }
  return out;
}
