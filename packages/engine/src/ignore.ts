/**
 * `.siidekickignore`: paths a repo owner asks Siidekick not to scan, such as deliberately vulnerable demos,
 * test fixtures or the scanner's own rule definitions. Same idea as `.gitignore`:
 *
 *   # comment            blank lines and comments are skipped
 *   demo/                a directory, at any depth (or at the root with a leading "/")
 *   /docs/samples/       anchored to the repo root
 *   *.min.js             a glob on the file name, at any depth
 *   test/**\/fixtures/    "**" matches any number of directories
 *   !demo/README.md      a later "!" pattern brings a path back
 *
 * Ignored files are never hidden silently: the report counts them and lists the patterns.
 */
export const IGNORE_FILE = ".siidekickignore";

interface Rule {
  re: RegExp;
  negate: boolean;
}

function globToRegex(glob: string): string {
  let out = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i];
    if (c === "*") {
      if (glob[i + 1] === "*") {
        // "**/" = zero or more directories; a trailing "**" = everything below
        if (glob[i + 2] === "/") {
          out += "(?:.*/)?";
          i += 2;
        } else {
          out += ".*";
          i += 1;
        }
      } else out += "[^/]*";
    } else if (c === "?") out += "[^/]";
    else out += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return out;
}

export function parseIgnore(text: string): Rule[] {
  const rules: Rule[] = [];
  for (const raw of text.split(/\r?\n/)) {
    let line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const negate = line.startsWith("!");
    if (negate) line = line.slice(1);
    const dir = line.endsWith("/");
    if (dir) line = line.slice(0, -1);
    const anchored = line.startsWith("/") || line.includes("/");
    line = line.replace(/^\//, "");
    if (!line) continue;
    const body = globToRegex(line);
    // A directory pattern matches everything under it; a file pattern matches the path itself or a directory of that name.
    const tail = dir ? "/.*" : "(?:/.*)?";
    const re = new RegExp(`^${anchored ? "" : "(?:.*/)?"}${body}${tail}$`);
    rules.push({ re, negate });
  }
  return rules;
}

export function isIgnored(path: string, rules: Rule[]): boolean {
  let ignored = false;
  for (const r of rules) if (r.re.test(path)) ignored = !r.negate;
  return ignored;
}
