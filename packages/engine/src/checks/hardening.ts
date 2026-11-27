/* eslint-disable @typescript-eslint/no-explicit-any */
import type { Check, FileEdit, Finding, Patch, RepoFile, RepoSnapshot, Severity } from "../types.js";
import { analysable, children, isFunction, lineOf, memberPath, parseFile, snippet, stringValue } from "../analysis/ast.js";

/**
 * AST checks for code that is insecure on its own, without needing request input to reach it:
 * weak cryptography and insecure configuration (TLS checks off, hard-coded session secrets,
 * credentialed CORS for any origin, serving the project folder, leaking stack traces …).
 */

type N = any;

interface Visit {
  file: RepoFile;
  node: N;
  /** Enclosing nodes, innermost last. */
  stack: N[];
}

function walkRepo(repo: RepoSnapshot, cb: (v: Visit) => void): void {
  for (const file of repo.files) {
    if (!analysable(file)) continue;
    const ast = parseFile(file);
    if (!ast) continue;
    const stack: N[] = [];
    const go = (node: N) => {
      cb({ file, node, stack });
      stack.push(node);
      for (const c of children(node)) go(c);
      stack.pop();
    };
    go(ast.program);
  }
}

function propName(p: N): string | null {
  if (p?.type !== "ObjectProperty") return null;
  return p.key.type === "Identifier" ? p.key.name : stringValue(p.key);
}

function enclosingFunction(stack: N[]): N | null {
  for (let i = stack.length - 1; i >= 0; i--) if (isFunction(stack[i])) return stack[i];
  return null;
}

/** The name a value is stored under: const token = …, obj.resetCode = …, { secret: … }, function makeToken() { return … }. */
function storedUnder(stack: N[]): string {
  for (let i = stack.length - 1; i >= 0; i--) {
    const n = stack[i];
    if (n.type === "VariableDeclarator" && n.id.type === "Identifier") return n.id.name;
    if (n.type === "AssignmentExpression") return memberPath(n.left) ?? "";
    if (n.type === "ObjectProperty") return propName(n) ?? "";
    if (n.type === "ReturnStatement") {
      const fn = enclosingFunction(stack.slice(0, i));
      const parent = stack[stack.indexOf(fn) - 1];
      return fn?.id?.name ?? (parent?.type === "VariableDeclarator" ? parent.id.name : "") ?? "";
    }
    if (isFunction(n)) return n.id?.name ?? "";
  }
  return "";
}

const SECURITY_NAME = /token|secret|passw|pwd|otp|nonce|salt|session|apikey|api_key|reset|invite|verif|csrf|code|key|auth/i;
const PASSWORD_TEXT = /passw|pwd|credential/i;

function finding(checkId: string, v: Visit, severity: Severity, title: string, explanation: string, remedy?: string): Finding {
  return { checkId, title, severity, file: v.file.path, line: lineOf(v.node), evidence: snippet(v.file.content, v.node), explanation, remedy };
}

function num(n: N): number | null {
  return n?.type === "NumericLiteral" ? n.value : null;
}

// ---------------------------------------------------------------------------------------------

function weakCryptoFindings(repo: RepoSnapshot): Finding[] {
  const out: Finding[] = [];
  walkRepo(repo, (v) => {
    const n = v.node;
    if (n.type !== "CallExpression" && n.type !== "NewExpression") return;
    const path = memberPath(n.callee) ?? "";
    const method = path.split(".").pop() ?? "";
    const args: N[] = n.arguments ?? [];

    if (method === "createHash" || method === "createHmac") {
      const alg = (stringValue(args[0]) ?? "").toLowerCase();
      const fn = enclosingFunction(v.stack);
      const scope = fn ? v.file.content.slice(fn.start, fn.end) : v.file.content.slice(Math.max(0, n.start - 300), n.end + 300);
      if (method === "createHash" && /^(md5|sha1|md4|sha-1)$/.test(alg) && PASSWORD_TEXT.test(scope)) {
        out.push(finding("weak-crypto", v, "high", `Passwords hashed with ${alg.toUpperCase()}`, `${alg.toUpperCase()} is fast and unsalted here, so leaked hashes are cracked in minutes with a GPU or a lookup table.`, "Hash passwords with bcrypt (cost 12), scrypt or argon2id, which are slow on purpose and salt each hash."));
      } else if (method === "createHash" && /^(sha256|sha512|sha-256)$/.test(alg) && PASSWORD_TEXT.test(scope) && !/salt|pbkdf2|scrypt|bcrypt|argon/i.test(scope)) {
        out.push(finding("weak-crypto", v, "medium", "Passwords hashed with a fast unsalted hash", "A single SHA-2 round is billions of guesses per second on a GPU; without a per-user salt, equal passwords also share a hash.", "Use bcrypt, scrypt or argon2id for passwords."));
      }
    }
    if (path === "Math.random" || path === "global.Math.random") {
      const name = storedUnder(v.stack);
      if (SECURITY_NAME.test(name)) {
        out.push(finding("weak-crypto", v, "high", "Predictable random value used for a security token", `Math.random() is not cryptographically secure; values stored in "${name}" can be predicted from earlier outputs.`, "Use crypto.randomBytes(32).toString('hex') or crypto.randomUUID()."));
      }
    }
    if (/^(crypto\.)?(createCipher|createDecipher)$/.test(path)) {
      out.push(finding("weak-crypto", v, "high", "Deprecated createCipher without an IV", "createCipher derives the key with one round of MD5 and uses no IV, so the same text always encrypts the same way. It was removed in Node 22.", "Use createCipheriv('aes-256-gcm', key, iv) with a random 12-byte IV per message and store the auth tag."));
    }
    if (method === "createCipheriv" || method === "createDecipheriv" || method === "createCipher") {
      const alg = (stringValue(args[0]) ?? "").toLowerCase();
      if (/-ecb$|^des\b|^des-|^rc4|^rc2|^bf-|^blowfish/.test(alg)) {
        out.push(finding("weak-crypto", v, "high", `Weak cipher mode ${alg}`, "ECB leaks patterns in the data, and DES, RC2, RC4 and Blowfish are broken or too weak today.", "Use aes-256-gcm with a random IV per message."));
      }
      const iv = args[2];
      if (method === "createCipheriv" && iv && (iv.type === "StringLiteral" || (iv.type === "CallExpression" && /Buffer\.(from|alloc)$/.test(memberPath(iv.callee) ?? "") && (iv.arguments[0]?.type === "StringLiteral" || iv.arguments[0]?.type === "NumericLiteral")))) {
        out.push(finding("weak-crypto", v, "medium", "Fixed IV for encryption", "Reusing one IV with the same key makes equal messages encrypt identically, and with GCM or CTR it can reveal the plaintext.", "Generate a new IV for every message with crypto.randomBytes(12) and store it next to the ciphertext."));
      }
    }
    if (/^(bcrypt|bcryptjs)?\.?(hash|hashSync|genSalt|genSaltSync)$/.test(path) && /bcrypt/i.test(v.file.content)) {
      const cost = method.startsWith("genSalt") ? num(args[0]) : num(args[1]);
      if (cost !== null && cost < 10) {
        out.push(finding("weak-crypto", v, "medium", `bcrypt cost ${cost} is too low`, "Each step down halves the work an attacker needs to crack a leaked hash; below 10 it is fast enough to brute-force common passwords.", "Use a cost of 12 (about 250 ms per hash on a server)."));
      }
    }
    if (/^(crypto\.)?pbkdf2(Sync)?$/.test(path)) {
      const iters = num(args[2]);
      const digest = (stringValue(args[4]) ?? "").toLowerCase();
      if ((iters !== null && iters < 100_000) || /^(md5|sha1)$/.test(digest)) {
        out.push(finding("weak-crypto", v, "medium", "Weak PBKDF2 settings", `PBKDF2 with ${iters ?? "?"} iterations${digest ? ` of ${digest}` : ""} is far below today's guidance of 600,000 iterations of SHA-256.`, "Raise the iterations to 600000 with sha256, or switch to argon2id or scrypt."));
      }
    }
    if (path === "crypto.pseudoRandomBytes") {
      out.push(finding("weak-crypto", v, "medium", "pseudoRandomBytes is not secure", "pseudoRandomBytes is a deprecated alias that was never meant for keys or tokens.", "Use crypto.randomBytes."));
    }
  });
  return out;
}

export const weakCrypto: Check = {
  id: "weak-crypto",
  group: "C-security",
  title: "Strong cryptography",
  severity: "high",
  mode: "report",
  detect: ({ repo }) => weakCryptoFindings(repo),
};

// ---------------------------------------------------------------------------------------------

interface ConfigHit extends Finding {
  /** For the fix: the exact text to swap on that line. */
  swap?: [string, string];
}

function insecureConfigFindings(repo: RepoSnapshot): ConfigHit[] {
  const out: ConfigHit[] = [];
  walkRepo(repo, (v) => {
    const n = v.node;
    const id = "insecure-config";

    if (n.type === "ObjectProperty") {
      const key = propName(n);
      const val = n.value;
      if ((key === "rejectUnauthorized" || key === "strictSSL") && val.type === "BooleanLiteral" && !val.value) {
        const text = v.file.content.slice(n.start, n.end);
        out.push({
          ...finding(id, v, "high", "TLS certificate checks are turned off", "With certificate checks off, anyone on the network path (public Wi-Fi, a compromised router) can impersonate the server and read or change the traffic, including passwords and API keys.", "Remove the option, or set it to true and give the client the right CA certificate instead."),
          swap: [text, text.replace(/false\s*$/, "true")],
        });
      }
      if (key === "httpOnly" && val.type === "BooleanLiteral" && !val.value) {
        out.push(finding(id, v, "medium", "Cookie readable by page scripts (httpOnly: false)", "Any XSS bug can then read the session cookie and send it to the attacker.", "Set httpOnly: true for session and auth cookies."));
      }
      if (key === "secure" && val.type === "BooleanLiteral" && !val.value && v.stack.some((s) => s.type === "ObjectProperty" && propName(s) === "cookie")) {
        out.push(finding(id, v, "medium", "Session cookie sent over plain HTTP (secure: false)", "Without secure, the browser also sends the cookie over http://, where anyone on the network can read it.", "Set secure: true in production (and app.set('trust proxy', 1) behind a load balancer)."));
      }
    }

    if (n.type === "AssignmentExpression" && /NODE_TLS_REJECT_UNAUTHORIZED$/.test(memberPath(n.left) ?? "") && stringValue(n.right) === "0") {
      out.push(finding(id, v, "high", "TLS certificate checks are turned off for the whole process", "Every HTTPS request the app makes accepts any certificate, so traffic can be intercepted and changed.", "Delete this line; trust a private CA with NODE_EXTRA_CA_CERTS instead."));
    }

    if (n.type === "CallExpression") {
      const path = memberPath(n.callee) ?? "";
      const args: N[] = n.arguments;
      const opts = args.find((a) => a?.type === "ObjectExpression");
      const prop = (o: N, k: string) => o?.properties.find((p: N) => propName(p) === k)?.value;

      // express-session / cookie-session / cookie-parser with a secret written in the code
      if (/^(session|expressSession|cookieSession|cookieParser|fastifySession|fastifyCookie)$/.test(path) || /\b(session|cookie-session)\b/.test(path)) {
        const secret = path === "cookieParser" ? args[0] : prop(opts, "secret") ?? prop(opts, "keys");
        const lit = secret?.type === "StringLiteral" ? secret.value : secret?.type === "ArrayExpression" && secret.elements[0]?.type === "StringLiteral" ? secret.elements[0].value : null;
        if (lit !== null) {
          out.push({ ...finding(id, v, "high", "Session secret written in the code", "Anyone who can read the repo can sign their own session cookie and log in as any user.", "Read it from an environment variable (process.env.SESSION_SECRET) and fail at startup when it is missing."), evidence: `${path}({ secret: "${lit.slice(0, 3)}…" })` });
        }
      }
      // cors({ origin: true, credentials: true }) reflects any origin and sends cookies
      if (path === "cors" && opts) {
        const origin = prop(opts, "origin");
        const creds = prop(opts, "credentials");
        const reflects = origin && ((origin.type === "BooleanLiteral" && origin.value) || (isFunction(origin) && /callback\(null,\s*true\)|cb\(null,\s*true\)/.test(v.file.content.slice(origin.start, origin.end))));
        if (reflects && creds?.type === "BooleanLiteral" && creds.value) {
          out.push(finding(id, v, "high", "Any website can make logged-in requests (CORS reflects every origin with credentials)", "Every site the user visits can call this API with their cookies and read the answers, so their data and actions are exposed.", "List the exact origins you trust: cors({ origin: ['https://your.app'], credentials: true })."));
        }
      }
      // express.static over the project folder serves .env, source and .git
      if (/(^|\.)static$/.test(path) && /express|serve-static|serveStatic/.test(v.file.content)) {
        const a0 = args[0];
        const text = a0 ? v.file.content.slice(a0.start, a0.end).replace(/\s+/g, "") : "";
        if (/^(__dirname|process\.cwd\(\)|["']\.\/?["']|path\.(join|resolve)\(__dirname\)|path\.(join|resolve)\(__dirname,["']\.\.?\/?["']\))$/.test(text)) {
          out.push(finding(id, v, "high", "The whole project folder is served to the web", "Anyone can download server.js, package.json and, worst of all, .env with its keys, by guessing the file name.", "Serve only a dedicated folder: express.static(path.join(__dirname, 'public'))."));
        }
      }
      // Stack traces and raw errors sent to the client
      if (/^(res|response|reply)\.(send|json|end|write)$|^(res|response)\.status\(.*\)\.(send|json)$/.test(path) || (/\.(send|json)$/.test(path) && /^(res|response|reply)\b/.test(snippet(v.file.content, n.callee)))) {
        const text = args.map((a) => v.file.content.slice(a.start, a.end)).join(",");
        if (/\b(err|error|e|ex|exception)\.stack\b/.test(text)) {
          out.push(finding(id, v, "medium", "Stack traces are sent to the client", "Stack traces reveal file paths, library versions and code structure, which makes the next attack easier.", "Log the error on the server and send a short message with a request ID instead."));
        }
      }
    }

    // if (password === "admin123") – a password written in the code
    if (n.type === "BinaryExpression" && (n.operator === "===" || n.operator === "==")) {
      const sides = [n.left, n.right];
      const lit = sides.find((s) => s.type === "StringLiteral" && s.value.length >= 3);
      const other = sides.find((s) => s !== lit);
      const name = memberPath(other) ?? "";
      if (lit && /passw|pwd|passcode|pin$/i.test(name.split(".").pop() ?? "")) {
        out.push({ ...finding(id, v, "critical", "Password checked against a value written in the code", "Anyone who reads the repo, or guesses a common value, gets in; the password cannot be changed without a deploy.", "Store a bcrypt hash per user in the database and compare with bcrypt.compare()."), evidence: `${name} === "${lit.value.slice(0, 2)}…"` });
      }
    }
  });
  return out;
}

export const insecureConfig: Check = {
  id: "insecure-config",
  group: "C-security",
  title: "Secure configuration",
  severity: "high",
  mode: "auto",
  detect: ({ repo }) => insecureConfigFindings(repo).map(({ swap: _s, ...f }) => f),

  /** Only the TLS switch is fixed automatically: flipping false to true changes one token on one line. */
  fix({ repo }): Patch | null {
    const hits = insecureConfigFindings(repo).filter((h) => h.swap);
    if (hits.length === 0) return null;
    const edits: FileEdit[] = [];
    const removals: string[] = [];
    for (const path of new Set(hits.map((h) => h.file!))) {
      const before = repo.files.find((f) => f.path === path)!.content;
      const lines = before.split("\n");
      for (const h of hits.filter((x) => x.file === path)) {
        const original = lines[h.line! - 1];
        const replaced = original.replace(h.swap![0], h.swap![1]);
        if (replaced === original) continue;
        lines[h.line! - 1] = replaced;
        removals.push(original.trim());
      }
      const after = lines.join("\n");
      if (after !== before) edits.push({ kind: "modify", path, before, after });
    }
    if (edits.length === 0) return null;
    return {
      id: "insecure-config-1",
      checkId: "insecure-config",
      title: "Turn TLS certificate checks back on",
      class: "minimal-edit",
      reason: "rejectUnauthorized: false accepts any certificate. Setting it to true restores the check; if the server uses a private CA, pass it with the ca option.",
      edits,
      allowedRemovals: removals,
    };
  },
};
