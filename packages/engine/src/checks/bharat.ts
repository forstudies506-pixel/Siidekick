/**
 * Bharat Pack: mistakes specific to apps built for Indian users. Online payments (Razorpay, Paytm, PhonePe,
 * UPI callbacks), Aadhaar and PAN numbers, and OTP logins appear in most Indian student, college and
 * small-business projects, and generic scanners do not look for how they go wrong.
 */
import type { Check, FileEdit, Finding, Patch, RepoFile } from "../types.js";
import { CODE_EXT, lineAt } from "../util.js";

const TEST_PATH = /(^|\/)(test|tests|__tests__)(\/|$)|\.(test|spec)\.[jt]sx?$/;
const SKIP = /(^|\/)(node_modules|dist|build|\.siidekick)\/|\.min\.js$|(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$/;
const codeFiles = (files: RepoFile[]) => files.filter((f) => CODE_EXT.test(f.path) && !SKIP.test(f.path));
const lineText = (content: string, line: number) => content.split("\n")[line - 1]?.trim().slice(0, 160) ?? "";

// ---------- payments: confirmations the server never checks ----------

/** Reads a Razorpay payment id that the browser sent. */
const RZP_HANDLER = /req\.(?:body|query|params)(?:\.|\[\s*['"])razorpay_payment_id|\{[^}\n]*\brazorpay_payment_id\b[^}\n]*\}\s*=\s*req\.(?:body|query|params)/;
/** Proof the handler checks Razorpay's signature (SDK helper, HMAC over order|payment, or a helper we added). */
const RZP_VERIFIED = /validatePaymentVerification|validateWebhookSignature|verifyRazorpaySignature\s*\(|createHmac\s*\(\s*['"]sha256['"]/;
/** A payment status the browser or a callback query string reports, trusted as is. */
const CLIENT_STATUS = /req\.(?:body|query|params)\.(?:status|payment_?status|txn_?status|STATUS|code)\s*={2,3}\s*['"](?:success|paid|captured|completed|TXN_SUCCESS|SUCCESS|PAYMENT_SUCCESS|PAYMENT_SUCCESS)['"]/;
const CALLBACK_VERIFIED = /verifySignature|verifychecksumbyString|verifyChecksum|checksum|x-verify|createHmac|timingSafeEqual|getOrderStatus|orders\.fetch|payments\.fetch|\/status\//i;

function paymentFindings(files: RepoFile[]): Finding[] {
  const out: Finding[] = [];
  for (const f of codeFiles(files)) {
    if (TEST_PATH.test(f.path)) continue;
    const handler = RZP_HANDLER.exec(f.content);
    if (handler && !RZP_VERIFIED.test(f.content)) {
      const line = lineAt(f.content, handler.index);
      out.push({
        checkId: "payment-verification",
        title: "Razorpay payment accepted without checking its signature",
        severity: "critical",
        file: f.path,
        line,
        evidence: lineText(f.content, line),
        explanation:
          "This route trusts the payment id the browser sends. Anyone can post a made-up razorpay_payment_id and get the order marked paid: free fest passes, merch or fee receipts. Razorpay signs order_id|payment_id with your key secret so the server can tell a real payment from a fake one.",
        remedy:
          "const crypto = require(\"crypto\");\nconst expected = crypto.createHmac(\"sha256\", process.env.RAZORPAY_KEY_SECRET)\n  .update(`${razorpay_order_id}|${razorpay_payment_id}`).digest(\"hex\");\nif (expected !== razorpay_signature) return res.status(400).json({ error: \"payment not verified\" });",
      });
    }
    const status = CLIENT_STATUS.exec(f.content);
    if (status && !CALLBACK_VERIFIED.test(f.content)) {
      const line = lineAt(f.content, status.index);
      out.push({
        checkId: "payment-verification",
        title: "Payment status taken from the request instead of the gateway",
        severity: "critical",
        file: f.path,
        line,
        evidence: lineText(f.content, line),
        explanation:
          "The server believes a 'success' status that arrives in the request. A buyer can edit the callback URL or body and mark a failed or unpaid UPI payment as paid.",
        remedy:
          "Verify the gateway's checksum or signature on the callback (Paytm: verifySignature; PhonePe: the X-VERIFY header; Razorpay: the HMAC above), or ask the gateway for the order status from your server before marking it paid.",
      });
    }
  }
  return out;
}

function isEsm(files: RepoFile[]): boolean {
  const pkg = files.find((f) => f.path === "package.json");
  try {
    return pkg ? (JSON.parse(pkg.content) as { type?: string }).type === "module" : false;
  } catch {
    return false;
  }
}

/** POSIX path from the file `from` to `to`, as require/import wants it ("./x", "../lib/x"). */
function relPath(from: string, to: string): string {
  const a = from.split("/").slice(0, -1);
  const b = to.split("/");
  let i = 0;
  while (i < a.length && i < b.length - 1 && a.at(i) === b.at(i)) i++;
  const up = a.length - i;
  const rest = b.slice(i).join("/");
  return up === 0 ? `./${rest}` : `${"../".repeat(up)}${rest}`;
}

const HELPER_PATH = "lib/verifyRazorpaySignature.js";

/**
 * Wires the check into one handler file with added lines only: an import under the existing ones, and a guard
 * right before the line that reads razorpay_payment_id. Returns null when the shape is not one we can wire safely.
 */
function wireHandler(f: RepoFile, esm: boolean): FileEdit | null {
  const m = RZP_HANDLER.exec(f.content);
  if (!m) return null;
  const lines = f.content.split("\n");
  const at = lineAt(f.content, m.index) - 1;
  const target = lines.at(at) ?? "";
  // A one-line route (handler and body on the same line) has no safe place for a guard.
  if (/\b(?:app|router)\.(?:post|get|all|put)\s*\(/.test(target) || !/\bres\./.test(f.content)) return null;
  const indent = /^\s*/.exec(target)?.[0] ?? "";
  const q = /require\('|from '/.test(f.content) ? "'" : '"';
  const rel = relPath(f.path, HELPER_PATH);
  const importLine = esm
    ? `import verifyRazorpaySignature from ${q}${rel}${q};`
    : `const verifyRazorpaySignature = require(${q}${rel.replace(/\.js$/, "")}${q});`;
  const guard = `${indent}if (!verifyRazorpaySignature(req.body)) { res.status(400).json({ error: ${q}payment not verified${q} }); return; }`;
  // After the last top-level import/require line, else at the top.
  let last = -1;
  lines.forEach((l, i) => {
    if (esm ? /^import\s/.test(l) : /^(?:const|let|var)\s+[^=]+=\s*require\(/.test(l)) last = i;
  });
  const out = [...lines];
  out.splice(at, 0, guard);
  out.splice(last + 1, 0, importLine);
  return { kind: "modify", path: f.path, before: f.content, after: out.join("\n") };
}

function verifyHelper(files: RepoFile[]): string {
  const esm = isEsm(files);
  const body = `function verifyRazorpaySignature({ razorpay_order_id, razorpay_payment_id, razorpay_signature }, secret = process.env.RAZORPAY_KEY_SECRET) {
  if (!secret || !razorpay_order_id || !razorpay_payment_id || !razorpay_signature) return false;
  const expected = crypto.createHmac("sha256", secret).update(\`\${razorpay_order_id}|\${razorpay_payment_id}\`).digest("hex");
  const a = Buffer.from(expected);
  const b = Buffer.from(String(razorpay_signature));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}`;
  const head = `// Added by Siidekick. Razorpay signs "order_id|payment_id" with your key secret; only a matching
// signature proves the payment happened. Call this before marking an order paid:
//   if (!verifyRazorpaySignature(req.body)) return res.status(400).json({ error: "payment not verified" });
`;
  return esm
    ? `${head}import crypto from "node:crypto";\n\nexport ${body}\n\nexport default verifyRazorpaySignature;\n`
    : `${head}const crypto = require("node:crypto");\n\n${body}\n\nmodule.exports = verifyRazorpaySignature;\n`;
}

export const paymentVerification: Check = {
  id: "payment-verification",
  group: "D-domain",
  title: "Online payments are verified on the server",
  severity: "critical",
  mode: "auto",
  detect: ({ repo }) => paymentFindings(repo.files),
  fix({ repo }, findings): Patch | null {
    const handlers = new Set(findings.filter((f) => f.title.startsWith("Razorpay") && f.file).map((f) => f.file as string));
    if (handlers.size === 0 || repo.files.some((f) => f.path === HELPER_PATH)) return null;
    const esm = isEsm(repo.files);
    const wired = repo.files.filter((f) => handlers.has(f.path)).map((f) => wireHandler(f, esm)).filter((e): e is FileEdit => e !== null);
    return {
      id: "payment-verification-1",
      checkId: "payment-verification",
      title: wired.length ? "Check Razorpay's signature before issuing the order" : "Add a Razorpay signature check helper",
      class: "additive",
      reason: wired.length
        ? "Adds verifyRazorpaySignature(), which recomputes Razorpay's HMAC over order_id|payment_id with RAZORPAY_KEY_SECRET and compares it in constant time, and calls it at the top of the payment route: a made-up payment id now gets 400 instead of a pass. Only lines are added; set RAZORPAY_KEY_SECRET in the environment."
        : "Adds verifyRazorpaySignature(), which recomputes Razorpay's HMAC with your key secret and compares it in constant time. Call it in the payment route before marking an order paid; until it is wired in, the check keeps failing.",
      edits: [{ kind: "create", path: HELPER_PATH, content: verifyHelper(repo.files) }, ...wired],
    };
  },
};

// ---------- Aadhaar and PAN ----------

// Verhoeff tables: every real Aadhaar number ends in a Verhoeff check digit (UIDAI). Random 12-digit
// numbers pass only one time in ten, so this keeps phone numbers, ids and timestamps out.
const D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5], [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1], [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const P = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4], [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1], [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

export function verhoeffValid(digits: string): boolean {
  let c = 0;
  const rev = digits.split("").reverse().map(Number);
  for (let i = 0; i < rev.length; i++) c = D[c][P[i % 8][rev[i]]];
  return c === 0;
}

/** The check digit that makes `digits` Verhoeff-valid (used by tests, so no real-looking number is committed). */
export function verhoeffDigit(digits: string): number {
  for (let d = 0; d < 10; d++) if (verhoeffValid(digits + d)) return d;
  return 0;
}

const AADHAAR = /(?<![\d.])([2-9]\d{3})([ -]?)(\d{4})\2(\d{4})(?![\d.])/g;
const AADHAAR_WORD = /aadh?aa?r|\buid\b|uidai/i;
const PAN = /\b([A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z])\b/g;
const PAN_WORD = /\bpan\b|pan_?(?:no|number|card)|panNumber|permanent account/i;
/** console/logger calls whose arguments name identity data. */
const LOG_CALL = /\b(?:console\.(?:log|info|debug|warn|error)|logger\.(?:log|info|debug|warn|error)|log\.(?:info|debug))\s*\(([^;\n]*)\)/g;
const PII_NAME = /\b(?:aadh?aa?r\w*|pan(?:_?(?:no|number|card))?|panNumber|upi_?id|vpa|dob|date_?of_?birth)\b/i;

const maskAadhaar = (last4: string) => `XXXX XXXX ${last4}`;
const maskPan = (pan: string) => `${pan.slice(0, 2)}XXXXX${pan.slice(7)}`;

function piiFindings(files: RepoFile[]): Finding[] {
  const out: Finding[] = [];
  for (const f of files) {
    if (SKIP.test(f.path)) continue;
    const isCode = CODE_EXT.test(f.path);
    const lines = f.content.split("\n");
    for (const m of f.content.matchAll(AADHAAR)) {
      const digits = m[1] + m[3] + m[4];
      const line = lineAt(f.content, m.index!);
      const text = lines[line - 1] ?? "";
      // Formatted 4-4-4 or named as Aadhaar on the same line, and checksum-valid.
      if (!(m[2] || AADHAAR_WORD.test(text)) || !verhoeffValid(digits) || text.length > 400) continue;
      out.push({
        checkId: "indian-pii",
        title: "Aadhaar number written in the code",
        severity: "high",
        file: f.path,
        line,
        evidence: maskAadhaar(m[4]),
        explanation:
          "This passes the Aadhaar checksum, so it may be a real person's number. Aadhaar numbers are identity data: keep them out of code, test data and git history, and store them only masked or encrypted.",
        remedy: "Replace it with a clearly fake value that fails the checksum, remove it from git history, and mask stored numbers (show only the last 4 digits).",
      });
    }
    for (const m of f.content.matchAll(PAN)) {
      const line = lineAt(f.content, m.index!);
      if (!PAN_WORD.test(lines[line - 1] ?? "")) continue;
      out.push({
        checkId: "indian-pii",
        title: "PAN number written in the code",
        severity: "high",
        file: f.path,
        line,
        evidence: maskPan(m[1]),
        explanation: "A PAN in code or test data can be a real person's tax identity. Keep it out of the repo.",
        remedy: "Use an obviously fake value in tests and remove the real one from git history.",
      });
    }
    if (!isCode || TEST_PATH.test(f.path)) continue;
    for (const m of f.content.matchAll(LOG_CALL)) {
      if (!PII_NAME.test(m[1])) continue;
      const line = lineAt(f.content, m.index!);
      out.push({
        checkId: "indian-pii",
        title: "Identity data written to the logs",
        severity: "high",
        file: f.path,
        line,
        evidence: lineText(f.content, line),
        explanation:
          "Aadhaar, PAN, UPI ids or dates of birth in logs end up in log files and dashboards that many people and services can read, and are kept far longer than the data itself.",
        remedy: "Log an id or a masked value instead, e.g. aadhaar.slice(-4), and never the full number.",
      });
    }
  }
  return out;
}

export const indianPii: Check = {
  id: "indian-pii",
  group: "D-domain",
  title: "Aadhaar, PAN and UPI data stays out of code and logs",
  severity: "high",
  mode: "report",
  detect: ({ repo }) => piiFindings(repo.files),
};

// ---------- OTP logins ----------

const OTP_IN_RESPONSE = /res\.(?:status\([^)]*\)\.)?(?:json|send)\s*\(\s*\{[^}]*\botp\b/i;
const OTP_LOGGED = /\b(?:console\.(?:log|info|debug|warn)|logger\.(?:log|info|debug|warn))\s*\([^;\n]*\botp\b/i;
const OTP_WEAK = /Math\.floor\s*\(\s*(?:\d+\s*\+\s*)?Math\.random\s*\(\s*\)\s*\*\s*\d+/;

function otpFindings(files: RepoFile[]): Finding[] {
  const out: Finding[] = [];
  for (const f of codeFiles(files)) {
    if (TEST_PATH.test(f.path) || !/otp/i.test(f.content)) continue;
    const add = (re: RegExp, title: string, severity: Finding["severity"], explanation: string, remedy: string) => {
      const m = re.exec(f.content);
      if (!m) return;
      const line = lineAt(f.content, m.index);
      out.push({ checkId: "otp-safety", title, severity, file: f.path, line, evidence: lineText(f.content, line), explanation, remedy });
    };
    add(
      OTP_IN_RESPONSE,
      "OTP sent back in the API response",
      "critical",
      "The one-time password is returned to whoever asked for it, so anyone can log in as any phone number without receiving the SMS.",
      'Send the OTP only by SMS and respond with res.json({ sent: true }).',
    );
    add(
      OTP_LOGGED,
      "OTP written to the logs",
      "high",
      "Anyone who can read the logs can take over accounts while the OTP is valid.",
      "Do not log OTPs; log that one was sent, and to which masked number.",
    );
    // Math.random only counts when the same file is clearly about OTPs (checked above).
    add(
      OTP_WEAK,
      "OTP generated with Math.random",
      "medium",
      "Math.random is not meant for secrets; its output can be predicted, which shrinks how many OTPs an attacker needs to try.",
      'const otp = crypto.randomInt(100000, 1000000); // const crypto = require("node:crypto")',
    );
  }
  return out;
}

export const otpSafety: Check = {
  id: "otp-safety",
  group: "D-domain",
  title: "OTP logins keep the code secret",
  severity: "critical",
  mode: "report",
  detect: ({ repo }) => otpFindings(repo.files),
};

export const bharatChecks: Check[] = [paymentVerification, indianPii, otpSafety];
