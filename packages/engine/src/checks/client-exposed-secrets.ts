import type { Check, Finding } from "../types.js";
import { lineAt } from "../util.js";

const SKIP = /(^|\/)(node_modules|dist|build|\.next|out|coverage)\//;
const TEST_PATH = /(^|\/)(test|tests|__tests__)(\/|$)|\.(test|spec)\.[jt]sx?$/;
const SOURCE = /\.((c|m)?(j|t)sx?|vue|svelte|astro|html)$/;
const ENV_FILE = /(^|\/)\.env(\.[\w.-]+)?$/;

/** Bundlers inline every variable with these prefixes into the JavaScript sent to the browser. */
const PUBLIC_VAR = /\b(?:VITE|NEXT_PUBLIC|REACT_APP|EXPO_PUBLIC|GATSBY|NUXT_PUBLIC|PUBLIC)_[A-Z0-9_]+\b/g;
/** Names that say the value is a credential only a server should hold. */
const SECRET_NAME =
  /SECRET|PRIVATE|SERVICE_ROLE|PASSWORD|PASSWD|DATABASE_URL|DB_URL|ADMIN_KEY|OPENAI|ANTHROPIC|CLAUDE|GROQ|GEMINI|MISTRAL|OPENROUTER|COHERE|DEEPSEEK|REPLICATE|HUGGINGFACE|HF_TOKEN|GITHUB_TOKEN|STRIPE_SK/;
/** Keys that are public by design: Supabase anon, Stripe publishable, Firebase web config, reCAPTCHA site key. */
const PUBLIC_BY_DESIGN = /ANON|PUBLISHABLE|FIREBASE_API_KEY|SITE_KEY|MEASUREMENT_ID/;

export const LLM_HOSTS = /https:\/\/(api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com|api\.groq\.com|api\.mistral\.ai|openrouter\.ai\/api|api\.deepseek\.com)/g;
const SERVER_PATH = /(^|\/)(server|api|functions|backend|lambda|supabase\/functions|scripts)\//;
export const JWT = /eyJ[A-Za-z0-9_-]{10,}\.(eyJ[A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]{10,}/g;

/** A file whose code runs in the browser: component files, "use client", or Vite-style env access. */
function isClientFile(path: string, content: string): boolean {
  if (SERVER_PATH.test(path)) return false;
  return /\.(jsx|tsx|vue|svelte|astro|html)$/.test(path) || /^\s*["']use client["']/m.test(content) || content.includes("import.meta.env");
}

export function jwtRole(payload: string): string | null {
  try {
    const json = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as { role?: unknown };
    return typeof json.role === "string" ? json.role : null;
  } catch {
    return null;
  }
}

export const clientExposedSecrets: Check = {
  id: "client-exposed-secrets",
  group: "F-ai",
  title: "No server secrets in browser code",
  severity: "critical",
  mode: "report",

  detect({ repo }) {
    const findings: Finding[] = [];
    for (const f of repo.files) {
      if (SKIP.test(f.path) || TEST_PATH.test(f.path)) continue;
      const isEnv = ENV_FILE.test(f.path);
      if (!isEnv && !SOURCE.test(f.path)) continue;

      const named = new Set<string>();
      for (const m of f.content.matchAll(PUBLIC_VAR)) {
        const name = m[0];
        if (named.has(name) || !SECRET_NAME.test(name) || PUBLIC_BY_DESIGN.test(name)) continue;
        named.add(name);
        findings.push({
          checkId: "client-exposed-secrets",
          title: `${name} is bundled into the browser`,
          severity: "critical",
          file: f.path,
          line: lineAt(f.content, m.index!),
          evidence: `variable name ${name}`,
          explanation:
            "Variables with this prefix are copied into the JavaScript every visitor downloads, so anyone can read this key in DevTools and spend it or use it as you. Move the call to a server route or edge function and keep the key in a server-only variable without the public prefix.",
        });
      }
      if (isEnv) continue;

      for (const m of f.content.matchAll(/dangerouslyAllowBrowser\s*:\s*true/g)) {
        findings.push({
          checkId: "client-exposed-secrets",
          title: "AI SDK is allowed to run in the browser",
          severity: "critical",
          file: f.path,
          line: lineAt(f.content, m.index!),
          evidence: "dangerouslyAllowBrowser: true",
          explanation:
            "This flag turns off the SDK's guard against shipping your API key to visitors. Every user can copy the key and run up your bill or read your account. Call the model from a server route instead.",
        });
      }

      for (const m of f.content.matchAll(JWT)) {
        if (jwtRole(m[1]) !== "service_role") continue;
        findings.push({
          checkId: "client-exposed-secrets",
          title: "Supabase service_role key is in the source",
          severity: "critical",
          file: f.path,
          line: lineAt(f.content, m.index!),
          evidence: "JWT with role service_role (value not shown)",
          explanation:
            "The service_role key skips every row-level security policy, so whoever has it can read and change all data. Rotate it in the Supabase dashboard now, and use it only from server code that reads it from an environment variable.",
        });
      }

      if (!isClientFile(f.path, f.content)) continue;
      const hosts = new Set<string>();
      for (const m of f.content.matchAll(LLM_HOSTS)) {
        if (hosts.has(m[1])) continue;
        hosts.add(m[1]);
        findings.push({
          checkId: "client-exposed-secrets",
          title: `Browser code calls ${m[1]} directly`,
          severity: "high",
          file: f.path,
          line: lineAt(f.content, m.index!),
          evidence: m[0],
          explanation:
            "A model API called from the browser needs its key in the browser too, where visitors can take it. It also lets anyone send any prompt on your account. Put a server route in between that holds the key, checks the user and limits requests.",
        });
      }
    }
    return findings;
  },
};
