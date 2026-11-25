import { describe, expect, it } from "vitest";
import { clientExposedSecrets } from "../src/checks/client-exposed-secrets";
import type { Finding, RepoFile } from "../src/types";

const run = (files: RepoFile[]) => clientExposedSecrets.detect({ repo: { name: "t", files } }) as Finding[];
const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
// Built at test time so the repo holds no key-shaped literal.
const jwt = (role: string) => `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ iss: "supabase", role, iat: 1700000000 })}.${"s".repeat(43)}`;

describe("client-exposed-secrets", () => {
  it("flags secret-named public env vars in code and .env files, once per file", () => {
    const f = run([
      { path: "src/ai.ts", content: "const k = import.meta.env.VITE_OPENAI_API_KEY;\nconst again = import.meta.env.VITE_OPENAI_API_KEY;\n" },
      { path: ".env.local", content: "NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=x\nNEXT_PUBLIC_SUPABASE_URL=y\n" },
    ]);
    expect(f.map((x) => [x.title, x.line])).toEqual([
      ["VITE_OPENAI_API_KEY is bundled into the browser", 1],
      ["NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY is bundled into the browser", 1],
    ]);
  });

  it("leaves keys that are public by design alone", () => {
    const content = [
      "import.meta.env.VITE_SUPABASE_ANON_KEY",
      "process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY",
      "process.env.REACT_APP_FIREBASE_API_KEY",
      "process.env.OPENAI_API_KEY",
    ].join("\n");
    expect(run([{ path: "src/config.ts", content }])).toEqual([]);
  });

  it("flags dangerouslyAllowBrowser", () => {
    const f = run([{ path: "src/chat.tsx", content: "new OpenAI({ apiKey, dangerouslyAllowBrowser: true });" }]);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ severity: "critical", title: "AI SDK is allowed to run in the browser" });
  });

  it("flags a service_role JWT without echoing it, and ignores an anon JWT", () => {
    const content = `const admin = "${jwt("service_role")}";\nconst anon = "${jwt("anon")}";\n`;
    const f = run([{ path: "src/db.ts", content }]);
    expect(f).toHaveLength(1);
    expect(f[0]).toMatchObject({ title: "Supabase service_role key is in the source", line: 1 });
    expect(JSON.stringify(f)).not.toContain(jwt("service_role"));
  });

  it("flags model API calls from browser files only", () => {
    const call = 'fetch("https://api.openai.com/v1/chat/completions", { method: "POST" });';
    expect(run([{ path: "src/Chat.tsx", content: call }])).toHaveLength(1);
    expect(run([{ path: "src/page.ts", content: `"use client";\n${call}` }])[0]).toMatchObject({ severity: "high", line: 2 });
    expect(run([{ path: "server/chat.ts", content: call }])).toEqual([]);
    expect(run([{ path: "src/node-only.ts", content: call }])).toEqual([]);
  });

  it("skips tests and build output", () => {
    const content = "import.meta.env.VITE_OPENAI_API_KEY; dangerouslyAllowBrowser: true";
    expect(run([{ path: "src/a.test.ts", content }, { path: "dist/assets/index.js", content }])).toEqual([]);
  });
});
