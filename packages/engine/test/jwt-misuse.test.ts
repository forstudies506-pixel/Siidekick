import { describe, expect, it } from "vitest";
import { jwtMisuse } from "../src/checks/jwt-misuse";
import { guardPatch } from "../src/diffGuard";
import type { Finding, Patch, RepoFile } from "../src/types";

const repoOf = (files: RepoFile[]) => ({ name: "t", files });
const detect = (files: RepoFile[]) => jwtMisuse.detect({ repo: repoOf(files) }) as Finding[];
const titles = (path: string, content: string) => detect([{ path, content }]).map((f) => [f.title, f.severity, f.line]);

describe("jwt-misuse", () => {
  it("flags decode without verify, and not when the file verifies", () => {
    const decodeOnly = 'const jwt = require("jsonwebtoken");\nconst user = jwt.decode(req.headers.authorization);\n';
    expect(titles("src/auth.js", decodeOnly)).toEqual([["Token is decoded but never verified", "high", 2]]);
    const both = `${decodeOnly}jwt.verify(token, process.env.JWT_SECRET);\n`;
    expect(titles("src/auth.js", both)).toEqual([]);
  });

  it("ignores files that do not use a JWT library", () => {
    expect(titles("src/ui.ts", "const user = jwt.decode(token); algorithms: ['none']")).toEqual([]);
  });

  it("flags alg none, literal secrets and env fallbacks without echoing the secret", () => {
    const content = [
      'import jwt from "jsonwebtoken";',
      'jwt.verify(token, key, { algorithms: ["HS256", "none"] });',
      'const t = jwt.sign({ id }, "supersecretvalue123");',
      'const key = process.env.JWT_SECRET || "fallback-dev-secret";',
      "jwt.sign({ id }, key, { expiresIn: '15m' });",
    ].join("\n");
    const f = detect([{ path: "server/token.ts", content }]);
    expect(f.map((x) => [x.title, x.severity, x.line])).toEqual([
      ["Unsigned tokens (alg none) are accepted", "critical", 2],
      ["JWT secret is written in the code", "critical", 3],
      ["JWT secret falls back to a value in the code", "high", 4],
    ]);
    const text = JSON.stringify(f);
    expect(text).not.toContain("supersecretvalue123");
    expect(text).not.toContain("fallback-dev-secret");
  });

  it("flags PyJWT with signature or expiry checks turned off", () => {
    const content = [
      "import jwt",
      'claims = jwt.decode(token, options={"verify_signature": False})',
      'claims = jwt.decode(token, KEY, algorithms=["HS256"], options={"verify_exp": False})',
      'SECRET = os.getenv("JWT_SECRET", "changeme-later")',
    ].join("\n");
    expect(titles("app/auth.py", content)).toEqual([
      ["Token signature is not checked", "critical", 2],
      ["Expired tokens are accepted", "high", 3],
      ["JWT secret falls back to a value in the code", "high", 4],
    ]);
  });

  it("fixes ignoreExpiration within the diff guard, and the rescan is clean", () => {
    const content = 'import jwt from "jsonwebtoken";\nexport const check = (t: string) => jwt.verify(t, process.env.JWT_SECRET!, { ignoreExpiration: true });\n';
    const files = [{ path: "src/mw.ts", content }];
    expect(titles("src/mw.ts", content)).toEqual([["Expired tokens are accepted", "high", 2]]);
    const patch = jwtMisuse.fix!({ repo: repoOf(files) }, []) as Patch;
    expect(guardPatch(repoOf(files), patch).ok).toBe(true);
    const after = (patch.edits[0] as { after: string }).after;
    expect(after).toContain("ignoreExpiration: false");
    expect(detect([{ path: "src/mw.ts", content: after }])).toEqual([]);
  });

  it("has no fix when nothing can be fixed safely, and skips tests", () => {
    const content = 'const jwt = require("jsonwebtoken");\njwt.decode(t);\n';
    expect(jwtMisuse.fix!({ repo: repoOf([{ path: "a.js", content }]) }, [])).toBeNull();
    expect(detect([{ path: "test/a.test.js", content }])).toEqual([]);
  });
});
