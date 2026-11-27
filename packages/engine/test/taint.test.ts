import { describe, expect, it } from "vitest";
import { analyseRepo, type FlowCategory } from "../src/analysis/taint.js";
import type { RepoSnapshot } from "../src/types.js";

function repo(files: Record<string, string>): RepoSnapshot {
  return { name: "t", files: Object.entries(files).map(([path, content]) => ({ path, content })) };
}

function cats(files: Record<string, string>): FlowCategory[] {
  return analyseRepo(repo(files)).flows.map((f) => f.category);
}

const express = `const express = require("express");\nconst app = express();\n`;

describe("taint analysis: sources reach sinks", () => {
  it("finds command injection through a variable and a template string", () => {
    const src = `${express}const { exec } = require("child_process");
app.get("/ping", (req, res) => {
  const host = req.query.host;
  exec(\`ping -c 1 \${host}\`, (e, out) => res.send(out));
});`;
    const flows = analyseRepo(repo({ "server.js": src })).flows;
    expect(flows).toHaveLength(1);
    expect(flows[0]).toMatchObject({ category: "command", file: "server.js", line: 6, source: "req.query.host", sourceLine: 5 });
  });

  it("does not flag spawn with a fixed program and argument array", () => {
    const src = `${express}const cp = require("node:child_process");
app.get("/x", (req, res) => { cp.spawn("ping", ["-c", "1", req.query.host]); });`;
    expect(cats({ "a.js": src })).toEqual([]);
  });

  it("flags spawn with shell: true", () => {
    const src = `${express}import { spawn } from "child_process";
app.get("/x", (req, res) => { spawn("ping", [req.query.host], { shell: true }); });`;
    expect(cats({ "a.mjs": src })).toEqual(["command"]);
  });

  it("finds path traversal through path.join and respects path.basename", () => {
    const bad = `${express}const fs = require("fs"); const path = require("path");
app.get("/f", (req, res) => { res.send(fs.readFileSync(path.join(__dirname, "files", req.params.name))); });`;
    const good = `${express}const fs = require("fs"); const path = require("path");
app.get("/f", (req, res) => { res.send(fs.readFileSync(path.join(__dirname, "files", path.basename(req.params.name)))); });`;
    expect(cats({ "bad.js": bad })).toContain("path");
    expect(cats({ "good.js": good })).not.toContain("path");
  });

  it("finds res.sendFile without a root and accepts one with a root", () => {
    expect(cats({ "a.js": `${express}app.get("/d", (req, res) => res.sendFile(req.query.p));` })).toEqual(["path"]);
    expect(cats({ "a.js": `${express}app.get("/d", (req, res) => res.sendFile(req.query.p, { root: "public" }));` })).toEqual([]);
  });

  it("finds SSRF only when the host is not fixed", () => {
    const bad = `${express}const axios = require("axios");
app.get("/p", async (req, res) => { const r = await axios.get(req.query.url); res.json(r.data); });`;
    const fixedHost = `${express}
app.get("/p", async (req, res) => { const r = await fetch("https://api.example.com/items/" + req.query.id); res.json(await r.json()); });`;
    const hostOnly = `${express}
app.get("/p", async (req, res) => { const r = await fetch(\`https://\${req.query.host}/status\`); res.json(await r.json()); });`;
    expect(cats({ "a.js": bad })).toEqual(["ssrf"]);
    expect(cats({ "a.js": fixedHost })).toEqual([]);
    expect(cats({ "a.js": hostOnly })).toEqual(["ssrf"]);
  });

  it("finds open redirects and allows fixed relative paths", () => {
    expect(cats({ "a.js": `${express}app.get("/r", (req, res) => res.redirect(req.query.next));` })).toEqual(["redirect"]);
    expect(cats({ "a.js": `${express}app.get("/r", (req, res) => res.redirect("/orders/" + req.query.id));` })).toEqual([]);
    expect(cats({ "a.js": `${express}app.get("/r", (req, res) => res.redirect(302, req.query.next));` })).toEqual(["redirect"]);
  });

  it("finds reflected XSS but not JSON responses or escaped output", () => {
    expect(cats({ "a.js": `${express}app.get("/h", (req, res) => res.send("<h1>Hi " + req.query.name + "</h1>"));` })).toEqual(["xss"]);
    expect(cats({ "a.js": `${express}app.get("/h", (req, res) => res.json({ name: req.query.name }));` })).toEqual([]);
    expect(cats({ "a.js": `${express}const escapeHtml = require("escape-html");\napp.get("/h", (req, res) => res.send("<h1>" + escapeHtml(req.query.name) + "</h1>"));` })).toEqual([]);
    expect(cats({ "a.js": `${express}app.post("/h", (req, res) => res.send(req.body));` })).toEqual([]);
  });

  it("finds DOM XSS from the URL into innerHTML and JSX", () => {
    const dom = `const q = new URLSearchParams(location.search).get("q");\ndocument.getElementById("out").innerHTML = "You searched " + q;`;
    expect(cats({ "public/app.js": dom })).toEqual(["xss"]);
    const jsx = `export function P() { const h = window.location.hash; return <div dangerouslySetInnerHTML={{ __html: h }} />; }`;
    expect(cats({ "src/P.jsx": jsx })).toEqual(["xss"]);
  });

  it("finds SQL built from input and ignores parameterised queries", () => {
    const bad = `${express}const db = require("./db");
app.get("/u", async (req, res) => { const rows = await db.query("SELECT * FROM users WHERE id = " + req.params.id); res.json(rows); });`;
    const good = `${express}const db = require("./db");
app.get("/u", async (req, res) => { const rows = await db.query("SELECT * FROM users WHERE id = $1", [req.params.id]); res.json(rows); });`;
    const tagged = `${express}import { sql } from "./db";
app.get("/u", async (req, res) => { res.json(await sql\`SELECT * FROM users WHERE id = \${req.params.id}\`); });`;
    expect(cats({ "a.js": bad })).toEqual(["sql"]);
    expect(cats({ "a.js": good })).toEqual([]);
    expect(cats({ "a.mjs": tagged })).toEqual([]);
  });

  it("does not treat Map.get or RegExp.exec as SQL", () => {
    const src = `${express}const cache = new Map(); const re = /x/;
app.get("/c", (req, res) => { res.json({ a: cache.get(req.query.k), b: re.exec(req.query.k) }); });`;
    expect(cats({ "a.js": src })).toEqual([]);
  });

  it("finds NoSQL operator injection from a JSON body and accepts String()", () => {
    const bad = `const mongoose = require("mongoose"); const User = mongoose.model("User");
module.exports = async (req, res) => { const u = await User.findOne({ email: req.body.email, password: req.body.password }); res.json(!!u); };`;
    const good = `const mongoose = require("mongoose"); const User = mongoose.model("User");
module.exports = async (req, res) => { const u = await User.findOne({ email: String(req.body.email) }); res.json(!!u); };`;
    const params = `const mongoose = require("mongoose"); const User = mongoose.model("User");
module.exports = async (req, res) => { res.json(await User.find({ name: req.params.name })); };`;
    expect(cats({ "a.js": bad })).toEqual(["nosql"]);
    expect(cats({ "a.js": good })).toEqual([]);
    expect(cats({ "a.js": params })).toEqual([]);
  });

  it("finds code injection through eval, new Function and vm", () => {
    expect(cats({ "a.js": `${express}app.get("/e", (req, res) => res.json(eval(req.query.expr)));` })).toEqual(["code"]);
    expect(cats({ "a.js": `${express}app.get("/e", (req, res) => { const f = new Function("x", req.body.code); res.json(f(1)); });` })).toEqual(["code"]);
    expect(cats({ "a.js": `${express}const vm = require("vm");\napp.get("/e", (req, res) => res.json(vm.runInNewContext(req.query.c)));` })).toEqual(["code"]);
  });

  it("finds unsafe deserialisation and prototype pollution", () => {
    const ser = `${express}const serialize = require("node-serialize");\napp.post("/s", (req, res) => res.json(serialize.unserialize(req.cookies.profile)));`;
    expect(cats({ "a.js": ser })).toEqual(["deserialize"]);
    const merge = `${express}const _ = require("lodash");\nconst settings = {};\napp.post("/s", (req, res) => { _.merge(settings, req.body); res.json(settings); });`;
    expect(cats({ "a.js": merge })).toEqual(["prototype"]);
    const gadget = `${express}const store = {};\napp.post("/s", (req, res) => { store[req.body.a][req.body.b] = req.body.c; res.end(); });`;
    expect(cats({ "a.js": gadget })).toEqual(["prototype"]);
  });

  it("flags js-yaml load only on v3", () => {
    const src = `${express}const yaml = require("js-yaml");\napp.post("/y", (req, res) => res.json(yaml.load(req.body.doc)));`;
    expect(cats({ "a.js": src, "package.json": JSON.stringify({ dependencies: { "js-yaml": "^3.13.1" } }) })).toEqual(["deserialize"]);
    expect(cats({ "a.js": src, "package.json": JSON.stringify({ dependencies: { "js-yaml": "^4.1.0" } }) })).toEqual([]);
  });

  it("finds regex injection unless escaped", () => {
    expect(cats({ "a.js": `${express}app.get("/s", (req, res) => res.json(new RegExp(req.query.q).test("x")));` })).toEqual(["regex"]);
    expect(cats({ "a.js": `${express}const _ = require("lodash");\napp.get("/s", (req, res) => res.json(new RegExp(_.escapeRegExp(req.query.q)).test("x")));` })).toEqual([]);
  });

  it("drops taint through numbers, booleans and schema validation", () => {
    const src = `${express}const fs = require("fs"); const { z } = require("zod");
const Body = z.object({ id: z.number() });
app.get("/n", (req, res) => { const id = parseInt(req.query.id, 10); res.send(fs.readFileSync("/data/" + id)); });
app.post("/z", async (req, res) => { const User = require("mongoose").model("U"); res.json(await User.find(Body.parse(req.body))); });`;
    expect(cats({ "a.js": src })).toEqual([]);
  });
});

describe("taint analysis: following calls", () => {
  it("follows input into a helper in another file and reports the sink there", () => {
    const route = `${express}const db = require("../lib/db");
app.get("/u", async (req, res) => res.json(await db.findUser(req.query.name)));`;
    const lib = `const { Pool } = require("pg"); const pool = new Pool();
function findUser(name) {
  return pool.query("SELECT * FROM users WHERE name = '" + name + "'");
}
module.exports = { findUser };`;
    const flows = analyseRepo(repo({ "routes/users.js": route, "lib/db.js": lib })).flows;
    expect(flows).toHaveLength(1);
    expect(flows[0]).toMatchObject({ category: "sql", file: "lib/db.js", line: 3, source: "req.query.name", sourceFile: "routes/users.js" });
    expect(flows[0].via[0]).toMatch(/^findUser \(lib\/db\.js:2\)/);
  });

  it("follows a value returned from a helper", () => {
    const src = `${express}const { exec } = require("child_process");
function buildCmd(host) { return "ping " + host; }
app.get("/p", (req, res) => exec(buildCmd(req.query.h)));`;
    expect(cats({ "a.js": src })).toEqual(["command"]);
  });

  it("follows destructuring from req and from the Lambda event", () => {
    const express1 = `${express}const fs = require("fs");\napp.get("/f", (req, res) => { const { query } = req; res.send(fs.readFileSync(query.file)); });`;
    expect(cats({ "a.js": express1 })).toEqual(["path"]);
    const lambda = `const { execSync } = require("child_process");
exports.handler = async (event) => { const body = JSON.parse(event.body); execSync("convert " + body.file); return { statusCode: 200 }; };`;
    expect(cats({ "handler.js": lambda })).toEqual(["command"]);
  });

  it("reads TypeScript and skips tests, vendored and minified code", () => {
    const ts = `import express, { Request, Response } from "express";
import { exec } from "child_process";
const app = express();
app.get("/x", (req: Request, res: Response) => { const h = req.query.h as string; exec("ping " + h!); });`;
    expect(cats({ "src/app.ts": ts })).toEqual(["command"]);
    expect(cats({ "test/app.test.js": `require("child_process").exec(req.query.x);` })).toEqual([]);
    expect(cats({ "node_modules/x/index.js": `require("child_process").exec(req.query.x);` })).toEqual([]);
  });

  it("reports parse statistics", () => {
    const { stats } = analyseRepo(repo({ "a.js": "const x = 1;", "b.ts": "export function f(a: string) { return a; }" }));
    expect(stats.filesParsed).toBe(2);
    expect(stats.functionsSummarised).toBe(1);
  });
});
