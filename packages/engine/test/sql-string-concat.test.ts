import { describe, expect, it } from "vitest";
import { sqlStringConcat } from "../src/checks/sql-string-concat";
import type { RepoSnapshot } from "../src/types";

const VULN = `const express = require('express');
const app = express();
const db = require('./db');
app.get('/search', (req, res) => {
  const rows = db.all("SELECT * FROM users WHERE name = " + req.query.name, (err, rows) => res.json(rows));
  const order = db.prepare(\`SELECT * FROM orders WHERE id = \${req.params.id}\`).get();
});
app.listen(3000);
`;

const CLEAN = `const express = require('express');
const app = express();
const db = require('./db');
app.get('/search', (req, res) => {
  const rows = db.all("SELECT * FROM users WHERE name = ?", [req.query.name], (err, rows) => res.json(rows));
  db.prepare('SELECT * FROM orders WHERE id = ?').all((row) => res.json(row));
  const cache = new Map();
  cache.get('recent-searches');
});
app.listen(3000);
`;

const vuln: RepoSnapshot = { name: "vuln", files: [{ path: "server.js", content: VULN }] };
const clean: RepoSnapshot = { name: "clean", files: [{ path: "server.js", content: CLEAN }] };

describe("sql-string-concat", () => {
  it("flags '+' concatenation and template-literal SQL, with a parameterised rewrite", async () => {
    const f = await sqlStringConcat.detect({ repo: vuln });
    expect(f).toHaveLength(2);
    expect(f[0]).toMatchObject({ checkId: "sql-string-concat", severity: "critical", file: "server.js", line: 5 });
    expect(f[0].evidence).toContain(`db.all("SELECT * FROM users WHERE name = " + req.query.name`);
    expect(f[0].explanation).toContain(`Rewrite as db.all("SELECT * FROM users WHERE name = ?", req.query.name`);

    expect(f[1].line).toBe(6);
    expect(f[1].explanation).toContain(`Rewrite as db.prepare("SELECT * FROM orders WHERE id = ?", req.params.id)`);
  });

  it("passes on parameterised queries and non-SQL calls", async () => {
    expect(await sqlStringConcat.detect({ repo: clean })).toEqual([]);
  });

  it("is report-only: it declares the mode and ships no fixer", () => {
    expect(sqlStringConcat.mode).toBe("report");
    expect(sqlStringConcat.fix).toBeUndefined();
  });

  it("ignores URLs that only contain SQL words", async () => {
    const content = `axios.get('/api/update/' + id);\nhttp.get('/api/where-to-buy/' + id);\nclient.get("https://x.test/delete?id=" + id);\ncache.get('update-' + key);\n`;
    expect(await sqlStringConcat.detect({ repo: { name: "u", files: [{ path: "client.js", content }] } })).toEqual([]);
  });

  it("drops the quotes around a value spliced into a quoted SQL literal", async () => {
    const content = `db.all("SELECT * FROM users WHERE name = '" + name + "'");\n`;
    const f = await sqlStringConcat.detect({ repo: { name: "q", files: [{ path: "db.js", content }] } });
    expect(f).toHaveLength(1);
    expect(f[0].explanation).toContain(`Rewrite as db.all("SELECT * FROM users WHERE name = ?", name)`);
  });
});
