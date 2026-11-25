"""Threat view of a project, using this definition:

    A vulnerability is
      1. WAY IN       - an entry point through which an attacker can get access,
      2. WAY OUT      - a path through which data or information can leak,
      3. RUN CODE     - a route through which malware or a virus can attack the server.

This module
  * maps every entry point (routes, API handlers, serverless functions, PHP pages, forms, uploads),
  * adds checks the line rules cannot see (public endpoints with no rate limit, third-party
    scripts without integrity hashes, missing deployment headers, file uploads, install-time
    code, logging of secrets, server version disclosure),
  * sorts every finding into one or more of the three groups.
"""
import json
import os
import re

from . import scan as scanner

WAY_IN, WAY_OUT, RUN_CODE = "way_in", "way_out", "run_code"
GROUP_TITLE = {
    WAY_IN: "Ways in: an attacker can get access",
    WAY_OUT: "Ways out: data or information can leak",
    RUN_CODE: "Ways to run code: malware or a virus can attack the server",
}

# Which groups each weakness (CWE) belongs to. A finding can be in several groups.
CWE_GROUPS = {
    "CWE-306": {WAY_IN}, "CWE-307": {WAY_IN}, "CWE-287": {WAY_IN}, "CWE-347": {WAY_IN},
    "CWE-352": {WAY_IN}, "CWE-770": {WAY_IN}, "CWE-693": {WAY_IN, WAY_OUT},
    "CWE-798": {WAY_IN, WAY_OUT}, "CWE-1004": {WAY_IN, WAY_OUT}, "CWE-942": {WAY_IN, WAY_OUT},
    "CWE-79": {WAY_IN, WAY_OUT}, "CWE-89": {WAY_IN, WAY_OUT, RUN_CODE}, "CWE-22": {WAY_IN, WAY_OUT},
    "CWE-538": {WAY_OUT}, "CWE-209": {WAY_OUT}, "CWE-200": {WAY_OUT}, "CWE-319": {WAY_OUT},
    "CWE-922": {WAY_OUT}, "CWE-328": {WAY_OUT}, "CWE-295": {WAY_OUT}, "CWE-338": {WAY_IN},
    "CWE-497": {WAY_OUT}, "CWE-532": {WAY_OUT}, "CWE-1327": {WAY_IN},
    "CWE-78": {RUN_CODE}, "CWE-95": {RUN_CODE}, "CWE-502": {RUN_CODE}, "CWE-98": {RUN_CODE},
    "CWE-434": {RUN_CODE}, "CWE-494": {RUN_CODE}, "CWE-829": {RUN_CODE, WAY_OUT},
    "CWE-1395": {RUN_CODE, WAY_IN, WAY_OUT}, "CWE-489": {RUN_CODE, WAY_OUT},
}
PROJECT_GROUPS = {"PRJ-NO-README": set(), "PRJ-NO-CI": set(), "PRJ-NO-TESTS": set()}

AUTH_HINT = re.compile(r"(?i)auth|login_required|jwt_required|requireAdmin|requireUser|isAuthenticated|verifyToken|protect\b|ensureLoggedIn|passport\.authenticate|Depends\(.*(user|auth)")
RATE_HINT = re.compile(r"(?i)rateLimit|rate-limit|rate_limit|limiter|slowapi|flask_limiter|throttle")
INPUT_METHODS = {"POST", "PUT", "PATCH", "DELETE", "ALL", "ANY"}


def _finding(rid, sev, cwe, title, explain, fix, file="(project)", line=0, snippet="", groups=None):
    return dict(preset_groups=groups, id=f"{rid}:{file}:{line}", rule=rid, title=title, severity=sev, cwe=cwe, owasp="",
                file=file, line=line, snippet=snippet[:200], explain=explain, fix=fix,
                fixer=None, mode="report", source="threats")


# ---------------- entry-point map ----------------

def find_entry_points(root, files, texts):
    eps = []

    def add(kind, method, path, rel, line, ctx, takes_input=None):
        method = method.upper()
        eps.append(dict(kind=kind, method=method, path=path, file=rel, line=line,
                        auth=bool(AUTH_HINT.search(ctx)),
                        takes_input=takes_input if takes_input is not None else method in INPUT_METHODS))

    for rel in files:
        text = texts[rel]
        lines = text.splitlines()
        ext = os.path.splitext(rel)[1].lower()
        if ext in (".js", ".ts", ".mjs", ".cjs"):
            for i, l in enumerate(lines, 1):
                m = re.search(r"""\b(app|router|server)\.(get|post|put|patch|delete|all)\(\s*['"`]([^'"`]+)""", l)
                if m:
                    takes = m.group(2).upper() in INPUT_METHODS or bool(re.search(r"req\.(query|params|body|files?)", "\n".join(lines[i - 1:i + 8])))
                    add("express route", m.group(2), m.group(3), rel, i, l, takes)
        elif ext == ".py":
            for i, l in enumerate(lines, 1):
                m = re.search(r"""@(\w+)\.(route|get|post|put|patch|delete)\(\s*['"]([^'"]+)['"](.*)""", l)
                if m:
                    meth = m.group(2)
                    if meth == "route":
                        mm = re.search(r"methods\s*=\s*\[([^\]]*)\]", m.group(4))
                        meth = ",".join(x.strip(" '\"") for x in mm.group(1).split(",")) if mm else "GET"
                    ctx = "\n".join(lines[max(0, i - 4):i + 2])
                    body = "\n".join(lines[i:i + 15])
                    takes = any(x in meth.upper() for x in INPUT_METHODS) or bool(re.search(r"request\.(args|form|json|files|get_json|values)", body))
                    add("python route", meth, m.group(3), rel, i, ctx, takes)
            for m in re.finditer(r"^(\s*)def do_(GET|POST|PUT|PATCH|DELETE)\b.*$", text, re.M):
                indent, meth = m.group(1), m.group(2)
                rest = text[m.end():]
                nxt = re.search(rf"^{indent}(def |@)", rest, re.M)
                body = rest[:nxt.start()] if nxt else rest
                paths = sorted(set(re.findall(r"""path\s*(?:==|!=)\s*["'](/[^"']*)["']""", body)))
                takes = bool(re.search(r"rfile|_read_json|parse_qs|query", body))
                hl = text[:m.start()].count("\n") + 1
                for pth in paths or ["(any path)"]:
                    add("python http.server handler", meth, pth, rel, hl, body, takes)
        elif ext == ".php":
            if re.search(r"\$_(GET|POST|REQUEST|COOKIE|FILES)", text):
                add("php page", "ANY", "/" + rel, rel, 1, text[:2000], True)
        elif ext in (".html", ".htm"):
            for m in re.finditer(r"<form\b[^>]*>", text, re.I | re.S):
                line = text[:m.start()].count("\n") + 1
                action = re.search(r"""action=["']([^"']*)""", m.group(0))
                method = re.search(r"""method=["']([^"']*)""", m.group(0))
                add("html form", method.group(1) if method else "GET", action.group(1) if action else "(same page)", rel, line, "", True)
        if rel.startswith("api/") and ext in (".py", ".js", ".ts"):
            reads = bool(re.search(r"rfile|request\.|req\.(body|query)|_read_json|json\(\)", text))
            add("serverless function" + ("" if reads else " (reuses a handler above)"), "ANY",
                "/" + os.path.splitext(rel)[0], rel, 1, text, reads)
    return eps


# ---------------- extra checks the line rules cannot see ----------------

def extra_checks(root, files, texts, eps):
    out = []
    alltext = "\n".join(texts.values())
    has_rate = bool(RATE_HINT.search(alltext))

    seen_paths = set()
    for ep in eps:
        key = (ep["path"], ep["method"])
        if (ep["takes_input"] and not ep["auth"] and not has_rate and key not in seen_paths
                and ep["kind"] != "html form" and ep["method"] in INPUT_METHODS
                and not re.search(r"(?i)login|signin|signup|register|reset", ep["path"])):
            seen_paths.add(key)
            out.append(_finding("TH-PUBLIC-NO-LIMIT", "medium", "CWE-770",
                                f"Public endpoint {ep['method']} {ep['path']} accepts input with no rate limit",
                                "Anyone on the internet can call this as often as they like. Bots can guess passwords, flood it, or run up your hosting bill and take the site down.",
                                "Add a rate limit (app middleware, or your host's firewall such as Vercel Firewall or AWS WAF) and require login if the data is private.",
                                ep["file"], ep["line"]))

    for rel in files:
        text, ext = texts[rel], os.path.splitext(rel)[1].lower()
        lines = text.splitlines()
        if ext in (".html", ".htm"):
            for m in re.finditer(r"<(script|link)\b[^>]*>", text, re.I | re.S):
                tag = m.group(0)
                src = re.search(r"""(?:src|href)=["'](https?://[^"']+)""", tag)
                if not src or "integrity=" in tag:
                    continue
                if m.group(1).lower() == "link" and "stylesheet" not in tag:
                    continue
                if "fonts.googleapis.com" in src.group(1):
                    continue  # generated per browser, cannot carry a fixed hash
                line = text[:m.start()].count("\n") + 1
                host = re.sub(r"https?://([^/]+).*", r"\1", src.group(1))
                is_script = m.group(1).lower() == "script"
                out.append(_finding("TH-NO-SRI", "high" if is_script else "low", "CWE-829",
                                    f"{'Script' if is_script else 'Stylesheet'} from {host} loaded without an integrity hash",
                                    ("If that site is hacked, the attacker's code runs inside your page and can steal what visitors type." if is_script
                                     else "If that site is hacked or changes the file, it can alter your page or track visitors."),
                                    "Host the file yourself, or add an integrity=\"sha384-...\" hash with crossorigin=\"anonymous\".",
                                    rel, line, tag.replace("\n", " "), None if is_script else [WAY_OUT]))
        for i, l in enumerate(lines, 1):
            s = l.strip()
            if s.startswith(("#", "//")):
                continue
            if re.search(r"""\bmulter\(""", l) and not re.search(r"fileFilter|limits", "\n".join(lines[i - 1:i + 6])):
                out.append(_finding("TH-UPLOAD", "high", "CWE-434", "File upload with no type or size check",
                                    "An attacker can upload a script or malware and, if it is served or run, take over the server.",
                                    "Set limits.fileSize and a fileFilter allow-list, store uploads outside the web root (for example a private S3 bucket) and give them random names.",
                                    rel, i, l))
            if re.search(r"request\.files", l) or (re.search(r"\.save\(", l) and "request.files" in text and "secure_filename" not in text):
                if re.search(r"\.save\(", l) and "secure_filename" not in text:
                    out.append(_finding("TH-UPLOAD", "high", "CWE-434", "Uploaded file saved with its original name",
                                        "A name like ../../app.py can overwrite your code, and uploaded scripts may be run.",
                                        "Use secure_filename, check the type and size, and save outside the code folder.", rel, i, l))
            if re.search(r"move_uploaded_file\(", l):
                out.append(_finding("TH-UPLOAD", "high", "CWE-434", "PHP file upload",
                                    "Uploaded .php files in a web folder can be run by visiting them.",
                                    "Check the type, rename with a random name and extension allow-list, and store outside the web root.", rel, i, l))
            if re.search(r"""(curl|wget)[^|\n]*\|\s*(sudo\s+)?(sh|bash)\b""", l):
                out.append(_finding("TH-PIPE-SHELL", "high", "CWE-494", "Script downloaded and run straight from the internet",
                                    "Whoever controls that URL controls your server or build machine.",
                                    "Download the file, check its hash or signature, then run it.", rel, i, l))
            if re.search(r"""(?i)(console\.(log|info|debug)|print|logger\.\w+|logging\.\w+)\(.*\b(password|passwd|secret|token|api_?key)\b""", l):
                out.append(_finding("TH-LOG-SECRET", "medium", "CWE-532", "Password, token or key written to the logs",
                                    "Logs are copied to many places and read by many people; secrets in them leak.",
                                    "Log the event, never the value.", rel, i, l))
        if os.path.basename(rel) == "package.json":
            try:
                scripts = json.loads(text).get("scripts", {})
            except ValueError:
                scripts = {}
            for k in ("preinstall", "install", "postinstall"):
                if k in scripts:
                    line = next((i for i, l in enumerate(lines, 1) if f'"{k}"' in l), 0)
                    out.append(_finding("TH-INSTALL-SCRIPT", "low", "CWE-829", f"Code runs automatically on npm install ({k})",
                                        "Install scripts run with your user's rights on every machine that installs the project.",
                                        "Make sure the script is yours and needed; run installs in CI with --ignore-scripts where possible.",
                                        rel, line, f'"{k}": "{scripts[k]}"'))
        if ext == ".py" and re.search(r"\.run\(", text) and "Flask(" in text and not re.search(r"gunicorn|waitress|uwsgi", alltext):
            line = next((i for i, l in enumerate(lines, 1) if re.search(r"app\.run\(", l)), 0)
            if line:
                out.append(_finding("TH-DEV-SERVER", "low", "CWE-497", "Flask development server used to serve the app",
                                    "Flask's built-in server is for development: it reveals its version and is not hardened for public traffic.",
                                    "Run with gunicorn or waitress when the app is shared or deployed.", rel, line))
        if ext == ".py" and "BaseHTTPRequestHandler" in text and "sys_version" not in text:
            line = next((i for i, l in enumerate(lines, 1) if "BaseHTTPRequestHandler)" in l), 0)
            out.append(_finding("TH-VERSION", "low", "CWE-497", "Server header reveals the Python version",
                                "Attackers use exact versions to pick known exploits.",
                                'Set sys_version = "" and a plain server_version on the handler class.', rel, line))

    vercel = next((f for f in files if os.path.basename(f) == "vercel.json"), None)
    if vercel and '"headers"' not in texts[vercel]:
        out.append(_finding("TH-DEPLOY-HEADERS", "low", "CWE-693", "Deployed pages have no security headers",
                            "Without Content-Security-Policy and frame-ancestors, other sites can frame your pages (clickjacking) and injected scripts are not limited.",
                            "Add a headers block to vercel.json: Content-Security-Policy, X-Frame-Options or frame-ancestors, Referrer-Policy, Permissions-Policy.",
                            vercel, 1))
    return out


def classify(f):
    if f.get("preset_groups"):
        return sorted(f["preset_groups"])
    if f["rule"] in PROJECT_GROUPS:
        return sorted(PROJECT_GROUPS[f["rule"]])
    groups = set()
    for c in re.findall(r"CWE-\d+", f.get("cwe", "")):
        groups |= CWE_GROUPS.get(c, set())
    if not groups and f["rule"].startswith(("SEC-", "GITLEAKS")):
        groups = {WAY_IN, WAY_OUT}
    if not groups and f["rule"].startswith(("DEP-", "NPM-")):
        groups = {RUN_CODE, WAY_IN, WAY_OUT}
    return sorted(groups) or [WAY_OUT]


def analyse(root, use_external=True):
    base = scanner.scan(root, use_external)
    files = sorted(scanner.iter_files(base["root"]))
    texts = {f: scanner.read_text(base["root"], f) for f in files}
    eps = find_entry_points(base["root"], files, texts)
    findings = scanner.dedupe(base["findings"] + extra_checks(base["root"], files, texts, eps))
    rank = {s: i for i, s in enumerate(scanner.SEVERITY_ORDER)}
    findings.sort(key=lambda f: (rank.get(f["severity"], 9), f["file"], f["line"]))
    groups = {WAY_IN: [], WAY_OUT: [], RUN_CODE: []}
    hygiene = []
    for f in findings:
        f["groups"] = classify(f)
        if not f["groups"]:
            hygiene.append(f)
        for g in f["groups"]:
            groups[g].append(f)
    vulns = [f for f in findings if f["groups"]]
    counts = {s: sum(1 for f in vulns if f["severity"] == s) for s in scanner.SEVERITY_ORDER}
    return dict(root=base["root"], files_scanned=base["files_scanned"], tools_used=base["tools_used"],
                tools_skipped=base["tools_skipped"], entry_points=eps, groups=groups, hygiene=hygiene,
                vulnerabilities=vulns, counts=counts, score=scanner.score(vulns))


def to_markdown(res):
    name = os.path.basename(res["root"])
    eps = res["entry_points"]
    out = [f"# Vulnerability report: {name}", "",
           "A vulnerability is (1) a way in for an attacker, (2) a way for data to leak out, or "
           "(3) a way for malware or a virus to run code on the server.", "",
           f"**Score {res['score']}/100** · {len(res['vulnerabilities'])} vulnerabilities · "
           + " · ".join(f"{v} {k}" for k, v in res["counts"].items() if v), "",
           f"## Attack surface: {len(eps)} entry points", "",
           "| Method | Path | Kind | Login check | Takes input | Where |", "| --- | --- | --- | --- | --- | --- |"]
    for e in eps:
        out.append(f"| {e['method']} | `{e['path']}` | {e['kind']} | {'yes' if e['auth'] else 'no'} | "
                   f"{'yes' if e['takes_input'] else 'no'} | `{e['file']}:{e['line']}` |")
    for g in (WAY_IN, WAY_OUT, RUN_CODE):
        items = res["groups"][g]
        out += ["", f"## {GROUP_TITLE[g]} ({len(items)})", ""]
        if not items:
            out.append("None found.")
            continue
        out += ["| Severity | Problem | Where | Fix |", "| --- | --- | --- | --- |"]
        for f in items:
            loc = f["file"] + (f":{f['line']}" if f["line"] else "")
            out.append(f"| {f['severity']} | **{f['title']}** ({f['cwe']}). {f['explain']} | `{loc}` | {f['fix']} |")
    if res["hygiene"]:
        out += ["", "## Good practice (not vulnerabilities)", ""] + [f"- {f['title']}: {f['fix']}" for f in res["hygiene"]]
    out += ["", f"_Tools: {', '.join(res['tools_used'])}"
            + (f". Skipped: {'; '.join(res['tools_skipped'])}" if res["tools_skipped"] else "") + "._"]
    return "\n".join(out) + "\n"


# ---------------- exit points: everywhere data leaves the app ----------------

EXIT_RULES = [
    # (kind, regex, what leaves, extensions or None for all)
    ("outbound network call", r"""\b(fetch|axios\.\w+|axios)\(\s*[`'"]?(https?://[^'"`\s)]+)?|requests\.(get|post|put|delete|patch)\(|urllib\.request\.urlopen\(|http\.request\(|https\.request\(|httpx\.\w+\(""",
     "data sent to another server", (".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx", ".py", ".html")),
    ("email or message sent", r"""smtplib|sendmail\(|nodemailer|sgMail\.send|twilio|\.send_message\(""", "data sent by email or SMS", None),
    ("file written", r"""open\([^)]*['"][wa]b?\+?['"]|fs\.(writeFile|appendFile|createWriteStream)|\.to_csv\(|\.to_json\(|(?<!ctx)(?<!context)\.save\((?!\))|json\.dump\(|pickle\.dump\(""",
     "data written to disk", (".js", ".ts", ".mjs", ".cjs", ".py")),
    ("log output", r"""\bconsole\.(log|info|warn|error|debug)\(|\blogging\.\w+\(|\blogger\.\w+\(|^\s*print\(""",
     "data written to logs or the terminal", (".js", ".ts", ".mjs", ".cjs", ".py")),
    ("browser download", r"""URL\.createObjectURL|\.download\s*=|Content-Disposition""", "data handed to the user as a file", None),
    ("browser storage", r"""localStorage\.setItem|sessionStorage\.setItem|document\.cookie\s*=|indexedDB""", "data kept in the visitor's browser", (".js", ".ts", ".jsx", ".tsx", ".html")),
    ("database write", r"""\b(INSERT|UPDATE|DELETE)\s+(INTO|FROM|\w+\s+SET)\b|\.(insert_one|insert_many|update_one|create|save)\(|\.commit\(\)""", "data stored in a database", (".js", ".ts", ".py", ".php")),
]
EXIT_RX = [(k, re.compile(rx, re.M), what, exts) for k, rx, what, exts in EXIT_RULES]


def find_exit_points(root, files, texts, entry_points):
    exits = []
    # every endpoint that answers is an exit: its response leaves the server
    for e in entry_points:
        if e["kind"] != "html form" and "reuses" not in e["kind"]:
            exits.append(dict(kind="API / page response", target=f"{e['method']} {e['path']}",
                              what="response sent to whoever calls it" + ("" if e["auth"] else " (no login required)"),
                              file=e["file"], line=e["line"], external=not e["auth"]))
    for rel in files:
        text = texts[rel]
        ext = os.path.splitext(rel)[1].lower()
        if ext in (".md", ".txt", ".csv", ".json") and os.path.basename(rel) != "vercel.json":
            continue
        if re.search(r"(^|/)(tests?|__tests__|spec)/|\.(test|spec)\.", rel):
            continue
        for i, l in enumerate(text.splitlines(), 1):
            s = l.strip()
            if s.startswith(("#", "//", "*")):
                continue
            for kind, rx, what, exts in EXIT_RX:
                if exts and ext not in exts:
                    continue
                m = rx.search(l)
                if m:
                    url = re.search(r"https?://[\w.-]+", l)
                    host = url.group(0).split("//")[1] if url else ""
                    exits.append(dict(kind=kind, target=host or s[:60], what=what, file=rel, line=i,
                                      external=bool(host) and not host.startswith(("localhost", "127.0.0.1"))))
                    break
        if ext in (".html", ".htm"):
            for m in re.finditer(r"""<(script|link|img|iframe|video|source)\b[^>]*(?:src|href)=["'](https?://[^/"']+)""", text, re.I):
                line = text[:m.start()].count("\n") + 1
                exits.append(dict(kind="third-party request from the browser", target=m.group(2).split("//")[1],
                                  what="each visitor's IP address and browser details go to this site", file=rel, line=line, external=True))
    seen, out = set(), []
    for x in exits:
        k = (x["kind"], x["target"], x["file"])
        if k not in seen:
            seen.add(k)
            out.append(x)
    return out
