"""Scanner: runs built-in rules plus Semgrep, Gitleaks and npm audit when installed."""
import fnmatch
import json
import os
import re
import shutil
import subprocess
import tempfile

from .rules import ADVISORIES, CODE_RULES, PLACEHOLDER, SECRET_RULES

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist", "build",
             ".next", "vendor", "siidekick-out", "coverage"}
SKIP_FILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock"}
TEXT_EXT = {".md", ".sh", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".php", ".html", ".htm",
            ".json", ".yml", ".yaml", ".env", ".txt", ".cfg", ".ini", ".toml", ".conf", ".rb", ".go", ".java"}
MAX_BYTES = 1_000_000
SEVERITY_WEIGHT = {"critical": 10, "high": 6, "medium": 3, "low": 1}
SEVERITY_ORDER = ["critical", "high", "medium", "low"]

for _r in CODE_RULES + SECRET_RULES:
    _r["rx"] = re.compile(_r["pattern"], re.MULTILINE)
_PLACEHOLDER_RX = re.compile(PLACEHOLDER)


def is_env_file(name):
    return name == ".env" or (name.startswith(".env.") and name not in (".env.example", ".env.sample", ".env.template"))


def iter_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if name in SKIP_FILES or name.endswith(".min.js"):
                continue
            ext = os.path.splitext(name)[1].lower()
            if ext not in TEXT_EXT and not is_env_file(name) and name != ".gitignore":
                continue
            full = os.path.join(dirpath, name)
            try:
                if os.path.getsize(full) > MAX_BYTES:
                    continue
            except OSError:
                continue
            yield os.path.relpath(full, root).replace(os.sep, "/")


def read_text(root, rel):
    with open(os.path.join(root, rel), encoding="utf-8", errors="ignore") as fh:
        return fh.read()


def mask(text, start, end):
    secret = text[start:end]
    keep = secret[:4] if len(secret) > 8 else secret[:1]
    return text[:start] + keep + "****" + text[end:]


def make_finding(rule, rel, lineno, line, source="builtin", snippet=None, **extra):
    f = dict(
        id=f"{rule['id']}:{rel}:{lineno}",
        rule=rule["id"], title=rule["title"], severity=rule["severity"],
        cwe=rule.get("cwe", ""), owasp=rule.get("owasp", ""),
        file=rel, line=lineno, snippet=(snippet if snippet is not None else line.strip())[:200],
        explain=rule.get("explain", ""), fix=rule.get("fix", ""),
        fixer=rule.get("fixer"), mode=rule.get("mode", "report"), source=source,
    )
    f.update(extra)
    return f


def gitignored_env(root):
    path = os.path.join(root, ".gitignore")
    if not os.path.exists(path):
        return False
    with open(path, encoding="utf-8", errors="ignore") as fh:
        pats = [p.strip().lstrip("/") for p in fh if p.strip() and not p.startswith("#")]
    return any(fnmatch.fnmatch(".env", p) for p in pats if not p.startswith("!"))


def scan_file(root, rel, text, env_ignored):
    findings = []
    ext = os.path.splitext(rel)[1].lower()
    name = os.path.basename(rel)
    lines = text.splitlines()
    for i, line in enumerate(lines, 1):
        if "siidekick-ignore" in line:
            continue
        stripped = line.strip()
        is_comment = stripped.startswith(("//", "#", "*", "/*", "<!--"))
        if not is_comment:
            for rule in CODE_RULES:
                if ext in rule["exts"]:
                    m = rule["rx"].search(line)
                    if m and rule.get("unless") and re.search(rule["unless"], line):
                        m = None
                    if m:
                        snip = None
                        if rule.get("mask_group") is not None:
                            s, e = m.span(rule["mask_group"])
                            snip = mask(line, s, e).strip()
                        findings.append(make_finding(rule, rel, i, line, snippet=snip))
        if is_env_file(name):
            continue  # .env files are handled below
        for rule in SECRET_RULES:
            m = rule["rx"].search(line)
            if not m:
                continue
            g = rule.get("mask_group")
            if rule["id"] == "SEC-GENERIC" and _PLACEHOLDER_RX.search(m.group(5)):
                continue
            snip = mask(line, *m.span(g)).strip() if g is not None else stripped[:40] + " ..."
            fixer = "secret_env" if (rule["id"] != "SEC-PRIVKEY" and ext in (".js", ".ts", ".mjs", ".cjs")) else None
            findings.append(make_finding(rule, rel, i, line, snippet=snip, fixer=fixer,
                                         mode="edit" if fixer else "report"))
    if is_env_file(name) and not env_ignored:
        for i, line in enumerate(lines, 1):
            m = re.match(r"\s*([A-Z0-9_]*(KEY|SECRET|PASSWORD|PASS|TOKEN)[A-Z0-9_]*)\s*=\s*(\S{4,})", line)
            if m:
                rule = dict(id="SEC-ENV-COMMITTED", severity="high", cwe="CWE-538",
                            owasp="A05 Security Misconfiguration",
                            title=f"Secret {m.group(1)} in a .env file that git will commit",
                            explain=".env is not listed in .gitignore, so this secret will be pushed to GitHub with the code.",
                            fix="Add .env to .gitignore, and rotate the secret if it was ever pushed.",
                            fixer=None, mode="auto")
                findings.append(make_finding(rule, rel, i, line, snippet=mask(line, *m.span(3)).strip()))
    return findings


# ---------------- project-level checks ----------------

def project_checks(root, files, texts, env_ignored):
    out = []
    js = [f for f in files if f.endswith((".js", ".mjs", ".cjs", ".ts"))]
    alltext = "\n".join(texts.get(f, "") for f in js)
    app_file = app_line = None
    for f in js:
        for i, line in enumerate(texts[f].splitlines(), 1):
            if re.search(r"""=\s*express\(\s*\)""", line):
                app_file, app_line = f, i
                break
        if app_file:
            break

    def pf(rid, sev, title, explain, fix, file="", line=0, cwe="", owasp="", fixer=None, mode="report"):
        rule = dict(id=rid, severity=sev, title=title, explain=explain, fix=fix, cwe=cwe,
                    owasp=owasp, fixer=fixer, mode=mode)
        return make_finding(rule, file or "(project)", line, "", snippet="")

    if app_file:
        if not re.search(r"\bhelmet\b", alltext):
            out.append(pf("PRJ-NO-HEADERS", "high", "Security headers are missing",
                          "Without headers such as Content-Security-Policy and HSTS, browsers give fewer protections against XSS, clickjacking and sniffing.",
                          "Add helmet as middleware.", app_file, app_line, "CWE-693", "A05 Security Misconfiguration",
                          "security_middleware", "auto"))
        login = None
        for f in js:
            for i, line in enumerate(texts[f].splitlines(), 1):
                if re.search(r"""\.(post|get)\(\s*['"`][^'"`]*(login|signin|auth|register|signup|reset)""", line, re.I):
                    login = (f, i)
                    break
            if login:
                break
        if login and not re.search(r"rateLimit|rate-limit|express-slow-down", alltext):
            out.append(pf("PRJ-NO-RATELIMIT", "high", "Login has no rate limit",
                          "An attacker can try thousands of passwords per minute against this login.",
                          "Limit login, signup and reset attempts per IP.", login[0], login[1], "CWE-307",
                          "A07 Identification and Authentication Failures", "security_middleware", "auto"))
        if "x-powered-by" not in alltext.lower() and not re.search(r"\bhelmet\b", alltext):
            pass  # covered by helmet finding
    has_env = any(is_env_file(os.path.basename(f)) for f in files)
    if has_env and not env_ignored:
        out.append(pf("PRJ-ENV-NOT-IGNORED", "high", ".env is not in .gitignore",
                      "Your secrets file will be uploaded to GitHub on the next push.",
                      "Add .env to .gitignore.", ".gitignore", 0, "CWE-538", "A05 Security Misconfiguration",
                      "gitignore_env", "auto"))
    lower = [f.lower() for f in files]
    if not any(f.startswith("readme") for f in lower):
        out.append(pf("PRJ-NO-README", "low", "No README", "Nobody, including future you, knows how to set up or deploy this.",
                      "Add a README covering setup, environment variables and deployment."))
    if not any(f.startswith(".github/workflows/") for f in lower):
        out.append(pf("PRJ-NO-CI", "low", "No CI pipeline", "Nothing checks the code automatically on each push.",
                      "Add a GitHub Actions workflow that runs tests and this scanner."))
    if not any(re.search(r"(^|/)(tests?|__tests__|spec)/|\.(test|spec)\.", f) for f in lower):
        out.append(pf("PRJ-NO-TESTS", "low", "No automated tests", "Fixes can break things without anyone noticing.",
                      "Add tests for login, validation and role checks."))
    return out


# ---------------- dependencies ----------------

def vtuple(v):
    m = re.search(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?", v or "")
    return tuple(int(x or 0) for x in m.groups()) if m else None


def dep_checks(root, files):
    out = []
    def flag(eco, name, ver, adv, file, line):
        if adv["fixed"] is None:
            fixtxt = f"Remove {name}; no fixed version exists."
        else:
            fixtxt = f"Upgrade {name} to {adv['fixed']} or later, then run your tests."
        rule = dict(id="DEP-VULN", severity=adv["severity"], cwe="CWE-1395", owasp="A06 Vulnerable and Outdated Components",
                    title=f"{name} {ver} has a known vulnerability ({adv['cve']})",
                    explain=f"This version is affected by {adv['summary']}.", fix=fixtxt, fixer=None, mode="report")
        out.append(make_finding(rule, file, line, "", snippet=f'"{name}": "{ver}"'))

    def check(eco, name, ver, file, line):
        v = vtuple(ver)
        if v is None:
            return
        for adv in ADVISORIES[eco]:
            if adv["name"] != name.lower():
                continue
            if adv.get("safe_from") and vtuple(adv["safe_from"]) <= v < vtuple(adv["safe_below"]):
                continue
            if adv["fixed"] is None or v < vtuple(adv["fixed"]):
                flag(eco, name, ver, adv, file, line)

    for rel in files:
        base = os.path.basename(rel)
        if base == "package.json":
            text = read_text(root, rel)
            try:
                pkg = json.loads(text)
            except ValueError:
                continue
            lock = {}
            lock_path = os.path.join(root, os.path.dirname(rel), "package-lock.json")
            if os.path.exists(lock_path):
                try:
                    lock = json.load(open(lock_path)).get("packages", {})
                except ValueError:
                    lock = {}
            for section in ("dependencies", "devDependencies"):
                for name, spec in (pkg.get(section) or {}).items():
                    ver = (lock.get(f"node_modules/{name}") or {}).get("version") or spec
                    line = next((i for i, l in enumerate(text.splitlines(), 1) if f'"{name}"' in l), 0)
                    check("npm", name, ver, rel, line)
        elif base == "requirements.txt":
            for i, line in enumerate(read_text(root, rel).splitlines(), 1):
                m = re.match(r"\s*([A-Za-z0-9_.-]+)\s*(==|>=|~=)\s*([\d.]+)", line)
                if m:
                    check("pypi", m.group(1), m.group(3), rel, i)
    return out


# ---------------- external tools (used when installed) ----------------

def run_external(root):
    findings, used, skipped = [], [], []
    sev_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    if shutil.which("semgrep"):
        try:
            p = subprocess.run(["semgrep", "scan", "--config", "auto", "--json", "--quiet", root],
                               capture_output=True, text=True, timeout=600)
            for r in json.loads(p.stdout or "{}").get("results", []):
                rule = dict(id="SEMGREP:" + r["check_id"].split(".")[-1], severity=sev_map.get(r["extra"].get("severity"), "medium"),
                            title=r["extra"].get("message", "")[:120], explain=r["extra"].get("message", ""),
                            fix="See the Semgrep rule for the recommended fix.",
                            cwe=",".join(r["extra"].get("metadata", {}).get("cwe", []))[:40] if isinstance(r["extra"].get("metadata", {}).get("cwe"), list) else "",
                            owasp="", fixer=None, mode="report")
                rel = os.path.relpath(r["path"], root)
                findings.append(make_finding(rule, rel, r["start"]["line"], r["extra"].get("lines", ""), source="semgrep"))
            used.append("semgrep")
        except Exception as exc:  # noqa: BLE001
            skipped.append(f"semgrep failed: {exc}")
    else:
        skipped.append("semgrep not installed")
    if shutil.which("gitleaks"):
        try:
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
                rp = tmp.name
            subprocess.run(["gitleaks", "detect", "--source", root, "--redact", "--no-banner",
                            "--report-format", "json", "--report-path", rp], capture_output=True, timeout=600)
            for r in json.load(open(rp)) or []:
                rule = dict(id="GITLEAKS:" + r.get("RuleID", ""), severity="critical", cwe="CWE-798",
                            owasp="A07 Identification and Authentication Failures",
                            title=r.get("Description", "Secret found"),
                            explain="Gitleaks found a secret in the code or git history (commit " + r.get("Commit", "")[:8] + ").",
                            fix="Remove it from the code and rotate the credential.", fixer=None, mode="report")
                findings.append(make_finding(rule, r.get("File", ""), r.get("StartLine", 0), "", source="gitleaks",
                                             snippet=r.get("Match", "")[:80]))
            used.append("gitleaks")
        except Exception as exc:  # noqa: BLE001
            skipped.append(f"gitleaks failed: {exc}")
    else:
        skipped.append("gitleaks not installed (git history not scanned)")
    if os.path.exists(os.path.join(root, "package-lock.json")) and shutil.which("npm"):
        try:
            p = subprocess.run(["npm", "audit", "--json"], cwd=root, capture_output=True, text=True, timeout=90)
            data = json.loads(p.stdout or "{}")
            if "vulnerabilities" in data:
                for name, v in data["vulnerabilities"].items():
                    rule = dict(id="NPM-AUDIT", severity=v.get("severity", "medium"), cwe="CWE-1395",
                                owasp="A06 Vulnerable and Outdated Components",
                                title=f"{name} has a known vulnerability (npm audit)",
                                explain=f"npm audit reports {v.get('severity')} issues in {name} {v.get('range', '')}.",
                                fix="Run npm audit fix, or upgrade as npm audit suggests.", fixer=None, mode="report")
                    findings.append(make_finding(rule, "package-lock.json", 0, "", source="npm-audit", snippet=name))
                used.append("npm audit")
            else:
                skipped.append("npm audit returned no data (offline?)")
        except Exception as exc:  # noqa: BLE001
            skipped.append(f"npm audit failed: {exc}")
    return findings, used, skipped


# ---------------- entry point ----------------

def score(findings):
    penalty = sum(SEVERITY_WEIGHT.get(f["severity"], 1) for f in findings)
    return round(100 * 40 / (40 + penalty))


def dedupe(findings):
    seen, out = {}, []
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    for f in sorted(findings, key=lambda f: rank.get(f["severity"], 9)):
        key = (f["file"], f["line"], f["cwe"] or f["rule"]) if f["line"] else (f["rule"], f["file"], f["title"])
        if key in seen:
            continue
        seen[key] = True
        out.append(f)
    return out


def scan(root, use_external=True):
    root = os.path.abspath(root)
    files = sorted(iter_files(root))
    texts = {f: read_text(root, f) for f in files}
    env_ignored = gitignored_env(root)
    findings = []
    for f in files:
        findings += scan_file(root, f, texts[f], env_ignored)
    findings += project_checks(root, files, texts, env_ignored)
    findings += dep_checks(root, files)
    used, skipped = ["siidekick built-in rules"], []
    if use_external:
        ext, u, s = run_external(root)
        findings += ext
        used += u
        skipped += s
    findings = dedupe(findings)
    rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    findings.sort(key=lambda f: (rank.get(f["severity"], 9), f["file"], f["line"]))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}
    return dict(root=root, files_scanned=len(files), tools_used=used, tools_skipped=skipped,
                rules=len(CODE_RULES) + len(SECRET_RULES), score=score(findings), counts=counts, findings=findings)
