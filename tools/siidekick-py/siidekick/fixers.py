"""Deterministic fixers.

Every fixer either adds new files/lines or edits the single line a finding points at.
Nothing here deletes user code. The diff guard checks that promise independently.
"""
import json
import os
import re

SECURITY_FILE = "siidekick.security.js"
SECURITY_JS = r"""// Added by Siidekick. Review before deploying.
// To undo: delete this file and the one "siidekick" require line in your app.
const path = require('path');

let helmet = null;
let rateLimit = null;
try { helmet = require('helmet'); } catch (e) { console.warn('[siidekick] security headers off: run npm install helmet'); }
try { rateLimit = require('express-rate-limit'); } catch (e) { console.warn('[siidekick] rate limit off: run npm install express-rate-limit'); }

function siidekick(app) {
  app.disable('x-powered-by');
  if (helmet) app.use(helmet());
  if (rateLimit) {
    const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });
    app.use(['/login', '/signup', '/register', '/reset', '/api/login', '/api/auth'], authLimiter);
  }
}

// Allows the request only when the logged-in user has the admin role.
// Adapt the user lookup if your app stores the user somewhere else.
siidekick.requireAdmin = function requireAdmin(req, res, next) {
  const user = (req.session && req.session.user) || req.user;
  if (user && user.role === 'admin') return next();
  return res.status(403).send('Forbidden');
};

siidekick.escapeHtml = function escapeHtml(value) {
  const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  return String(value).replace(/[&<>"']/g, (c) => map[c]);
};

// Keeps only the file name, so "../../.env" becomes ".env" inside the intended folder.
siidekick.safeFileName = function safeFileName(name) {
  return path.basename(String(name));
};

module.exports = siidekick;
"""

ALLOWED_ORIGINS = "(process.env.ALLOWED_ORIGINS || 'http://localhost:3000').split(',')"
REQ_VALUE = r"req\.(?:query|params|body)\.[A-Za-z_$][\w$]*"


class Ctx:
    def __init__(self, files, deps):
        self.files = files            # rel -> list of lines (mutable)
        self.deps = deps              # set of dependency names
        self.need_security = set()    # files that use siidekick.* helpers
        self.need_middleware = False
        self.env_vars = {}            # NAME -> note
        self.applied = []             # dicts: finding id, fixer, note
        self.skipped = []
        self.new_files = {}           # rel -> text
        self.gitignore = False


# ---------------- line fixers: return new line or None ----------------

def fx_sql_param(line, f, ctx):
    ph = "$1" if "pg" in ctx.deps else "?"
    rx = re.compile(r"""(?P<q>["'])(?P<sql>[^"']*?)(?P<open>'?)(?P=q)\s*\+\s*(?P<expr>[\w$.\[\]]+)(?:\s*\+\s*(?P<q2>["'])'(?P=q2))?(?=\s*[,)])""")
    m = rx.search(line)
    if m:
        return line[:m.start()] + f"{m['q']}{m['sql']}{ph}{m['q']}, [{m['expr']}]" + line[m.end():]
    rx2 = re.compile(r"""`(?P<pre>[^`$]*?)'?\$\{(?P<expr>[^}]+)\}'?(?P<post>[^`$]*)`""")
    m = rx2.search(line)
    if m:
        return line[:m.start()] + f"`{m['pre']}{ph}{m['post']}`, [{m['expr'].strip()}]" + line[m.end():]
    return None


def fx_innerhtml(line, f, ctx):
    m = re.search(r"\.(innerHTML|outerHTML)\s*=(?!=)\s*(.*)", line)
    if not m or m.group(1) == "outerHTML":
        return None
    rhs = m.group(2).strip()
    if re.match(r"""^(["'`])[^"'`]*<""", rhs):
        return None  # a literal HTML template: needs a person to decide
    return re.sub(r"\.innerHTML(\s*)=(?!=)", r".textContent\1=", line, count=1)


def fx_escape_html(line, f, ctx):
    if "siidekick.escapeHtml" in line:
        return None
    new = re.sub(REQ_VALUE, lambda m: f"siidekick.escapeHtml({m.group(0)})", line)
    if new != line:
        ctx.need_security.add(f["file"])
        return new
    return None


def fx_safe_path(line, f, ctx):
    if "siidekick.safeFileName" in line:
        return None
    new = re.sub(REQ_VALUE, lambda m: f"siidekick.safeFileName({m.group(0)})", line, count=1)
    if new != line:
        ctx.need_security.add(f["file"])
        return new
    return None


def fx_cors(line, f, ctx):
    new = re.sub(r"""origin\s*:\s*(['"])\*\1""", f"origin: {ALLOWED_ORIGINS}", line)
    new = re.sub(r"""\bcors\(\s*\)""", f"cors({{ origin: {ALLOWED_ORIGINS} }})", new)
    if new != line:
        ctx.env_vars["ALLOWED_ORIGINS"] = "comma-separated list of sites allowed to call the API"
        return new
    return None


def fx_cookie(line, f, ctx):
    new = re.sub(r"httpOnly\s*:\s*false", "httpOnly: true", line)
    new = re.sub(r"secure\s*:\s*false", "secure: process.env.NODE_ENV === 'production'", new)
    return new if new != line else None


def fx_secret_env(line, f, ctx):
    m = re.search(r"""\b(const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(['"])[^'"]*\3""", line)
    if m:
        name = re.sub(r"(?<!^)(?=[A-Z])", "_", m.group(2)).upper() if not m.group(2).isupper() else m.group(2)
        ctx.env_vars[name] = f"moved out of {f['file']} - rotate the old value"
        return line[:m.start()] + f"{m.group(1)} {m.group(2)} = process.env.{name}" + line[m.end():]
    m = re.search(r"""\b([A-Za-z_$][\w$]*)\s*:\s*(['"])[^'"]*\2""", line)
    if m:
        key = m.group(1)
        name = "SESSION_SECRET" if key.lower() == "secret" else re.sub(r"(?<!^)(?=[A-Z])", "_", key).upper()
        ctx.env_vars[name] = f"moved out of {f['file']} - rotate the old value"
        return line[:m.start()] + f"{key}: process.env.{name}" + line[m.end():]
    return None


def fx_admin_guard(line, f, ctx):
    if "requireAdmin" in line:
        return None
    rx = re.compile(r"""(\.(?:get|post|put|patch|delete|all)\(\s*(['"`])/(?:api/)?admin[^'"`]*\2\s*,\s*)""")
    new = rx.sub(r"\1siidekick.requireAdmin, ", line, count=1)
    if new != line:
        ctx.need_security.add(f["file"])
        return new
    return None


def fx_hide_stack(line, f, ctx):
    new = re.sub(r"\b(err|error|e)\.stack\b", "'Internal server error'", line)
    return new if new != line else None


LINE_FIXERS = dict(sql_param=fx_sql_param, innerhtml=fx_innerhtml, escape_html=fx_escape_html,
                   safe_path=fx_safe_path, cors=fx_cors, cookie=fx_cookie, secret_env=fx_secret_env,
                   admin_guard=fx_admin_guard, hide_stack=fx_hide_stack)


# ---------------- project fixers ----------------

def _rel_require(from_file, target):
    rel = os.path.relpath(target, os.path.dirname(from_file) or ".").replace(os.sep, "/")
    return rel if rel.startswith(".") else "./" + rel


def _insert_requires(ctx, app_file, app_idx, app_var):
    sec_path = os.path.join(os.path.dirname(app_file), SECURITY_FILE).replace(os.sep, "/") if app_file else SECURITY_FILE
    sec_path = sec_path.lstrip("./") if sec_path.startswith("./") else sec_path
    ctx.new_files[sec_path] = SECURITY_JS
    if app_file:
        lines = ctx.files[app_file]
        req = _rel_require(app_file, sec_path)
        lines.insert(app_idx + 1, f"const siidekick = require('{req}'); siidekick({app_var}); // added by Siidekick")
    for rel in sorted(ctx.need_security):
        if rel == app_file:
            continue
        lines = ctx.files[rel]
        last_req = max([i for i, l in enumerate(lines[:40]) if re.search(r"require\(|^import ", l)], default=-1)
        lines.insert(last_req + 1, f"const siidekick = require('{_rel_require(rel, sec_path)}'); // added by Siidekick")
    return sec_path


def _add_package_deps(ctx, app_file):
    pkg_rel = os.path.join(os.path.dirname(app_file), "package.json").replace(os.sep, "/").lstrip("/")
    pkg_rel = pkg_rel[2:] if pkg_rel.startswith("./") else pkg_rel
    if pkg_rel not in ctx.files:
        return
    lines = ctx.files[pkg_rel]
    try:
        deps = json.loads("\n".join(lines)).get("dependencies", {})
    except ValueError:
        return
    wanted = {"helmet": "^8.0.0", "express-rate-limit": "^7.4.0"}
    add = {k: v for k, v in wanted.items() if k not in deps}
    if not add:
        return
    start = next((i for i, l in enumerate(lines) if re.match(r'\s*"dependencies"\s*:\s*\{', l)), None)
    if start is None:
        return
    end = next(i for i in range(start, len(lines)) if re.match(r"\s*\}", lines[i]))
    last = end - 1
    indent = re.match(r"\s*", lines[last]).group(0) if last > start else "    "
    if last > start and not lines[last].rstrip().endswith(","):
        lines[last] = lines[last].rstrip() + ","
    new = [f'{indent}"{k}": "{v}"' + ("," if i < len(add) - 1 else "") for i, (k, v) in enumerate(add.items())]
    lines[end:end] = new
    ctx.applied.append(dict(finding="(dependencies)", fixer="package_deps",
                            note=f"added {', '.join(add)} to {pkg_rel}; run npm install"))


def apply_fixes(files, findings, approved, deps):
    """files: rel -> text. Returns (new_files_map, ctx)."""
    ctx = Ctx({k: v.split("\n") for k, v in files.items()}, deps)
    by_line = {}
    for f in findings:
        if f["id"] not in approved or not f.get("fixer"):
            continue
        if f["fixer"] in LINE_FIXERS and f["line"] and f["file"] in ctx.files:
            by_line.setdefault((f["file"], f["line"]), []).append(f)
        elif f["fixer"] == "security_middleware":
            ctx.need_middleware = True
            ctx.applied.append(dict(finding=f["id"], fixer=f["fixer"], note="added helmet and login rate limiting in " + SECURITY_FILE))
        elif f["fixer"] == "gitignore_env":
            ctx.gitignore = True
            ctx.applied.append(dict(finding=f["id"], fixer=f["fixer"], note="added .env to .gitignore"))

    for (rel, lineno), fs in sorted(by_line.items()):
        lines = ctx.files[rel]
        for f in fs:
            fixer = LINE_FIXERS[f["fixer"]]
            new = fixer(lines[lineno - 1], f, ctx)
            if new is None:
                ctx.skipped.append(dict(finding=f["id"], reason="pattern too complex for an automatic fix; needs a person"))
            else:
                lines[lineno - 1] = new
                ctx.applied.append(dict(finding=f["id"], fixer=f["fixer"], note="edited 1 line"))

    # insert the security helper and requires (after line edits so line numbers stay valid)
    if ctx.need_middleware or ctx.need_security:
        app_file = app_idx = app_var = None
        for rel, lines in ctx.files.items():
            for i, l in enumerate(lines):
                m = re.search(r"""\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*express\(\s*\)""", l)
                if m:
                    app_file, app_idx, app_var = rel, i, m.group(1)
                    break
            if app_file:
                break
        if app_file:
            ctx.need_security.add(app_file)
            _insert_requires(ctx, app_file, app_idx, app_var)
            _add_package_deps(ctx, app_file)
        else:
            ctx.skipped.append(dict(finding="(middleware)", reason="no express() app found to attach middleware to"))

    if ctx.gitignore:
        gi = ctx.files.get(".gitignore")
        block = ["", "# added by Siidekick: keep secrets out of git", ".env", ".env.*", "!.env.example"]
        if gi is None:
            ctx.new_files[".gitignore"] = "\n".join(block[1:]) + "\n"
        else:
            while gi and gi[-1] == "":
                gi.pop()
            gi.extend(block + [""])

    env_names = dict(ctx.env_vars)
    for rel, lines in ctx.files.items():
        if os.path.basename(rel) == ".env":
            for l in lines:
                m = re.match(r"\s*([A-Z0-9_]+)\s*=", l)
                if m:
                    env_names.setdefault(m.group(1), "")
    if env_names and ".env.example" not in ctx.files:
        body = ["# Added by Siidekick. Copy to .env and fill in real values. Never commit .env."]
        for k, note in env_names.items():
            if note:
                body.append(f"# {k}: {note}")
            body.append(f"{k}=")
        ctx.new_files[".env.example"] = "\n".join(body) + "\n"

    out = {k: "\n".join(v) for k, v in ctx.files.items()}
    for k, v in ctx.new_files.items():
        out[k] = v
    return out, ctx
