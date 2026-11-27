import type { Check, Finding, RepoFile, Severity } from "../types.js";
import { VENDOR } from "../util.js";

/**
 * Python web code (Flask, Django, FastAPI). Line-based with light tracking of which names hold
 * request input (x = request.args.get(...)), so most findings need input to actually reach the call.
 */

const PY = /\.py$/;
const PY_TEST = /(^|\/)(tests?|__tests__)\/|(^|\/)test_[^/]*\.py$|_test\.py$|(^|\/)conftest\.py$/;
const REQUEST = /\brequest\.(args|form|values|json|data|files|cookies|headers|get_json|GET|POST|body|query_params|path_params|FILES|COOKIES|META)\b/;
const BUILT = /\bf["']|["']\s*%\s*[\w(]|\.format\(|["']\s*\+\s*\w|\w\s*\+\s*["']/;

interface Rule {
  re: RegExp;
  severity: Severity;
  title: string;
  why: string;
  fix: string;
  /** Only when the line also carries request input (directly or through a tracked name). */
  needsInput?: boolean;
  /** Only when the line builds a string (f-string, %, .format, +). */
  needsBuilt?: boolean;
  /** Rules in the same group report a line once (the first match wins). */
  group?: string;
  /** Only in files whose path matches. */
  path?: RegExp;
  unless?: RegExp;
}

const RULES: Rule[] = [
  { re: /\.(execute|executemany|executescript|raw|extra)\s*\(/, needsBuilt: true, severity: "critical", title: "SQL built from strings", why: "Values pasted into the SQL text let a request change the query (SQL injection).", fix: 'Pass values as parameters: cursor.execute("SELECT … WHERE id = %s", (user_id,)).' },
  { re: /\bos\.(system|popen)\s*\(|\bsubprocess\.\w+\([^)]*shell\s*=\s*True|\bcommands\.getoutput\(/, needsBuilt: true, group: "shell", severity: "critical", title: "Shell command built from strings", why: "Text such as `; rm -rf /` in the value runs as its own command on the server.", fix: 'Use subprocess.run(["ping", "-c", "1", host]) with a list and no shell=True.' },
  { re: /\bos\.(system|popen)\s*\(|\bsubprocess\.\w+\(/, needsInput: true, group: "shell", severity: "critical", title: "Request input reaches a shell command", why: "The sender controls part of the command that runs on the server.", fix: "Use a fixed program with an argument list, and validate the input against an allowlist.", unless: /shell\s*=\s*False/ },
  { re: /(?<![\w.])(eval|exec)\s*\(/, needsInput: true, severity: "critical", title: "Request input is run as Python code", why: "eval and exec run whatever they are given, so the sender runs their own code on the server.", fix: "Parse the data instead (json.loads, ast.literal_eval for literals)." },
  { re: /\b(pickle|cPickle|dill|joblib)\.loads?\s*\(|\bshelve\.open\s*\(/, needsInput: true, severity: "critical", title: "Request input is unpickled", why: "Unpickling runs code chosen by whoever wrote the data, so the sender runs their own code on the server.", fix: "Use JSON for anything that crosses a trust boundary (requests, caches, queues, uploads)." },
  { re: /\byaml\.(load|load_all)\s*\(/, severity: "high", title: "yaml.load without SafeLoader", why: "The full YAML loader can build arbitrary Python objects, which runs code from the document.", fix: "Use yaml.safe_load(text).", unless: /Loader\s*=\s*(yaml\.)?(C?SafeLoader|BaseLoader)/ },
  { re: /\byaml\.unsafe_load\s*\(|Loader\s*=\s*(yaml\.)?(Unsafe)?Loader\b/, severity: "high", title: "Unsafe YAML loader", why: "This loader builds arbitrary Python objects from the document.", fix: "Use yaml.safe_load(text)." },
  { re: /\brender_template_string\s*\(|\bTemplate\s*\(\s*(f["']|request)/, needsInput: true, severity: "critical", title: "Request input in a template (SSTI)", why: "Jinja expressions like {{ config.__class__… }} in the input run on the server.", fix: "Use render_template('page.html', name=value) with a fixed template file." },
  { re: /\brequests\.(get|post|put|patch|delete|head|request)\s*\(|\burllib\.request\.urlopen\s*\(|\bhttpx\.(get|post|AsyncClient|Client)\b|\baiohttp\.ClientSession\b.*\.(get|post)\(/, needsInput: true, severity: "high", title: "Request input chooses where the server sends a request (SSRF)", why: "The server can be pointed at internal addresses such as 169.254.169.254 (cloud credentials).", fix: "Fix the host in code, or check the host against an allowlist and refuse private addresses." },
  { re: /(?<![\w.])open\s*\(|\bsend_file\s*\(|\bsend_from_directory\s*\([^,]+,\s*request|\bFileResponse\s*\(/, needsInput: true, severity: "high", title: "Request input chooses a file path", why: "`../../` in the input reaches files outside the intended folder.", fix: "Use werkzeug.utils.secure_filename() and send_from_directory(folder, name)." },
  { re: /\bverify\s*=\s*False\b/, severity: "high", title: "TLS certificate checks turned off (verify=False)", why: "Traffic can be intercepted and changed by anyone on the network path.", fix: "Remove verify=False; pass verify='/path/to/ca.pem' for a private CA." },
  { re: /\.run\s*\([^)]*debug\s*=\s*True/, severity: "high", title: "Flask debug mode on", why: "The Werkzeug debugger gives anyone who reaches an error page a Python console on the server.", fix: "Read debug from the environment and keep it off in production." },
  { re: /^\s*DEBUG\s*=\s*True\b/, path: /(^|\/)settings[^/]*\.py$/, severity: "medium", title: "Django DEBUG = True in settings", why: "Error pages show settings, SQL and source code to every visitor.", fix: "DEBUG = os.environ.get('DJANGO_DEBUG') == '1'." },
  { re: /^\s*ALLOWED_HOSTS\s*=\s*\[\s*["']\*["']\s*\]/, path: /(^|\/)settings[^/]*\.py$/, severity: "low", title: "ALLOWED_HOSTS accepts any host", why: "Host-header attacks can poison password-reset links and caches.", fix: "List your real domain names." },
  { re: /@csrf_exempt\b/, severity: "medium", title: "CSRF protection turned off for a view", why: "Other websites can submit this form or call this view with the user's cookies.", fix: "Remove @csrf_exempt and send the CSRF token, or use token auth instead of cookies for APIs." },
  { re: /\bhashlib\.(md5|sha1)\s*\(/, severity: "medium", title: "MD5/SHA-1 used near passwords", why: "Fast unsalted hashes are cracked quickly when the database leaks.", fix: "Use argon2-cffi, bcrypt, or Django's make_password.", path: /./ },
  { re: /\brandom\.(random|randint|choice|choices|getrandbits|randrange)\s*\(/, severity: "medium", title: "random used for a security value", why: "Python's random is predictable; tokens made with it can be guessed.", fix: "Use secrets.token_urlsafe(32) or secrets.choice." },
  { re: /\bmark_safe\s*\(|\|\s*safe\b|autoescape\s*=\s*False|Markup\s*\(/, needsInput: true, severity: "high", title: "Request input marked as safe HTML", why: "Marking input safe turns off escaping, so it runs as script in the page (XSS).", fix: "Let the template escape it; never mark user input safe." },
  { re: /\bCORS\s*\([^)]*supports_credentials\s*=\s*True/, severity: "medium", title: "CORS with credentials", why: "If origins is broad, other sites can make logged-in requests and read the answers.", fix: "Set origins to the exact list of your front-end URLs.", unless: /origins\s*=\s*\[?\s*["']https?:\/\// },
  { re: /\btempfile\.mktemp\s*\(/, severity: "low", title: "tempfile.mktemp is race-prone", why: "Another process can create the file between the name being chosen and opened.", fix: "Use tempfile.NamedTemporaryFile or mkstemp." },
  { re: /\b(xml\.etree\.ElementTree|xml\.dom\.minidom|xml\.sax|lxml\.etree)\.(parse|fromstring|parseString|XML)\s*\(/, needsInput: true, severity: "medium", title: "XML from the request parsed without protection", why: "XML entities can read local files or exhaust memory (XXE, billion laughs).", fix: "Use defusedxml." },
];

const SECURITY_NAME = /token|secret|passw|otp|nonce|salt|session|key|reset|code|csrf/i;

function pythonFindings(file: RepoFile): Finding[] {
  const out: Finding[] = [];
  const lines = file.content.split("\n");
  // Names that hold request input: x = request.args.get("q"), data = request.get_json(), def view(request, slug) in Django.
  const tainted = new Set<string>();
  for (const l of lines) {
    const m = /^\s*(\w+)\s*(?::\s*\w+\s*)?=\s*(.*)$/.exec(l);
    if (m && (REQUEST.test(m[2]) || [...tainted].some((t) => new RegExp(`\\b${t}\\b`).test(m[2])))) tainted.add(m[1]);
    const fastapi = /^\s*(async\s+)?def\s+\w+\(([^)]*)\)/.exec(l);
    if (fastapi && /@(app|router)\.(get|post|put|patch|delete)\(/.test(lines[lines.indexOf(l) - 1] ?? "")) {
      for (const p of fastapi[2].split(",")) {
        const name = p.split(/[:=]/)[0].trim();
        if (name && name !== "self" && name !== "request" && !/Depends|Session|db/.test(p)) tainted.add(name);
      }
    }
  }
  const taintRe = tainted.size ? new RegExp(`\\b(${[...tainted].map((t) => t.replace(/[^\w]/g, "")).join("|")})\\b`) : null;
  const hasInput = (s: string) => REQUEST.test(s) || (taintRe?.test(s) ?? false);
  const near = (i: number) => lines.slice(Math.max(0, i - 6), i + 1).join("\n");

  const seen = new Set<string>();
  lines.forEach((raw, i) => {
    const l = raw.replace(/#.*$/, "");
    if (!l.trim()) return;
    // Rules match code, not text inside strings (a help message that says "verify=False" is not a call).
    const code = l.replace(/(["'])(?:\.|(?!\1).)*\1/g, '""');
    for (const r of RULES) {
      if (r.path && !r.path.test(file.path)) continue;
      if (!r.re.test(code)) continue;
      if (r.unless?.test(l)) continue;
      if (r.needsBuilt && !BUILT.test(l)) continue;
      if (r.needsInput && !hasInput(l)) continue;
      if (r.title.startsWith("MD5") && !/passw|pwd/i.test(near(i))) continue;
      if (r.title.startsWith("random used") && !SECURITY_NAME.test(/^\s*(\w+)\s*=/.exec(l)?.[1] ?? "")) continue;
      const key = `${i}|${r.group ?? r.title}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push({ checkId: "python-security", title: r.title, severity: r.severity, file: file.path, line: i + 1, evidence: raw.trim().slice(0, 140), explanation: r.why, remedy: r.fix });
    }
  });
  return out;
}

export const pythonSecurity: Check = {
  id: "python-security",
  group: "C-security",
  title: "Python web security",
  severity: "high",
  mode: "report",
  skip: ({ repo }) => (repo.files.some((x) => PY.test(x.path) && !VENDOR.test(x.path) && !PY_TEST.test(x.path)) ? null : "no Python source"),
  detect: ({ repo }) => repo.files.filter((x) => PY.test(x.path) && !VENDOR.test(x.path) && !PY_TEST.test(x.path)).flatMap(pythonFindings),
};
