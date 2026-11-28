"""Full security test in three steps:

  Step 1  Vulnerabilities        what is wrong in the code (scanner + extra checks)
  Step 2  Entry and exit points  every way data comes in and goes out, and which are exposed
  Step 3  Virus and malware      start the app and attack it live (payloads incl. the harmless
          attack simulation      EICAR test virus, malformed HTTP, flood, slowloris, memory watch)
"""
import os
import shlex
import subprocess
import time
import urllib.request

from . import attack, scan as scanner, threats

SEV = ["critical", "high", "medium", "low"]


def _wait(url, secs=180):
    end = time.time() + secs
    while time.time() < end:
        try:
            urllib.request.urlopen(url, timeout=5)
            return True
        except urllib.error.HTTPError:
            return True
        except Exception:  # noqa: BLE001
            time.sleep(2)
    return False


def run(project, url=None, health="/", start=None, cwd=None, endpoints=(), pid=None,
        flood_clients=50, flood_seconds=10, slow_sockets=200, slow_hold=10, log=print):
    project = os.path.abspath(project)
    res = dict(project=project)

    log("STEP 1/3  Vulnerabilities")
    a = threats.analyse(project)
    res["step1"] = dict(vulns=a["vulnerabilities"], counts=a["counts"], score=a["score"], tools=a["tools_used"],
                        skipped=a["tools_skipped"], hygiene=a["hygiene"])
    log(f"  {len(a['vulnerabilities'])} vulnerabilities, score {a['score']}/100")

    log("STEP 2/3  Entry and exit points")
    files = sorted(scanner.iter_files(project))
    texts = {f: scanner.read_text(project, f) for f in files}
    exits = threats.find_exit_points(project, files, texts, a["entry_points"])
    res["step2"] = dict(entry=a["entry_points"], exits=exits, groups={k: len(v) for k, v in a["groups"].items()},
                        group_items=a["groups"])
    log(f"  {len(a['entry_points'])} entry points, {len(exits)} exit points "
        f"({sum(1 for x in exits if x['external'])} reach outside or need no login)")

    log("STEP 3/3  Virus and malware attack simulation")
    proc = None
    if start:
        log(f"  starting the app: {start}")
        # Split the owner's start command into arguments; no shell, so nothing in it is interpreted.
        proc = subprocess.Popen(shlex.split(start), cwd=cwd or project,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pid = proc.pid
        if not _wait(url.rstrip("/") + health):
            proc.kill()
            res["step3"] = dict(skipped="the app did not start within 3 minutes")
            return res
    if not url:
        res["step3"] = dict(skipped="no running app given (use --url, or --start to launch it)")
        log("  skipped: no running app")
        return res
    try:
        eps = list(endpoints)
        known = {(e["method"], e["path"]) for e in eps}
        eps += [e for e in attack.endpoints_from_project(project) if (e["method"], e["path"]) not in known]
        rep = attack.run(url, eps, health, pid, False, flood_clients, flood_seconds, slow_sockets, slow_hold,
                         log=lambda m: log("  " + m))
        rep["endpoints"] = eps
        res["step3"] = rep
    finally:
        if proc:
            proc.terminate()
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()
    return res


def verdicts(res):
    s1 = res["step1"]["counts"]
    v1 = "FAIL" if s1["critical"] else "NEEDS FIXES" if s1["high"] or s1["medium"] else "PASS"
    entry = res["step2"]["entry"]
    open_input = [e for e in entry if not e["auth"] and e["takes_input"] and e["kind"] != "html form"]
    third = {x["target"] for x in res["step2"]["exits"] if x["kind"].startswith("third-party")}
    v2 = "NEEDS FIXES" if open_input or third else "PASS"
    s3 = res.get("step3", {})
    if "skipped" in s3:
        v3 = "NOT RUN"
    else:
        sev = {f["severity"] for f in s3["findings"]}
        v3 = "FAIL" if s3["crashed"] or "critical" in sev else "NEEDS FIXES" if sev & {"high", "medium"} else "PASS"
    return v1, v2, v3, open_input, third


def to_markdown(res):
    name = os.path.basename(res["project"])
    v1, v2, v3, open_input, third = verdicts(res)
    s1, s2, s3 = res["step1"], res["step2"], res.get("step3", {})
    order = {"FAIL": 0, "NEEDS FIXES": 1, "NOT RUN": 2, "PASS": 3}
    overall = min((v1, v2, v3), key=lambda v: order[v])
    out = [f"# Siidekick full security test: {name}", "",
           f"**Overall: {overall}**", "",
           "| Step | What it tests | Result | Verdict |", "| --- | --- | --- | --- |",
           f"| 1. Vulnerabilities | Flaws in the code | {len(s1['vulns'])} found (" +
           ", ".join(f"{v} {k}" for k, v in s1["counts"].items() if v) + f"); score {s1['score']}/100 | **{v1}** |",
           f"| 2. Entry and exit points | How data gets in and out | {len(s2['entry'])} entry points ({len(open_input)} public and take input), "
           f"{len(s2['exits'])} exit points ({len(third)} third-party sites) | **{v2}** |",
           f"| 3. Virus and malware attack | Live attack on the running app | " +
           (s3.get("skipped", "") if "skipped" in s3 else
            ("CRASHED" if s3["crashed"] else "survived") + f", {s3.get('payload_requests', 0)} malicious requests, "
            f"{len(attack.dedupe(s3['findings']))} problems") + f" | **{v3}** |", ""]

    # step 1
    out += ["## Step 1: Vulnerabilities", ""]
    if s1["vulns"]:
        out += ["| Severity | Problem | Way in / out / runs code | Where | Fix |", "| --- | --- | --- | --- | --- |"]
        label = {threats.WAY_IN: "in", threats.WAY_OUT: "out", threats.RUN_CODE: "runs code"}
        for f in s1["vulns"]:
            loc = f["file"] + (f":{f['line']}" if f["line"] else "")
            out.append(f"| {f['severity']} | **{f['title']}** ({f['cwe']}). {f['explain']} | "
                       f"{', '.join(label[g] for g in f['groups'])} | `{loc}` | {f['fix']} |")
    else:
        out.append("No vulnerabilities found.")
    out += ["", f"_Tools: {', '.join(s1['tools'])}" + (f"; skipped: {'; '.join(s1['skipped'])}" if s1["skipped"] else "") + "._", ""]

    # step 2
    out += ["## Step 2: Entry and exit points", "",
            f"Ways in: {s2['groups'][threats.WAY_IN]} · ways out: {s2['groups'][threats.WAY_OUT]} · "
            f"ways to run code: {s2['groups'][threats.RUN_CODE]} (from step 1, grouped).", "",
            f"### Entry points ({len(s2['entry'])})", "",
            "| Method | Path | Kind | Login check | Takes input | Where |", "| --- | --- | --- | --- | --- | --- |"]
    for e in s2["entry"]:
        flag = " ⚠" if (not e["auth"] and e["takes_input"] and e["kind"] != "html form") else ""
        out.append(f"| {e['method']} | `{e['path']}`{flag} | {e['kind']} | {'yes' if e['auth'] else 'no'} | "
                   f"{'yes' if e['takes_input'] else 'no'} | `{e['file']}:{e['line']}` |")
    out += ["", f"### Exit points ({len(s2['exits'])})", "",
            "| Kind | Goes to | What leaves | Leaves your control | Where |", "| --- | --- | --- | --- | --- |"]
    for x in sorted(s2["exits"], key=lambda x: (not x["external"], x["kind"])):
        tgt = x["target"].replace("|", "\\|")
        out.append(f"| {x['kind']} | `{tgt[:60]}` | {x['what']} | {'yes' if x['external'] else 'no'} | `{x['file']}:{x['line']}` |")
    if third:
        out += ["", f"Third-party sites every visitor's browser contacts: {', '.join(sorted(third))}."]
    out.append("")

    # step 3
    out += ["## Step 3: Virus and malware attack simulation", ""]
    if "skipped" in s3:
        out.append(f"Not run: {s3['skipped']}.")
    else:
        body = attack.to_markdown(s3, name).split("\n", 2)[2]  # drop its title
        out.append("Attacks used: injection, script, command, template and path-traversal payloads; the harmless EICAR "
                   "test virus; malicious JSON (prototype pollution, deep nesting, huge objects); broken HTTP; a request "
                   "flood; slowloris half-open connections. Endpoints attacked: " +
                   ", ".join(f"`{e['method']} {e['path']}`" for e in s3["endpoints"]) + ".")
        out.append("")
        out.append(body.replace("## ", "### "))
    return "\n".join(out) + "\n"
