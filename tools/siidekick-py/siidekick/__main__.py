"""Siidekick command line.

  python3 -m siidekick scan  <project>                 list findings (JSON with --json)
  python3 -m siidekick fix   <project> [--out DIR]     scan, fix a copy, guard, verify, re-scan, HTML report
  python3 -m siidekick guard <patch.diff> --findings findings.json   check any patch (for example an AI-written one)
"""
import argparse
import json
import os
import sys

from . import guard, pipeline, report, scan

COLORS = {"critical": "\033[31m", "high": "\033[33m", "medium": "\033[36m", "low": "\033[37m"}


def print_scan(res):
    print(f"\nScanned {res['files_scanned']} files with {res['rules']} rules. Tools: {', '.join(res['tools_used'])}")
    for s in res["tools_skipped"]:
        print(f"  (skipped: {s})")
    for f in res["findings"]:
        loc = f["file"] + (f":{f['line']}" if f["line"] else "")
        print(f"{COLORS.get(f['severity'], '')}[{f['severity'].upper():8}]\033[0m {f['title']}  ->  {loc}")
    print(f"\nScore: {res['score']}/100   " + "  ".join(f"{k}: {v}" for k, v in res["counts"].items()))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="siidekick")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("scan"); p.add_argument("project"); p.add_argument("--json", action="store_true"); p.add_argument("--no-external", action="store_true")
    p = sub.add_parser("fix"); p.add_argument("project"); p.add_argument("--out", default="siidekick-out"); p.add_argument("--no-external", action="store_true")
    p.add_argument("--approve", default="all", help="'all' or comma-separated finding ids")
    p = sub.add_parser("guard"); p.add_argument("patch"); p.add_argument("--findings", required=True)
    p.add_argument("--approve", default="all"); p.add_argument("--protect", default="")
    p = sub.add_parser("threats", help="entry points + vulnerabilities grouped as way in / way out / run code")
    p.add_argument("project"); p.add_argument("--out", default=""); p.add_argument("--json", action="store_true")
    p.add_argument("--no-external", action="store_true")
    p = sub.add_parser("attack", help="simulate attacks against a RUNNING local copy of your app")
    p.add_argument("url"); p.add_argument("--project", help="find entry points from this source folder")
    p.add_argument("--endpoint", action="append", default=[], help='e.g. "GET /api/find pid" or "POST /api/simulation days,seed"')
    p.add_argument("--health", default="/"); p.add_argument("--pid", type=int)
    p.add_argument("--flood-clients", type=int, default=100); p.add_argument("--flood-seconds", type=int, default=15)
    p.add_argument("--slow-sockets", type=int, default=300); p.add_argument("--slow-hold", type=int, default=20)
    p.add_argument("--out", default=""); p.add_argument("--i-own-this", action="store_true")
    p = sub.add_parser("full", help="3-step test: vulnerabilities, entry/exit points, live virus and malware attack")
    p.add_argument("project"); p.add_argument("--url"); p.add_argument("--health", default="/")
    p.add_argument("--start", help='command that starts the app, e.g. "python3 app.py"'); p.add_argument("--cwd")
    p.add_argument("--endpoint", action="append", default=[]); p.add_argument("--pid", type=int)
    p.add_argument("--flood-clients", type=int, default=50); p.add_argument("--flood-seconds", type=int, default=10)
    p.add_argument("--out", default="siidekick-full-report.md")
    a = ap.parse_args(argv)

    if a.cmd == "full":
        from . import full
        eps = []
        for spec in a.endpoint:
            parts = spec.split()
            eps.append(dict(method=parts[0].upper(), path=parts[1], params=(parts[2].split(",") if len(parts) > 2 else []),
                            json=parts[0].upper() in ("POST", "PUT", "PATCH")))
        res = full.run(a.project, a.url, a.health, a.start, a.cwd, eps, a.pid, a.flood_clients, a.flood_seconds)
        with open(a.out, "w") as fh:
            fh.write(full.to_markdown(res))
        v = full.verdicts(res)
        print(f"\nStep 1 vulnerabilities: {v[0]}   Step 2 entry/exit points: {v[1]}   Step 3 attack: {v[2]}")
        print("Report:", a.out)
        return 0 if all(x in ("PASS", "NOT RUN") for x in v[:3]) else 1

    if a.cmd == "attack":
        from . import attack
        eps = []
        for spec in a.endpoint:
            parts = spec.split()
            eps.append(dict(method=parts[0].upper(), path=parts[1], params=(parts[2].split(",") if len(parts) > 2 else []),
                            json=parts[0].upper() in ("POST", "PUT", "PATCH")))
        manual = {(e["method"], e["path"]) for e in eps}
        if a.project:
            eps += [e for e in attack.endpoints_from_project(a.project) if (e["method"], e["path"]) not in manual]
        if not eps:
            raise SystemExit("No endpoints: pass --project or --endpoint.")
        print("Endpoints under attack:")
        for e in eps:
            print(f"  {e['method']:6} {e['path']}  params={e['params']}")
        rep = attack.run(a.url, eps, a.health, a.pid, a.i_own_this, a.flood_clients, a.flood_seconds, a.slow_sockets, a.slow_hold)
        print("\nVERDICT:", "CRASHED" if rep["crashed"] else "server survived every phase")
        for g in attack.dedupe(rep["findings"]):
            print(f"  [{g['severity'].upper():8}] {g['what']}  ({g['attack']}, x{g['count']})")
        if a.out:
            open(a.out, "w").write(attack.to_markdown(rep, a.project or a.url))
            print("Report:", a.out)
        return 2 if rep["crashed"] else 0

    if a.cmd == "threats":
        from . import threats
        res = threats.analyse(a.project, not a.no_external)
        if a.json:
            print(json.dumps(res, indent=2))
        else:
            eps = res["entry_points"]
            print(f"\nATTACK SURFACE: {len(eps)} entry points, "
                  f"{sum(1 for e in eps if not e['auth'])} without a login check, "
                  f"{sum(1 for e in eps if e['takes_input'])} accept input")
            for e in eps:
                print(f"  {e['method']:7} {e['path'][:50]:50} auth={'yes' if e['auth'] else 'NO '}  input={'yes' if e['takes_input'] else 'no '}  {e['file']}:{e['line']}")
            for g in (threats.WAY_IN, threats.WAY_OUT, threats.RUN_CODE):
                items = res["groups"][g]
                print(f"\n{threats.GROUP_TITLE[g].upper()} ({len(items)})")
                for f in items:
                    loc = f["file"] + (f":{f['line']}" if f["line"] else "")
                    print(f"  {COLORS.get(f['severity'], '')}[{f['severity'].upper():8}]\033[0m {f['title']}  ->  {loc}")
                if not items:
                    print("  none found")
            print(f"\nScore: {res['score']}/100   " + "  ".join(f"{k}: {v}" for k, v in res["counts"].items()))
        if a.out:
            with open(a.out, "w") as fh:
                fh.write(threats.to_markdown(res))
            print(f"Markdown report: {a.out}")
        return 1 if res["counts"]["critical"] or res["counts"]["high"] else 0

    if a.cmd == "scan":
        res = scan.scan(a.project, not a.no_external)
        print(json.dumps(res, indent=2)) if a.json else print_scan(res)
        return 1 if res["counts"]["critical"] or res["counts"]["high"] else 0

    if a.cmd == "fix":
        approve = "all" if a.approve == "all" else a.approve.split(",")
        res = pipeline.run(a.project, a.out, approve, not a.no_external)
        path = os.path.join(os.path.abspath(a.out), "report.html")
        with open(path, "w") as fh:
            fh.write(report.render(res))
        b, af = res["before"], res["after"]
        print(f"Before: score {b['score']}, {len(b['findings'])} findings  ->  After: score {af['score']}, {len(af['findings'])} findings")
        print(f"Guard: {'PASSED' if res['guard']['passed'] else 'REJECTED'}  " + "; ".join(res["guard"]["reasons"][:5]))
        print(f"Verification: {sum(v['ok'] for v in res['verification'])}/{len(res['verification'])} passed" + ("  (rolled back)" if res["rolled_back"] else ""))
        print(f"Fixed copy: {res['patched_dir']}\nPatch: {os.path.join(os.path.abspath(a.out), 'siidekick.patch')}\nReport: {path}")
        return 0 if res["guard"]["passed"] and not res["rolled_back"] else 2

    if a.cmd == "guard":
        findings = json.load(open(a.findings))
        findings = findings.get("findings", findings) if isinstance(findings, dict) else findings
        if a.approve != "all":
            ids = set(a.approve.split(","))
            findings = [f for f in findings if f["id"] in ids]
        res = guard.check(open(a.patch).read(), findings, [p for p in a.protect.split(",") if p])
        print(json.dumps(res, indent=2))
        return 0 if res["passed"] else 3


if __name__ == "__main__":
    sys.exit(main())
