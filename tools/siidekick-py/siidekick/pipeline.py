"""scan -> fix -> guard -> apply on a copy -> verify -> re-scan."""
import difflib
import json
import os
import shutil
import subprocess

from . import fixers, guard, scan as scanner

COPY_IGNORE = shutil.ignore_patterns(".git", "node_modules", "venv", ".venv", "__pycache__", "siidekick-out")


def project_deps(root):
    deps = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in scanner.SKIP_DIRS]
        if "package.json" in filenames:
            try:
                pkg = json.load(open(os.path.join(dirpath, "package.json")))
                deps |= set(pkg.get("dependencies", {})) | set(pkg.get("devDependencies", {}))
            except ValueError:
                pass
    return deps


def make_diff(before, after):
    chunks = []
    for rel in sorted(set(before) | set(after)):
        a, b = before.get(rel), after.get(rel)
        if a == b:
            continue
        a_lines = [] if a is None else a.split("\n")
        b_lines = [] if b is None else b.split("\n")
        chunks.extend(difflib.unified_diff(a_lines, b_lines,
                                           "/dev/null" if a is None else f"a/{rel}",
                                           "/dev/null" if b is None else f"b/{rel}", lineterm=""))
    return "\n".join(chunks) + ("\n" if chunks else "")


def verify(root, changed):
    results = []
    for rel in changed:
        path = os.path.join(root, rel)
        if rel.endswith((".js", ".cjs")) and shutil.which("node"):
            p = subprocess.run(["node", "--check", path], capture_output=True, text=True)
            results.append(dict(file=rel, check="node --check", ok=p.returncode == 0, detail=p.stderr.strip()[:300]))
        elif rel.endswith(".py"):
            p = subprocess.run(["python3", "-m", "py_compile", path], capture_output=True, text=True)
            results.append(dict(file=rel, check="py_compile", ok=p.returncode == 0, detail=p.stderr.strip()[:300]))
        elif rel.endswith(".json"):
            try:
                json.load(open(path))
                results.append(dict(file=rel, check="valid JSON", ok=True, detail=""))
            except ValueError as exc:
                results.append(dict(file=rel, check="valid JSON", ok=False, detail=str(exc)))
    return results


def run(project, out_dir, approve="all", use_external=True):
    project = os.path.abspath(project)
    out_dir = os.path.abspath(out_dir)
    patched = os.path.join(out_dir, "patched")
    if os.path.exists(patched):
        shutil.rmtree(patched)
    os.makedirs(out_dir, exist_ok=True)

    before = scanner.scan(project, use_external)
    fixable = [f for f in before["findings"] if f.get("fixer")]
    approved_ids = {f["id"] for f in fixable} if approve == "all" else set(approve)
    approved = [f for f in fixable if f["id"] in approved_ids]

    # the original project is never modified: work on a copy
    shutil.copytree(project, patched, ignore=COPY_IGNORE)
    originals = {rel: scanner.read_text(patched, rel) for rel in scanner.iter_files(patched)}
    new_files, ctx = fixers.apply_fixes(originals, before["findings"], approved_ids, project_deps(project))
    patch = make_diff(originals, new_files)
    gres = guard.check(patch, approved)

    changed = [rel for rel in new_files if new_files[rel] != originals.get(rel)]
    verification, rolled_back = [], False
    if gres["passed"]:
        for rel in changed:
            dest = os.path.join(patched, rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            with open(dest, "w", encoding="utf-8") as fh:
                fh.write(new_files[rel])
        verification = verify(patched, changed)
        if not all(v["ok"] for v in verification):
            rolled_back = True
            shutil.rmtree(patched)
            shutil.copytree(project, patched, ignore=COPY_IGNORE)
    after = scanner.scan(patched, use_external)

    for f in before["findings"]:
        if f["id"] in approved_ids and any(a["finding"] == f["id"] for a in ctx.applied) and not rolled_back:
            f["status"] = "fixed"
        elif f.get("fixer") and f["mode"] != "report":
            f["status"] = "needs review"
        else:
            f["status"] = "your action"
    result = dict(project=project, before=before, after=after, applied=ctx.applied, skipped=ctx.skipped,
                  guard=gres, verification=verification, rolled_back=rolled_back, patch=patch,
                  changed_files=changed, patched_dir=patched)
    with open(os.path.join(out_dir, "siidekick.patch"), "w") as fh:
        fh.write(patch)
    with open(os.path.join(out_dir, "results.json"), "w") as fh:
        json.dump({k: v for k, v in result.items() if k != "patch"}, fh, indent=2)
    return result
