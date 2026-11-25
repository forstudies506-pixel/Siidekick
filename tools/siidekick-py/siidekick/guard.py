"""Diff guard: a plain, non-AI check that a patch never removes or rewrites the user's code
except on lines an approved scanner finding points at.

Rules
 1. No file may be deleted.
 2. Protected paths may not be touched at all.
 3. Every removed line must be either
      a) on a line that an approved finding points at, and the replacement must keep at least
         70% of the original line's code words in order (so an approved line cannot be swapped
         for unrelated code), or
      b) a "comma-only" edit: the new line is the old line plus a trailing comma (JSON lists).
 4. Added lines may not contain dangerous code: eval, child_process, shell calls,
    hardcoded credentials, or calls to outside URLs. This stops a poisoned AI suggestion
    (for example from a prompt hidden in a code comment) from slipping in a backdoor.
 5. The patch must stay small (default: 400 added lines).
"""
import difflib
import fnmatch
import re

BANNED_ADDED = [
    (r"(?<![\w.$])eval\s*\(", "adds eval"),
    (r"new\s+Function\s*\(", "adds new Function"),
    (r"child_process", "adds child_process"),
    (r"\b(exec|execSync|spawn|spawnSync)\s*\(", "adds a shell/process call"),
    (r"\bos\.system\(|subprocess\.", "adds a shell/process call"),
    (r"https?://(?!localhost|127\.0\.0\.1)[\w.-]+", "adds a call to an outside URL"),
    (r"\b(AKIA|ASIA)[0-9A-Z]{16}\b|-----BEGIN [A-Z ]*PRIVATE KEY|\bgh[pousr]_[A-Za-z0-9]{36,}", "adds a credential"),
    (r"""(?i)\b(api[_-]?key|secret|passw(or)?d|token)\b\s*[:=]\s*['"][^'"\s]{6,}['"]""", "adds a hardcoded secret"),
    (r"\.on\(\s*['\"]data['\"].*(fetch|request|http)", "adds data exfiltration"),
    (r"(?i)rm\s+-rf|DROP\s+TABLE", "adds a destructive command"),
]
BANNED_RX = [(re.compile(p), why) for p, why in BANNED_ADDED]


def parse_unified(patch):
    """Return list of file dicts: old, new, hunks=[list of (kind, old_no, new_no, text)]."""
    files, cur, old_no, new_no = [], None, 0, 0
    for raw in patch.splitlines():
        if raw.startswith("--- "):
            cur = dict(old=raw[4:].split("\t")[0], new=None, hunks=[])
            files.append(cur)
            continue
        if raw.startswith("+++ ") and cur is not None and cur["new"] is None:
            cur["new"] = raw[4:].split("\t")[0]
            continue
        m = re.match(r"@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@", raw)
        if m and cur is not None:
            old_no, new_no = int(m.group(1)), int(m.group(2))
            cur["hunks"].append([])
            continue
        if cur is None or not cur["hunks"]:
            continue
        if raw.startswith("-"):
            cur["hunks"][-1].append(("-", old_no, None, raw[1:]))
            old_no += 1
        elif raw.startswith("+"):
            cur["hunks"][-1].append(("+", None, new_no, raw[1:]))
            new_no += 1
        elif raw.startswith("\\"):
            continue
        else:
            cur["hunks"][-1].append((" ", old_no, new_no, raw[1:] if raw.startswith(" ") else raw))
            old_no += 1
            new_no += 1
    return files


STRING_RX = re.compile(r"""(["'`])(?:\\.|(?!\1).)*\1""")
WORD_RX = re.compile(r"[A-Za-z_$][\w$]*")


def kept_ratio(old, new):
    """Share of the original line's code words (outside string literals) still present, in order."""
    literals = {"true", "false", "null", "undefined", "True", "False", "None"}
    a = [w for w in WORD_RX.findall(STRING_RX.sub(" ", old)) if w not in literals]
    b = [w for w in WORD_RX.findall(STRING_RX.sub(" ", new)) if w not in literals]
    if not a:
        return 1.0
    m = difflib.SequenceMatcher(None, a, b, autojunk=False)
    return sum(bl.size for bl in m.get_matching_blocks()) / len(a)


def _strip(path):
    if path == "/dev/null":
        return None
    return path[2:] if path[:2] in ("a/", "b/") else path


def check(patch, approved_findings, protected=(), max_added=400, min_kept=0.7):
    approved_lines = {(f["file"], f["line"]) for f in approved_findings if f.get("line")}
    reasons, stats = [], dict(files=0, added=0, removed=0, approved_edits=0, comma_edits=0, new_files=0)
    for fd in parse_unified(patch):
        old, new = _strip(fd["old"]), _strip(fd["new"])
        path = new or old
        stats["files"] += 1
        if new is None:
            reasons.append(f"{old}: deletes a whole file")
            continue
        if old is None:
            stats["new_files"] += 1
        if any(fnmatch.fnmatch(path, p) for p in protected):
            reasons.append(f"{path}: touches a protected path")
        for hunk in fd["hunks"]:
            i = 0
            while i < len(hunk):
                if hunk[i][0] != "-" and hunk[i][0] != "+":
                    i += 1
                    continue
                removed, added = [], []
                while i < len(hunk) and hunk[i][0] == "-":
                    removed.append(hunk[i]); i += 1
                while i < len(hunk) and hunk[i][0] == "+":
                    added.append(hunk[i]); i += 1
                stats["removed"] += len(removed)
                stats["added"] += len(added)
                for a in added:
                    for rx, why in BANNED_RX:
                        if rx.search(a[3]):
                            reasons.append(f"{path}:{a[2]}: {why}: {a[3].strip()[:80]}")
                for k, r in enumerate(removed):
                    repl = added[k][3] if k < len(added) else None
                    if repl is not None and repl.rstrip() == r[3].rstrip() + ",":
                        stats["comma_edits"] += 1
                        continue
                    if (path, r[1]) in approved_lines:
                        if repl is None:
                            reasons.append(f"{path}:{r[1]}: approved line was deleted instead of fixed")
                            continue
                        kept = kept_ratio(r[3], repl)
                        if kept < min_kept:
                            reasons.append(f"{path}:{r[1]}: approved line was replaced by unrelated code (kept {kept:.0%} of its code)")
                            continue
                        stats["approved_edits"] += 1
                        continue
                    reasons.append(f"{path}:{r[1]}: removes or rewrites user code that no approved finding covers: {r[3].strip()[:80]}")
    if stats["added"] > max_added:
        reasons.append(f"patch adds {stats['added']} lines (limit {max_added})")
    return dict(passed=not reasons, reasons=reasons, stats=stats)
