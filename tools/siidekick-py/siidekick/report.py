"""Self-contained HTML report."""
import html
import os

SEV_COLOR = {"critical": "#b42318", "high": "#c4320a", "medium": "#b54708", "low": "#475467"}
STATUS_COLOR = {"fixed": "#067647", "needs review": "#b54708", "your action": "#475467"}


def esc(s):
    return html.escape(str(s if s is not None else ""))


def _rows(findings):
    out = []
    for f in findings:
        loc = f["file"] + (f":{f['line']}" if f["line"] else "")
        status = f.get("status", "")
        out.append(f"""<tr>
<td><span class="pill" style="background:{SEV_COLOR.get(f['severity'], '#475467')}">{esc(f['severity'])}</span></td>
<td><b>{esc(f['title'])}</b><div class="muted">{esc(f['cwe'])} · {esc(f['owasp'])} · {esc(f['rule'])}</div>
<div class="why">{esc(f['explain'])}</div><div class="fix"><b>Fix:</b> {esc(f['fix'])}</div></td>
<td><code>{esc(loc)}</code>{'<pre>' + esc(f['snippet']) + '</pre>' if f['snippet'] else ''}</td>
<td>{'<span class="pill" style="background:' + STATUS_COLOR.get(status, '#475467') + '">' + esc(status) + '</span>' if status else ''}</td>
</tr>""")
    return "\n".join(out)


def _diff_html(patch):
    lines = []
    for l in patch.splitlines():
        cls = "add" if l.startswith("+") and not l.startswith("+++") else "del" if l.startswith("-") and not l.startswith("---") else "hdr" if l.startswith(("@@", "---", "+++")) else ""
        lines.append(f'<span class="{cls}">{esc(l)}</span>')
    return "\n".join(lines)


def render(result, title="Siidekick security report"):
    b, a, g = result["before"], result["after"], result["guard"]
    fixed = [f for f in b["findings"] if f.get("status") == "fixed"]
    left = [f for f in b["findings"] if f.get("status") != "fixed"]
    counts = lambda r: " · ".join(f"{v} {k}" for k, v in r["counts"].items() if v) or "none"
    ver = result["verification"]
    ver_html = "".join(f"<li>{'PASS' if v['ok'] else 'FAIL'} - {esc(v['check'])}: <code>{esc(v['file'])}</code> {esc(v['detail'])}</li>" for v in ver) or "<li>No files changed.</li>"
    guard_html = ("<p class='ok'>PASSED: the patch only adds code, or edits lines that approved findings point at.</p>" if g["passed"]
                  else "<p class='bad'>REJECTED - nothing was applied:</p><ul>" + "".join(f"<li>{esc(r)}</li>" for r in g["reasons"]) + "</ul>")
    s = g["stats"]
    skipped_html = "".join(f"<li>{esc(x['finding'])}: {esc(x['reason'])}</li>" for x in result["skipped"])
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)}</title><style>
body{{font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;margin:0;background:#f7f7f5;color:#1d2939}}
main{{max-width:1100px;margin:0 auto;padding:28px 20px 60px}}h1{{font-size:24px;margin:0 0 4px}}h2{{font-size:18px;margin:32px 0 10px}}
.muted{{color:#667085;font-size:12.5px}}.cards{{display:flex;gap:14px;flex-wrap:wrap;margin:18px 0}}
.card{{background:#fff;border:1px solid #e4e7ec;border-radius:10px;padding:14px 18px;min-width:200px;flex:1}}
.big{{font-size:38px;font-weight:700}}.arrow{{font-size:28px;align-self:center;color:#98a2b3}}
table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e4e7ec;border-radius:10px;overflow:hidden}}
td,th{{text-align:left;vertical-align:top;padding:10px 12px;border-bottom:1px solid #eaecf0}}th{{background:#f2f4f7;font-size:13px}}
.pill{{color:#fff;border-radius:999px;padding:2px 9px;font-size:12px;white-space:nowrap}}
.why{{margin-top:4px}}.fix{{margin-top:4px;color:#344054}}pre{{margin:6px 0 0;white-space:pre-wrap;word-break:break-all;font-size:12px;background:#f2f4f7;padding:6px 8px;border-radius:6px}}
code{{font-size:12.5px}}.diff{{background:#0c111d;color:#d0d5dd;padding:14px;border-radius:10px;overflow:auto;font:12.5px/1.45 ui-monospace,Menlo,monospace;white-space:pre}}
.add{{color:#75e0a7}}.del{{color:#fda29b}}.hdr{{color:#84adff}}.ok{{color:#067647;font-weight:600}}.bad{{color:#b42318;font-weight:600}}
</style></head><body><main>
<h1>{esc(title)}</h1>
<div class="muted">Project: <code>{esc(os.path.basename(result['project']))}</code> · {b['files_scanned']} files · {b['rules']} built-in rules · tools used: {esc(', '.join(b['tools_used']))}{' · skipped: ' + esc('; '.join(b['tools_skipped'])) if b['tools_skipped'] else ''}</div>
<div class="cards">
<div class="card"><div class="muted">Security score before</div><div class="big" style="color:#b42318">{b['score']}</div><div class="muted">{len(b['findings'])} findings: {esc(counts(b))}</div></div>
<div class="arrow">&rarr;</div>
<div class="card"><div class="muted">Security score after automatic fixes</div><div class="big" style="color:#067647">{a['score']}</div><div class="muted">{len(a['findings'])} findings: {esc(counts(a))}</div></div>
<div class="card"><div class="muted">Fixed automatically</div><div class="big">{len(fixed)}</div><div class="muted">{len(left)} still need you</div></div>
</div>
<p class="muted">Score = 100 × 40 / (40 + penalty), where each finding costs critical 10, high 6, medium 3, low 1. It never claims 100% safety; it shows progress.</p>

<h2>Diff guard (your code is protected)</h2>{guard_html}
<p class="muted">{s['files']} files in patch · {s['added']} lines added · {s['removed']} lines changed ({s['approved_edits']} on approved findings, {s['comma_edits']} comma-only) · {s['new_files']} new files</p>
<h2>Verification</h2><ul>{ver_html}</ul>{'<p class="bad">A check failed, so every change was rolled back.</p>' if result['rolled_back'] else ''}

<h2>Fixed automatically ({len(fixed)})</h2>
<table><tr><th>Severity</th><th>Problem</th><th>Where</th><th>Status</th></tr>{_rows(fixed) or '<tr><td colspan=4>None</td></tr>'}</table>

<h2>Still needs you ({len(left)})</h2>
<p class="muted">These need a decision by a person (for example password re-hashing, key rotation or library upgrades), or the pattern was too complex to change safely.</p>
<table><tr><th>Severity</th><th>Problem</th><th>Where</th><th>Status</th></tr>{_rows(left) or '<tr><td colspan=4>None</td></tr>'}</table>
{('<h2>Not fixed automatically</h2><ul>' + skipped_html + '</ul>') if skipped_html else ''}

<h2>The exact patch ({len(result['changed_files'])} files)</h2>
<div class="diff">{_diff_html(result['patch']) or 'No changes.'}</div>
<p class="muted">Rotate any key or password listed above even after it is moved to .env: once code is shared, the old value must be treated as leaked.</p>
</main></body></html>"""
