

HTML_CSS = """
:root{--bg:#0b0e13;--panel:#12161d;--ink:#d7dde6;--mut:#8b94a3;--line:#232a35;
--cr:#ff2d55;--hi:#ff6b35;--me:#ffb020;--lo:#4aa3ff;--in:#7d8590;--acc:#39d98a}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.6 "DejaVu Sans Mono",Consolas,monospace}
.wrap{max-width:1040px;margin:0 auto;padding:34px 26px 80px}
header.top{border-bottom:1px solid var(--line);padding-bottom:22px;margin-bottom:26px}
.kicker{color:var(--acc);font-size:12px;letter-spacing:.22em;text-transform:uppercase}
h1{font-size:26px;margin:8px 0 6px;font-weight:700}
.meta{color:var(--mut);font-size:12.5px}
.meta b{color:var(--ink)}
.grid{display:grid;grid-template-columns:270px 1fr;gap:26px;align-items:start}
@media(max-width:760px){.grid{grid-template-columns:1fr}}
.score\boxed{background:var(--panel);border:1px solid var(--line);padding:22px}
.score{font-size:64px;font-weight:700;line-height:1}
.score small{font-size:18px;color:var(--mut)}
.bar{height:10px;background:#1b212b;margin:16px 0 14px;position:relative}
.bar i{position:absolute;inset:0 auto 0 0;display:block}
.sevrow{display:flex;flex-wrap:wrap;gap:8px;margin-top:6px}
.chip{font-size:11.5px;padding:3px 9px;border:1px solid var(--line);color:var(--ink)}
h2{font-size:13px;letter-spacing:.18em;text-transform:uppercase;color:var(--mut);
margin:34px 0 12px;border-bottom:1px solid var(--line);padding-bottom:7px}
.narr{background:var(--panel);border-left:3px solid var(--acc);padding:14px 18px;
margin-bottom:10px}
.narr b{color:var(--acc)}
.narr div{color:var(--mut);font-size:13px;margin-top:4px}
details.f{background:var(--panel);border:1px solid var(--line);border-left-width:4px;
margin-bottom:9px}
details.f summary{cursor:pointer;padding:11px 15px;display:flex;gap:12px;
align-items:baseline;list-style:none}
details.f summary::-webkit-details-marker{display:none}
.tag{font-size:10.5px;padding:2px 7px;color:#0b0e13;font-weight:700;white-space:nowrap}
.ftitle{font-weight:700}
.fmeta{color:var(--mut);font-size:12px;margin-left:auto;white-space:nowrap}
.fbody{padding:0 15px 15px;border-top:1px solid var(--line);margin-top:2px;
padding-top:12px}
.fbody dt{color:var(--mut);font-size:11px;letter-spacing:.14em;
text-transform:uppercase;margin-top:10px}
.fbody dd{margin:3px 0 0}
pre{background:#0e1218;border:1px solid var(--line);padding:10px 12px;overflow:auto;
font-size:12.5px;white-space:pre-wrap;word-break:break-all}
.fix{color:var(--acc)}
a{color:var(--lo)}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border:1px solid var(--line);padding:7px 10px;text-align:left;vertical-align:top}
th{color:var(--mut);font-weight:600;font-size:11.5px;letter-spacing:.1em;
text-transform:uppercase}
.two{display:grid;grid-template-columns:1fr 1fr;gap:22px}
@media(max-width:760px){.two{grid-template-columns:1fr}}
.muted{color:var(--mut);font-size:13px}
.ok{color:var(--acc)}.bad{color:var(--cr)}
.filt{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 12px}
.filt button{background:var(--panel);color:var(--ink);border:1px solid var(--line);
padding:5px 13px;font:12px/1 "DejaVu Sans Mono",monospace;cursor:pointer;
letter-spacing:.08em}
.filt button.on{border-color:var(--acc);color:var(--acc)}
"""


def esc(s):
    return htmllib.escape(str(s or ""))


def html_report(bot):
    counts = bot.counts()
    score = bot.score()
    sev_css = {"CRITICAL": "var(--cr)", "HIGH": "var(--hi)", "MEDIUM": "var(--me)",
               "LOW": "var(--lo)", "INFO": "var(--in)"}
    shown = sorted(bot.findings, key=lambda f: (SEV_ORDER[f["severity"]],
                                                f["check_id"]))
    narr = [f for f in shown if f["severity"] in ("CRITICAL", "HIGH")][:3] or shown[:3]
    rows = []
    for f in shown:
        col = sev_css[f["severity"]]
        refs = " ".join(f'<a href="{esc(u)}">{esc(u.split("/")[2])}</a>'
                        for u in f.get("refs", []))
        rows.append(f"""<details class="f" data-sev="{f['severity']}"
 style="border-left-color:{col}">
<summary><span class="tag" style="background:{col}">{f['severity']}</span>
<span class="ftitle">{esc(f['title'])}</span>
<span class="fmeta">{esc(f['owasp'])} · {esc(f['check_id'])} ·
{'verified' if f['verified'] else esc(f['confidence'])}</span></summary>
<div class="fbody"><dl>
<dt>Where</dt><dd>{esc(f['url'])}{(' · param ' + esc(f['param'])) if f['param'] else ''}</dd>
<dt>Why it matters</dt><dd>{esc(f['impact'])}</dd>
{f'<dt>Detail</dt><dd>{esc(f["detail"])}</dd>' if f['detail'] else ''}
<dt>Evidence</dt><dd><pre>{esc(f['evidence'])}</pre></dd>
<dt>Exact fix</dt><dd class="fix">{esc(f['fix'])}</dd>
<dt>Reference</dt><dd>{refs}</dd>
</dl></div></details>""")
    owasp_rows = "".join(
        f"<tr><td>{k}:2025</td><td>{esc(v)}</td></tr>" for k, v in OWASP.items())
    fired = {f['check_id'] for f in bot.findings}
    cov = "".join(
        f"<tr><td>{esc(cid)}</td><td>{esc(CHECKS[cid][2])}</td>"
        f"<td class='{'ok' if cid in fired else ''}'>"
        f"{'FIRED' if cid in fired else 'clean / not applicable'}</td></tr>"
        for cid in sorted(CHECKS))
    recon = "".join(f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>"
                    for k, v in bot.recon)
    notes = "".join(f"<li>{esc(n)}</li>" for n in bot.notes[:40])
    barcol = "var(--acc)" if score >= 80 else ("var(--me)" if score >= 50 else "var(--cr)")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Red team report · {esc(bot.t.host)}</title>
<style>{HTML_CSS}</style></head><body><div class="wrap">
<header class="top">
<div class="kicker">authorized self-assessment · redteam.py v{VERSION}</div>
<h1>Attack simulation report</h1>
<div class="meta">target <b>{esc(bot.t.base + bot.t.path)}</b> ·
scope <b>{esc(', '.join(sorted(bot.t.allow)))}</b> ·
scenario <b>{esc(bot.args.scenario)}</b> ·
finished <b>{esc(bot.started)}</b> UTC ·
requests <b>{bot.t.used}/{bot.t.max_requests}</b></div>
</header>
<div class="grid">
<div class="scorebox">
<div class="kicker">security score</div>
<div class="score" style="color:{barcol}">{score}<small>/100</small></div>
<div class="bar"><i style="width:{score}%;background:{barcol}"></i></div>
<div class="sevrow">{''.join(f'<span class="chip" style="border-color:{sev_css[s]};color:{sev_css[s]}">{counts[s]} {s}</span>' for s in SEV_ORDER)}</div>
<p class="muted">weighted: critical −25, high −12, medium −5, low −2;
unverified critical/high count half.</p>
</div>
<div>
<h2>Attacker narrative</h2>
{''.join(f'<div class="narr"><b>{i}. {esc(f["title"])}</b> ({f["severity"]}, {f["owasp"]})<div>{esc(f["impact"])}</div></div>' for i, f in enumerate(narr, 1)) or '<div class="muted">No exploitable path found by the automated pass.</div>'}
<h2>Findings ({len(shown)})</h2>
<div class="filt">{''.join(f"<button class='{'on' if s == 'ALL' else ''}' onclick=\"ff('{s}',this)\">{s}</button>" for s in ["ALL"] + list(SEV_ORDER))}
</div>
{''.join(rows) or '<div class="muted">Nothing to report. Automated coverage is a subset of a real assessment: finish with manual access-control, business-logic and abuse-case testing.</div>'}
</div></div>
<h2>OWASP Top 10:2025 mapping</h2>
<table><tr><th>ID</th><th>Category</th></tr>{owasp_rows}</table>
<div class="two">
<div><h2>Check coverage</h2>
<table><tr><th>Check</th><th>What it probes</th><th>Result</th></tr>{cov}</table></div>
<div><h2>Recon</h2><table><tr><th>Item</th><th>Value</th></tr>{recon}</table>
<h2>Engine notes</h2><ul class="muted">{notes or '<li>none</li>'}</ul></div>
</div>
<h2>Method and safety rails</h2>
<p class="muted">Scope gate: every request host must match the allowlist, or it is
never sent. Rate limit {bot.args.rps} req/s with jitter, hard budget
{bot.t.max_requests} requests, identifiable User-Agent, benign payloads only
(canaries, error signatures, echo markers), no brute force, no DoS, no data
modification, robots.txt honored during discovery. Critical/high findings are
re-tested once; failures are downgraded to candidate.
Standards: OWASP Top 10:2025, OWASP WSTG, OWASP Cheat Sheet Series,
NIST SP 800-115, PTES.</p>
<p class="muted">redteam.py v{VERSION} · generated for the owner of
{esc(bot.t.host)} · re-run after each fix to confirm the score moves.</p>
</div></body></html>"""
