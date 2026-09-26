#!/usr/bin/env python3
"""Generate docs/ARCHITECTURE.html (dossier page) + standalone figure SVGs.

Direction: industrial dossier, LUNAR-TIE approved tokens
  graphite #0b0d11 ground (cold, B>R), muted amber #d9a45f single accent,
  Archivo display + JetBrains Mono numerals, leader-line annotations,
  left-aligned labels, reduced glow, hairline panels, 4px radius.
Run: python3 docs/build-arch-html.py
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))

# ---- palette (also mirrored in tokens.css + page :root) ----
BG, SURF, SURF2 = "#0b0d11", "#12161e", "#171c26"
LINE, LINE2 = "#262d3a", "#3a4356"
INK, INK2, INK3 = "#e7eaf0", "#aeb6c4", "#7b8494"
ACC = "#d9a45f"          # single accent: gates, primary path, fig index
RED, GREEN, TEAL = "#cf5c63", "#6fae8f", "#69a8a3"   # muted semantic set
MONO = "JetBrains Mono, monospace"
SANS = "Archivo, sans-serif"

def esc(t):
    return (t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;"))

def txt(x, y, s, size=13, fill=INK, weight=400, family=SANS, anchor="start",
        ls=None, extra=""):
    a = f' text-anchor="{anchor}"' if anchor != "start" else ""
    l = f' letter-spacing="{ls}"' if ls else ""
    return (f'<text x="{x}" y="{y}" font-family="{family}" '
            f'font-size="{size}" font-weight="{weight}" fill="{fill}"{a}{l}{extra}>'
            f'{esc(s)}</text>')

def halo_txt(x, y, s, size=12, fill=INK2, family=MONO, anchor="middle"):
    """label sitting on an arrow: halo of BG for readability"""
    a = f' text-anchor="{anchor}"' if anchor != "start" else ""
    return (f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" '
            f'fill="{fill}"{a} stroke="{BG}" stroke-width="4" '
            f'paint-order="stroke" stroke-linejoin="round">{esc(s)}</text>')

def panel(x, y, w, title, sub=None, kind="panel", h=None, title_dy=24):
    """hairline node. sub = list of mono lines. kind: panel|key|red|green|
    teal|dash|ghost|input"""
    sub = sub or []
    hh = h or (30 + title_dy + 20 * len(sub) + (8 if sub else 6))
    stroke, fill, dash = LINE, SURF, ""
    if kind == "key":      stroke, fill = INK2, SURF2
    elif kind == "red":    stroke = RED
    elif kind == "green":  stroke = GREEN
    elif kind == "teal":   stroke = TEAL
    elif kind == "dash":   stroke, dash = ACC, ' stroke-dasharray="5 4"'
    elif kind == "ghost":  stroke, fill = LINE2, "none"
    elif kind == "input":  stroke, fill = LINE2, SURF
    g = [f'<rect x="{x}" y="{y}" width="{w}" height="{hh}" rx="4" '
         f'fill="{fill}" stroke="{stroke}" stroke-width="1.25"{dash}/>']
    g.append(txt(x + 14, y + title_dy, title, 14, INK, 700))
    for i, s in enumerate(sub):
        g.append(txt(x + 14, y + title_dy + 20 + 18 * i, s, 12, INK3,
                     family=MONO))
    return "".join(g), hh

def diamond(cx, cy, w, h, lines, stroke=ACC):
    pts = f"{cx},{cy-h//2} {cx+w//2},{cy} {cx},{cy+h//2} {cx-w//2},{cy}"
    g = [f'<polygon points="{pts}" fill="{SURF}" stroke="{stroke}" '
         f'stroke-width="1.25"/>']
    n = len(lines)
    y0 = cy - (n - 1) * 9 + 5
    for i, s in enumerate(lines):
        g.append(txt(cx, y0 + i * 18, s, 13, INK, 600, anchor="middle"))
    return "".join(g)

def stadium(x, y, w, h, title):
    return (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{h//2}" '
            f'fill="{SURF}" stroke="{INK2}" stroke-width="1.25"/>'
            + txt(x + w / 2, y + h / 2 + 5, title, 14, INK, 700,
                  anchor="middle"))

def cyl(x, y, w, h, title, sub=None):
    sub = sub or []
    ry = 10
    g = [f'<path d="M{x},{y+ry} A{w//2},{ry} 0 0 1 {x+w},{y+ry} '
         f'L{x+w},{y+h-ry} A{w//2},{ry} 0 0 1 {x},{y+h-ry} Z" '
         f'fill="{SURF}" stroke="{LINE2}" stroke-width="1.25"/>',
         f'<ellipse cx="{x+w//2}" cy="{y+ry}" rx="{w//2}" ry="{ry}" '
         f'fill="{SURF2}" stroke="{LINE2}" stroke-width="1.25"/>',
         txt(x + w / 2, y + ry + 26, title, 14, INK, 700, anchor="middle")]
    for i, s in enumerate(sub or []):
        g.append(txt(x + w / 2, y + ry + 48 + 18 * i, s, 12, INK3,
                     family=MONO, anchor="middle"))
    return "".join(g)

def para(x, y, w, h, lines):
    """parallelogram artifact block"""
    sk = 16
    pts = (f"{x+sk},{y} {x+w},{y} {x+w-sk},{y+h} {x},{y+h}")
    g = [f'<polygon points="{pts}" fill="{SURF2}" stroke="{INK2}" '
         f'stroke-width="1.25"/>']
    for i, s in enumerate(lines):
        g.append(txt(x + w / 2 + 2, y + h / 2 + 5 - (len(lines)-1) * 10 + i * 20,
                     s, 13, INK, 600, anchor="middle"))
    return "".join(g)

_MARKERS = {}
def arrow(pts, kind="sec", label=None, label_at=None, dash=None):
    """polyline with marker. kind: acc|sec|red|green|teal"""
    color = {"acc": ACC, "sec": LINE2, "red": RED, "green": GREEN,
             "teal": TEAL}[kind]
    mid = f"m-{kind}"
    if mid not in _MARKERS:
        _MARKERS[mid] = mid
    d = f' stroke-dasharray="{dash}"' if dash else ""
    xs = [p[0] for p in pts]; ys = [p[1] for p in pts]
    poly = " ".join(f"{x},{y}" for x, y in pts)
    g = [f'<polyline points="{poly}" fill="none" stroke="{color}" '
         f'stroke-width="{1.6 if kind=="acc" else 1.25}"{d} '
         f'marker-end="url(#{mid})"/>']
    if label:
        if label_at is not None:
            x, y = pts[label_at]
        elif len(pts) == 2:
            x = (pts[0][0] + pts[1][0]) // 2
            y = (pts[0][1] + pts[1][1]) // 2
        else:
            x, y = pts[len(pts) // 2]
        g.append(halo_txt(x, y - 9, label, 12,
                          ACC if kind == "acc" else INK2))
    return "".join(g)

def marker_defs():
    out = []
    for k, c in [("acc", ACC), ("sec", LINE2), ("red", RED),
                 ("green", GREEN), ("teal", TEAL)]:
        out.append(
            f'<marker id="m-{k}" viewBox="0 0 10 10" refX="9" refY="5" '
            f'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
            f'<path d="M0,0 L10,5 L0,10 z" fill="{c}"/></marker>')
    return "".join(out)

def leader(x, y, tx, ty, label, anchor="start"):
    """annotation: dot + hairline + mono label (LUNAR-TIE pattern)"""
    line = f'<line x1="{x}" y1="{y}" x2="{tx}" y2="{ty}" stroke="{LINE2}" stroke-width="1"/>'
    dot = f'<circle cx="{x}" cy="{y}" r="2.5" fill="{ACC}"/>'
    off = 7 if anchor == "start" else -7
    return line + dot + txt(tx + off, ty + 4, label, 12, INK2, family=MONO,
                            anchor=anchor)

def ruler(w, y, step=16):
    ticks = []
    for x in range(0, w + 1, step):
        h = 7 if x % (step * 4) == 0 else 3.5
        ticks.append(f'<line x1="{x}" y1="{y}" x2="{x}" y2="{y+h}" '
                     f'stroke="{LINE}" stroke-width="1"/>')
    return f'<line x1="0" y1="{y}" x2="{w}" y2="{y}" stroke="{LINE}" stroke-width="1"/>' + "".join(ticks)

def _uniq_markers(svg, n):
    import re as _re
    return _re.sub(r"\bm-(acc|sec|red|green|teal)\b",
                   lambda m: f"m{n}-{m.group(1)}", svg)


def svg_doc(w, h, body, cls="fig-svg"):
    return (f'<svg viewBox="0 0 {w} {h}" width="{w}" height="{h}" '
            f'role="img" class="{cls}" xmlns="http://www.w3.org/2000/svg">'
            f'<defs>{marker_defs()}</defs>{body}</svg>')


# ==================== FIG 1: scan pipeline ====================
def fig1():
    w, h = 1040, 1050
    b = []
    # spine
    b.append(stadium(110, 24, 310, 46, "CLI invocation"))
    b.append(leader(420, 47, 462, 40, "target · allow · scenario"))
    b.append(diamond(265, 150, 300, 84, ["scope gate", "host in allowlist?"]))
    # branches
    p_blocked, hh = panel(500, 110, 260, "request never sent",
                          ["recorded as note"], kind="red")
    b.append(p_blocked)
    b.append(arrow([(415, 150), (500, 150)], kind="red", label="no"))
    b.append(arrow([(265, 192), (265, 235), (498, 235)], kind="sec"))
    b.append(halo_txt(452, 226, "in scope, no flag", 12, INK2))
    p_passive, hh = panel(500, 235, 260, "passive mode",
                          ["recon groups only"], kind="input")
    b.append(p_passive)
    # active path
    b.append(arrow([(265, 192), (265, 300)], kind="acc", label="yes"))
    p_tr, hh = panel(110, 300, 310, "Transport",
                     ["5 req/s + jitter · budget 500",
                      "1 retry · redirect re-check"])
    b.append(p_tr)
    b.append(arrow([(265, 403), (265, 430)], kind="acc"))
    p_disc, hh = panel(110, 430, 310, "Discovery",
                       ["3 passes + optional sources"])
    b.append(p_disc)
    b.append(arrow([(265, 513), (265, 540)], kind="acc"))
    p_run, hh = panel(110, 540, 310, "Runners",
                      ["12 groups · 63 checks"])
    b.append(p_run)
    b.append(arrow([(265, 623), (265, 658)], kind="acc"))
    b.append(diamond(265, 700, 280, 84, ["verify pass", "CRITICAL or HIGH?"]))
    p_down, hh = panel(500, 660, 270, "downgrade",
                       ["one level · confidence low"], kind="dash")
    b.append(p_down)
    b.append(arrow([(405, 700), (500, 700)], kind="sec", label="not reproduced"))
    b.append(arrow([(265, 742), (265, 780)], kind="acc", label="reproduced"))
    p_score, hh = panel(110, 780, 310, "dedupe + score",
                        ["score out of 100", "C25 H12 M5 L2"])
    b.append(p_score)
    b.append(arrow([(635, 743), (635, 850), (422, 850)], kind="sec"))
    b.append(para(110, 935, 360, 76,
                  ["terminal · report.html", "report.json · CHECKLIST.md"]))
    b.append(arrow([(265, 903), (265, 935)], kind="acc"))
    # passive + blocked converge on output via right rails
    b.append(arrow([(760, 150), (830, 150), (830, 990), (472, 990)],
                   kind="red"))
    b.append(arrow([(760, 275), (880, 275), (880, 970), (472, 970)],
                   kind="sec"))
    b.append(ruler(w, 1030))
    return svg_doc(w, h, "".join(b))


# ==================== FIG 2: discovery engine ====================
def fig2():
    w, h = 1060, 570
    b = []
    b.append(stadium(30, 60, 145, 44, "seed URL"))
    p1, _ = panel(230, 40, 250, "PASS 1 · BFS crawl",
                  ["robots · sitemap + gzip", "forms · params · JS URLs"])
    b.append(p1)
    p2, _ = panel(540, 40, 240, "PASS 2 · JS mining",
                  ["fetch same-origin bundles", "extract /api routes"])
    b.append(p2)
    p3, _ = panel(830, 40, 200, "PASS 3", ["probe mined routes"])
    b.append(p3)
    b.append(arrow([(175, 82), (230, 82)], kind="acc"))
    b.append(arrow([(480, 90), (540, 90)], kind="acc", label="mine"))
    b.append(arrow([(780, 90), (830, 90)], kind="acc"))
    b.append(cyl(830, 210, 200, 100, "stores",
                 ["pages · URLs", "params · forms · endpoints"]))
    b.append(arrow([(930, 123), (930, 210)], kind="acc", label="results"))
    # wayback branch
    b.append(arrow([(300, 143), (300, 245)], kind="teal", dash="2 6"))
    b.append(halo_txt(300, 195, "optional: Wayback", 12, INK2))
    wb, _ = panel(230, 245, 250, "Wayback CDX",
                  ["scope filter"], kind="teal")
    b.append(wb)
    rc, _ = panel(540, 245, 240, "re-crawl", ["historical URLs"])
    b.append(rc)
    b.append(arrow([(480, 295), (540, 295)], kind="sec"))
    b.append(arrow([(780, 286), (830, 286)], kind="sec"))
    # CT branch routed around the left
    b.append(arrow([(230, 100), (185, 100), (185, 455), (230, 455)],
                   kind="teal", dash="2 6"))
    b.append(halo_txt(185, 300, "optional: CT logs", 12, INK2))
    ct, _ = panel(230, 405, 270, "crt.sh then Cert Spotter",
                  ["+ DNS resolve"], kind="teal")
    b.append(ct)
    dg, _ = panel(560, 435, 240, "dangling subdomain",
                  ["report only"], kind="dash")
    b.append(dg)
    b.append(arrow([(500, 455), (560, 455)], kind="sec"))
    b.append(leader(800, 475, 860, 500, "takeover candidate"))
    b.append(ruler(w, 560))
    return svg_doc(w, h, "".join(b))


# ==================== FIG 3: codebase ====================
def fig3():
    w, h = 1080, 1015
    b = []
    def slice_card(y, name, rows, hi=False):
        s, _ = panel(40, y, 430, name, rows, kind="key" if hi else "panel")
        return s
    b.append(slice_card(60, "CORE", [
        "p1 head + constants ....... 70",
        "p2a CHECKS registry ....... 81",
        "p2b groups + scenarios ... 145"]))
    b.append(slice_card(203, "ENGINE", [
        "p3 transport ............. 226",
        "p4 bot + discovery ....... 418"]))
    b.append(slice_card(326, "CHECKS · 802 LOC", [
        "p5 headers/CORS/JWT ...... 229",
        "p6 TLS/exposures ......... 175",
        "p7 injection ............. 205",
        "p8 secrets/auth .......... 193"], hi=True))
    b.append(slice_card(489, "OUTPUT", [
        "p9 terminal/JSON ......... 108",
        "p10 HTML report .......... 156"]))
    b.append(slice_card(612, "CLI", ["p11 runners + parser ..... 149"]))
    for y1, y2 in [(183, 203), (306, 326), (469, 489), (592, 612)]:
        b.append(arrow([(255, y1), (255, y2)], kind="sec"))
    # build + product at column bottom
    bd, _ = panel(40, 740, 430, "build.sh",
                  ["ordered cat + compile check"], kind="acc")
    b.append(bd)
    b.append(arrow([(255, 695), (255, 740)], kind="acc", label="assemble"))
    pr, _ = panel(40, 860, 430, "redteam.py",
                  ["2155 lines · stdlib only"], kind="key")
    b.append(pr)
    b.append(arrow([(255, 823), (255, 860)], kind="acc"))
    # QA column
    b.append(f'<rect x="560" y="60" width="470" height="400" rx="4" '
             f'fill="none" stroke="{LINE2}" stroke-width="1.25" '
             f'stroke-dasharray="6 5"/>')
    b.append(txt(578, 86, "QA · proves the build", 13, INK3, 600,
                 family=MONO))
    hs, _ = panel(585, 110, 420, "qx_harness.py (397)",
                  ["weak / strong / TLS target"], kind="input")
    b.append(hs)
    us, _ = panel(585, 220, 420, "unit_sources.py (78)",
                  ["network stubbed"], kind="input")
    b.append(us)
    qp, _ = panel(585, 330, 420, "qa.py (233)",
                  ["16 assertion gates"], kind="acc")
    b.append(qp)
    b.append(arrow([(1005, 150), (1016, 150), (1016, 372), (1007, 372)],
                   kind="sec"))
    b.append(arrow([(795, 303), (795, 330)], kind="sec"))
    ex, _ = panel(560, 540, 380, "examples/",
                  ["sample reports + checklist"], kind="key")
    b.append(ex)
    b.append(arrow([(795, 433), (795, 505), (750, 505), (750, 538)],
                   kind="acc"))
    # product -> QA validation route
    b.append(arrow([(470, 905), (540, 905), (540, 530), (660, 530),
                    (660, 462)], kind="acc", label="proven by",
                   label_at=1))
    # research
    b.append(cyl(620, 700, 320, 110, "research corpus",
                 ["150+ sources"]))
    b.append(arrow([(780, 810), (780, 985), (255, 985), (255, 966)],
                   kind="teal", dash="4 4", label="grounding",
                   label_at=1))
    b.append(ruler(w, 1000))
    return svg_doc(w, h, "".join(b))


# ==================== FIG 4: check engine ====================
def fig4():
    w, h = 1040, 1095
    b = []
    b.append(cyl(110, 30, 310, 120, "CHECKS registry",
                 ["63 entries", "id · OWASP · severity · fix"]))
    b.append(leader(420, 95, 455, 70, "source of truth"))
    steps = [(190, "GROUPS", ["12 check groups"]),
             (303, "SCENARIOS", ["recon · headers · misconfig",
                                 "injection · auth · api · full"]),
             (446, "RUNNERS dispatch", ["select by scenario"]),
             (549, "check_* functions", ["bot.get with throttle"]),
             (652, "bot.add", ["dedupe: check + path + param",
                               "secrets redacted"])]
    prev_bottom = 150
    for y, title, subs in steps:
        s, hh = panel(110, y, 310, title, subs)
        b.append(s)
        b.append(arrow([(265, prev_bottom), (265, y)], kind="acc"))
        prev_bottom = y + hh
    # severity decision
    b.append(diamond(265, 800, 300, 88, ["severity is",
                                          "CRITICAL or HIGH?"]))
    b.append(arrow([(265, prev_bottom), (265, 756)], kind="acc"))
    b.append(arrow([(415, 800), (470, 800), (470, 640), (563, 640)],
                   kind="sec", label="yes", label_at=1))
    # re-test decision (right column)
    b.append(diamond(700, 640, 270, 84, ["re-test:", "reproduced?"]))
    ok, _ = panel(850, 520, 175, "verified", [], kind="green")
    b.append(ok)
    b.append(arrow([(835, 640), (850, 570)], kind="green", label="yes"))
    dn, _ = panel(850, 680, 185, "downgrade", ["confidence low"],
                  kind="dash")
    b.append(dn)
    b.append(arrow([(835, 640), (850, 715)], kind="sec", label="no"))
    # findings store
    b.append(arrow([(265, 844), (265, 880)], kind="acc",
                   label="lower severity"))
    b.append(cyl(110, 880, 310, 110, "findings list",
                 ["verified + candidates"]))
    b.append(arrow([(937, 581), (937, 845), (265, 845), (265, 878)],
                   kind="green"))
    b.append(halo_txt(937, 760, "verified", 12, INK2))
    b.append(arrow([(942, 763), (942, 862), (330, 862), (330, 878)],
                   kind="sec"))
    b.append(halo_txt(942, 800, "downgraded", 12, INK2))
    # outputs
    sc, _ = panel(560, 880, 310, "score / 100",
                  ["critical 25 · high 12", "medium 5 · low 2"],
                  kind="key")
    b.append(sc)
    b.append(arrow([(422, 915), (560, 915)], kind="acc", label="weighs"))
    b.append(para(560, 1015, 340, 56,
                  ["terminal · html · json · checklist"]))
    b.append(arrow([(715, 983), (715, 1015)], kind="acc", label="formats"))
    b.append(ruler(w, 1080))
    return svg_doc(w, h, "".join(b))


# ==================== FIG 5: safety rails ====================
def fig5():
    w, h = 980, 945
    b = []
    b.append(stadium(60, 30, 300, 46, "outgoing request"))
    own, _ = panel(560, 30, 300, "ownership flag",
                   ["required for active groups"], kind="input")
    b.append(own)
    b.append(arrow([(560, 72), (395, 72), (395, 52), (212, 52), (212, 96)],
                   kind="sec", dash="4 4"))
    b.append(halo_txt(470, 63, "gates active checks", 12, INK2))
    b.append(diamond(210, 140, 300, 84, ["host matches", "allowlist?"]))
    b.append(arrow([(210, 76), (210, 98)], kind="acc"))
    rd, _ = panel(560, 180, 300, "request blocked", ["never sent"],
                  kind="red")
    b.append(rd)
    b.append(arrow([(360, 140), (470, 140), (470, 221), (558, 221)],
                   kind="red", label="no", label_at=1))
    b.append(diamond(210, 270, 260, 80, ["budget left?"]))
    b.append(arrow([(210, 182), (210, 228)], kind="acc", label="yes"))
    bx, _ = panel(560, 300, 300, "budget exhausted",
                  ["stop · report still ships"], kind="dash")
    b.append(bx)
    b.append(arrow([(340, 270), (470, 270), (470, 350), (558, 350)],
                   kind="red", label="no", label_at=1))
    th, _ = panel(60, 390, 300, "throttle", ["5 req/s + jitter"])
    b.append(th)
    b.append(arrow([(210, 310), (210, 390)], kind="acc", label="yes"))
    b.append(diamond(210, 540, 280, 84, ["robots disallow?", "crawl phase"]))
    b.append(arrow([(210, 473), (210, 498)], kind="acc"))
    rb, _ = panel(560, 500, 300, "path skipped", ["robots rule"],
                  kind="dash")
    b.append(rb)
    b.append(arrow([(350, 540), (560, 540)], kind="red", label="yes"))
    b.append(diamond(210, 670, 300, 84, ["payload class", "benign?"]))
    b.append(arrow([(210, 582), (210, 628)], kind="acc", label="no"))
    ok, _ = panel(60, 810, 300, "ALLOWED",
                  ["canaries · echo markers",
                   "error signatures · benign GET/POST"], kind="green")
    b.append(ok)
    b.append(arrow([(210, 712), (210, 810)], kind="acc", label="benign"))
    no, _ = panel(560, 790, 300, "NOT IMPLEMENTED",
                  ["DoS · brute force · data writes",
                   "destructive SQL · shell exec"], kind="red")
    b.append(no)
    b.append(f'<rect x="560" y="790" width="300" height="103" rx="4" '
             f'fill="none" stroke="{RED}" stroke-width="1.25" '
             f'stroke-dasharray="5 4"/>')
    b.append(arrow([(360, 670), (470, 670), (470, 840), (558, 840)],
                   kind="red"))
    b.append(halo_txt(470, 745, "destructive", 12, INK2))
    b.append(ruler(w, 930))
    return svg_doc(w, h, "".join(b))


# ==================== FIG 6: QA loop ====================
def fig6():
    w, h = 1080, 640
    b = []
    b.append(f'<rect x="40" y="40" width="430" height="575" rx="4" '
             f'fill="none" stroke="{LINE2}" stroke-width="1.25" '
             f'stroke-dasharray="6 5"/>')
    b.append(txt(58, 68, "targets under test", 13, INK3, 600, family=MONO))
    inputs = [(95, "weak harness", ["54 known findings"]),
              (195, "strong harness", ["hardened"]),
              (295, "weak + TLS", ["10-day self-signed"]),
              (395, "passive run", ["ownership flag off"]),
              (495, "unit_sources.py", ["network stubbed"])]
    for y, title, subs in inputs:
        s, _ = panel(65, y, 380, title, subs, kind="input")
        b.append(s)
        mid = y + 42
        b.append(arrow([(445, mid), (590, 330)], kind="sec"))
    # edge labels (explicit positions, computed from the same source)
    edge_labels = [(95, "vulnerable target"), (195, "hardened target"),
                   (295, "TLS target"), (395, "passive target"),
                   (495, "stubbed network")]
    for y, lab in edge_labels:
        mid = y + 42
        lx = 505
        ly = mid + (330 - mid) * ((lx - 445) / (590 - 445)) - 10
        b.append(halo_txt(lx, ly, lab, 12, INK2))
    b.append(diamond(720, 330, 270, 90, ["qa.py", "16 assertion gates"]))
    p_ok, _ = panel(880, 240, 185, "ALL PASS", ["exit 0 · samples ok"],
                    kind="green")
    b.append(p_ok)
    b.append(arrow([(855, 312), (880, 285)], kind="green", label="pass",
                   label_at=1))
    p_no, _ = panel(880, 400, 185, "FAIL", ["release blocked"],
                    kind="red")
    b.append(p_no)
    b.append(arrow([(855, 348), (880, 435)], kind="red", label="fail",
                   label_at=1))
    b.append(ruler(w, 630))
    return svg_doc(w, h, "".join(b))


FIGS = [
    ("fig1", "FIG.01", "Scan pipeline",
     "Every request clears the scope gate before it exists; the report ships "
     "even when the scan stops early.", fig1),
    ("fig2", "FIG.02", "Discovery engine",
     "Three passes feed one store: linked surface, JavaScript-mined API routes, "
     "then optional read-only historical and certificate sources.", fig2),
    ("fig3", "FIG.03", "Codebase",
     "Twelve build slices, one assembly step, one artifact of 2,155 lines; "
     "every layer is proven by the QA gate it feeds.", fig3),
    ("fig4", "FIG.04", "Check engine",
     "One registry drives groups, scenarios and fixes; only re-tested "
     "critical and high findings keep full weight.", fig4),
    ("fig5", "FIG.05", "Safety rails",
     "Gates run in order at 5 req/s, and the destructive payload classes "
     "are not implemented at all, only documented as absent.", fig5),
    ("fig6", "FIG.06", "QA loop",
     "Five targets, one gate, zero tolerance: any miss blocks the release.",
     fig6),
]


# ==================== HTML shell ====================
CSS = """
:root{--bg:#0b0d11;--surface:#12161e;--surface-2:#171c26;--line:#262d3a;
--line-2:#3a4356;--ink:#e7eaf0;--ink-2:#aeb6c4;--ink-3:#7b8494;
--accent:#d9a45f;--red:#cf5c63;--green:#6fae8f;--teal:#69a8a3;
--mono:"JetBrains Mono",monospace;--sans:"Archivo",system-ui,sans-serif;
--r:4px;--w:1120px}
*{box-sizing:border-box}
html{background:var(--bg)}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);
font-size:16px;line-height:1.6;-webkit-font-smoothing:antialiased}
.wrap{max-width:var(--w);margin:0 auto;padding:56px 28px 90px}
.kicker{font-family:var(--mono);font-size:12px;letter-spacing:.22em;
text-transform:uppercase;color:var(--accent);margin:0 0 18px}
h1{font-size:clamp(2.1rem,4.6vw,3.3rem);font-weight:800;line-height:1.12;
margin:0 0 18px;letter-spacing:-.01em}
.lede{color:var(--ink-2);font-size:1.06rem;max-width:64ch;margin:0 0 26px}
.meta{display:flex;flex-wrap:wrap;gap:8px 26px;font-family:var(--mono);
font-size:13px;color:var(--ink-2);font-variant-numeric:tabular-nums;
padding:14px 0;border-top:1px solid var(--line);
border-bottom:1px solid var(--line)}
.meta b{color:var(--ink);font-weight:600}
.ruler{height:9px;border-top:1px solid var(--line);
background-image:repeating-linear-gradient(90deg,var(--line) 0 1px,transparent 1px 16px);
background-size:100% 5px;background-repeat:no-repeat;margin:44px 0 0;opacity:.9}
.idx{display:flex;flex-wrap:wrap;gap:10px;margin:26px 0 0;padding:0;list-style:none}
.idx a{display:inline-block;font-family:var(--mono);font-size:12.5px;
color:var(--ink-2);text-decoration:none;border:1px solid var(--line);
border-radius:var(--r);padding:13px 16px;min-height:44px;
transition:border-color .15s,
color .15s,transform .15s}
.idx a:hover{border-color:var(--accent);color:var(--accent);
transform:translateY(-1px)}
.idx a:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.legend{margin:34px 0 0;padding:18px 20px;background:var(--surface);
border:1px solid var(--line);border-radius:var(--r)}
.legend .lgh{font-family:var(--mono);font-size:12px;letter-spacing:.16em;
text-transform:uppercase;font-weight:600;margin:0 0 12px;display:block}
.legend .lgh-old{font-family:var(--mono);font-size:12px;letter-spacing:.16em;
text-transform:uppercase;color:var(--ink-2);margin:0 0 12px;font-weight:600}
.legend .row{display:flex;flex-wrap:wrap;gap:10px 22px;align-items:center}
.sw{display:inline-flex;align-items:center;gap:8px;font-size:13px;
color:var(--ink)}
.sw i{width:13px;height:13px;border-radius:3px;border:1.5px solid;
display:inline-block}
.legend .shapes{margin-top:12px;font-family:var(--mono);font-size:12px;
color:var(--ink-2)}
figure{margin:0;padding-top:8px}
.fig-head{display:flex;align-items:baseline;gap:18px;margin:0 0 4px}
.fig-idx{font-family:var(--mono);font-size:13px;color:var(--accent);
letter-spacing:.1em;white-space:nowrap}
.fig-head h2{font-size:1.45rem;font-weight:700;margin:0}
figure figcaption{color:var(--ink-2);font-size:.95rem;max-width:72ch;
margin:10px 0 0;padding-left:14px;border-left:2px solid var(--line-2)}
.figbox{margin-top:14px;background:var(--surface);border:1px solid var(--line);
border-radius:var(--r);padding:18px 14px;overflow-x:auto}
.figbox svg{display:block;width:100%;height:auto;min-width:860px}
.scrollhint{display:none;font-family:var(--mono);font-size:11.5px;
color:var(--ink-3);margin-top:8px}
footer{margin-top:56px;padding-top:20px;border-top:1px solid var(--line);
font-family:var(--mono);font-size:12px;color:var(--ink-3);
display:flex;flex-wrap:wrap;gap:8px 24px;font-variant-numeric:tabular-nums}
footer a{color:var(--ink-2);text-decoration:none;
border-bottom:1px solid var(--line-2);display:inline-block;
padding:12px 6px;min-height:44px;box-sizing:border-box}
footer a:hover{color:var(--accent);border-color:var(--accent)}
footer a:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
@media (max-width:760px){
  .wrap{padding:36px 16px 70px}
  .fig-head{flex-direction:column;gap:4px}
  .scrollhint{display:block}
}
@media (prefers-reduced-motion:no-preference){
  .rise{animation:rise .5s cubic-bezier(.22,1,.36,1) both}
  @keyframes rise{from{opacity:0;transform:translateY(14px)}to{opacity:1;
  transform:none}}
}
"""

def build_html():
    figs_html = []
    for i, (fid, fidx, ftitle, claim, fn) in enumerate(FIGS):
        art = fn()
        art = _uniq_markers(art, i + 1)
        art = art.replace('role="img" class="fig-svg"',
                          f'role="img" aria-label="{esc(ftitle)}: '
                          f'{esc(claim)}" class="fig-svg"', 1)
        figs_html.append(f"""
<figure id="{fid}">
  <div class="fig-head"><span class="fig-idx">{fidx}</span>
  <h2>{esc(ftitle)}</h2></div>
  <div class="figbox">{art}</div>
  <div class="scrollhint">scroll figure sideways on small screens</div>
  <figcaption>{esc(claim)}</figcaption>
</figure>""")
        if i < len(FIGS) - 1:
            figs_html.append('<div class="ruler" aria-hidden="true"></div>')
    nav = "".join(
        f'<li><a href="#{fid}">{fidx} {esc(ftitle)}</a></li>'
        for fid, fidx, ftitle, _c, _f in FIGS)
    legend = """
<div class="legend">
  <h2 class="lgh">Legend</h2>
  <div class="row">
    <span class="sw"><i style="border-color:#d9a45f;background:#12161e"></i>gate / primary path (amber)</span>
    <span class="sw"><i style="border-color:#cf5c63;background:#12161e"></i>blocked / forbidden (red)</span>
    <span class="sw"><i style="border-color:#6fae8f;background:#12161e"></i>verified / allowed (green)</span>
    <span class="sw"><i style="border-color:#69a8a3;background:#12161e"></i>external source (teal)</span>
    <span class="sw"><i style="border-color:#3a4356;background:#171c26"></i>artifact (keyed panel)</span>
  </div>
  <div class="shapes">shapes: stadium = start/end · diamond = decision ·
  cylinder = data store · parallelogram = artifact · dashed outline =
  degraded or report-only · dotted line = optional or reference</div>
</div>"""
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="Architecture dossier for redteam.py: how the
scan pipeline, discovery engine, check engine, safety rails and QA loop fit
together.">
<title>redteam.py · architecture dossier</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='6' fill='%230b0d11'/%3E%3Cpath d='M9 24V8h9a5 5 0 0 1 0 10h-4l6 6h-5l-6-6v6z' fill='%23d9a45f'/%3E%3C/svg%3E">
<meta property="og:type" content="website">
<meta property="og:title" content="redteam.py · architecture dossier">
<meta property="og:description" content="Six figures on how the scope-gated red team simulator works: pipeline, discovery, codebase, check engine, safety rails, QA loop.">
<meta property="og:image" content="diagrams/01-run-flow.png">
<style>{CSS}</style>
</head>
<body>
<div class="wrap">
<header class="rise">
  <p class="kicker">redqueen / architecture</p>
  <h1>How redteam.py works</h1>
  <p class="lede">Six figures, one claim each: a scope-gated scan pipeline
  throttled to 5 req/s, a three-pass discovery engine, twelve slices assembling
  into one dependency-free file of 2,155 lines, a registry-driven check engine,
  rails that make destructive payloads unreachable, and a QA gate that blocks
  any release it cannot prove.</p>
  <div class="meta">
    <span><b>v1.1.0</b></span><span><b>2,155</b> lines</span>
    <span><b>63</b> checks</span><span><b>16/16</b> QA gates</span>
    <span><b>0</b> dependencies</span><span>stdlib only</span>
  </div>
  <nav aria-label="figure index"><ul class="idx">{nav}</ul></nav>
  {legend}
</header>
<main>{''.join(figs_html)}</main>
<div class="ruler" aria-hidden="true"></div>
<footer>
  <span>redteam.py v1.1.0</span>
  <span>generated by docs/build-arch-html.py</span>
  <a href="ARCHITECTURE.md">mermaid + png version</a>
  <a href="../README.md">README</a>
  <span>graphite / amber · Archivo + JetBrains Mono</span>
</footer>
</div>
</body>
</html>
"""


def main():
    out_html = os.path.join(HERE, "ARCHITECTURE.html")
    with open(out_html, "w", encoding="utf-8") as fh:
        fh.write(build_html())
    svg_dir = os.path.join(HERE, "diagrams", "svg")
    os.makedirs(svg_dir, exist_ok=True)
    for fi, (fid, fidx, ftitle, _c, fn) in enumerate(FIGS):
        raw = fn()
        raw = _uniq_markers(raw, fi + 1)
        raw = raw.replace('role="img" class="fig-svg"',
                          f'role="img" aria-label="{esc(ftitle)}" '
                          f'class="fig-svg"', 1)
        import re as _re
        m = _re.search(r'viewBox="0 0 (\d+) (\d+)" width="\d+" '
                       r'height="\d+"', raw)
        vw, vh = int(m.group(1)), int(m.group(2))
        strip = 52
        raw = raw.replace(m.group(0),
                          f'viewBox="0 0 {vw} {vh + strip}" '
                          f'width="{vw}" height="{vh + strip}"', 1)
        head, rest = raw.split("</defs>", 1)
        inner = rest.rsplit("</svg>", 1)[0]
        bar = (f'<rect width="100%" height="100%" fill="{BG}"/>'
               f'<rect x="0" y="0" width="{vw}" height="{strip}" '
               f'fill="{SURF2}"/>'
               f'<line x1="0" y1="{strip}" x2="{vw}" y2="{strip}" '
               f'stroke="{LINE2}" stroke-width="1"/>'
               + txt(20, 33, fidx, 14, ACC, 700, family=MONO)
               + txt(112, 33, ftitle, 16, INK, 700)
               + txt(vw - 20, 32, "redteam.py v1.1.0", 12, INK3,
                     family=MONO, anchor="end"))
        out = (head + "</defs>" + bar
               + f'<g transform="translate(0,{strip})">' + inner + "</g></svg>")
        with open(os.path.join(svg_dir, fid + ".svg"), "w",
                  encoding="utf-8") as fh:
            fh.write(out)
    print("wrote", out_html)
    print("wrote 6 standalone svg files to", svg_dir)


if __name__ == "__main__":
    main()
