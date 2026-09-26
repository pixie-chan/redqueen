

SEV_GLYPH = {"CRITICAL": "✖", "HIGH": "▲", "MEDIUM": "●", "LOW": "○", "INFO": "•"}
ANSI = {"CRITICAL": "\033[1;91m", "HIGH": "\033[91m", "MEDIUM": "\033[93m",
        "LOW": "\033[94m", "INFO": "\033[90m", "reset": "\033[0m",
        "bold": "\033[1m", "dim": "\033[2m", "green": "\033[92m"}


def colorize(s, key, use_color):
    return f"{ANSI[key]}{s}{ANSI['reset']}" if use_color else s


def terminal_report(bot, use_color):
    out = []
    c = use_color
    line = "─" * 72
    out.append(colorize("╭" + line + "╮", "dim", c))
    title = " RED TEAM REPORT  ·  Quant IQ self-assault "
    out.append(colorize("│", "dim", c) + colorize(title.center(72), "bold", c)
               + colorize("│", "dim", c))
    out.append(colorize("╰" + line + "╯", "dim", c))
    sc = bot.score()
    filled = int(round(sc / 5))
    bar = "█" * filled + "░" * (20 - filled)
    out.append(f"  score   {colorize(bar, 'green' if sc >= 80 else 'MEDIUM' if sc >= 50 else 'CRITICAL', c)} {sc}/100")
    counts = bot.counts()
    parts = [colorize(f"{SEV_GLYPH[s]} {counts[s]} {s}", s, c)
             for s in SEV_ORDER if counts[s]]
    out.append("  findings " + "   ".join(parts))
    out.append(f"  requests {bot.t.used}/{bot.t.max_requests}   "
               f"budget {'EXHAUSTED' if bot.stopped else 'ok'}   "
               f"rate-limit responses {bot.t.rate_limited}")
    out.append("")
    shown = sorted(bot.findings, key=lambda f: (SEV_ORDER[f["severity"]],
                                                f["check_id"]))
    if not shown:
        out.append("  ✓ nothing to report. Move to manual and business-logic tests.")
    hdr = f"  {'SEV':<11}{'OWASP':<9}{'FINDING':<42}{'WHERE'}"
    out.append(colorize(hdr, "bold", c))
    out.append("  " + "─" * 68)
    for f in shown:
        sev = f"{SEV_GLYPH[f['severity']]} {f['severity']}"
        where = (f["url"] + (" [" + (f["param"] or "") + "]" if f["param"] else ""))[:56]
        mark = "✓" if f["verified"] else ("?" if f["confidence"] == "medium" else " ")
        out.append("  " + colorize(f"{sev:<11}", f["severity"], c)
                   + f"{f['owasp']:<9}{f['title'][:40]:<42}{where} {mark}")
    out.append("")
    top = [f for f in shown if f["severity"] in ("CRITICAL", "HIGH")][:3] or shown[:3]
    if top:
        out.append(colorize("  ATTACKER NARRATIVE", "bold", c))
        for i, f in enumerate(top, 1):
            out.append(f"   {i}. {f['title']} ({f['severity']}, {f['owasp']})")
            out.append(colorize(f"      -> {f['impact']}", "dim", c))
        out.append("")
        out.append(colorize("  FIX FIRST (in this order)", "bold", c))
        for i, f in enumerate(top, 1):
            out.append(f"   {i}. {f['fix'][:110]}")
    if bot.stopped:
        out.append(colorize(f"\n  ! scan stopped early: {bot.stopped}", "MEDIUM", c))
    return "\n".join(out)


def write_checklist(bot, out_dir):
    counts = bot.counts()
    lines = ["# Security fix checklist", "",
             f"Target: {bot.t.base}{bot.t.path}  |  score {bot.score()}/100  |  "
             f"{counts['CRITICAL']} critical, {counts['HIGH']} high, "
             f"{counts['MEDIUM']} medium, {counts['LOW']} low, "
             f"{counts['INFO']} info", "",
             "Work top to bottom. Re-run the bot after each fix and watch the "
             "score move.", ""]
    order = sorted(bot.findings, key=lambda f: (SEV_ORDER[f["severity"]],
                                                f["check_id"]))
    cur = None
    for f in order:
        if f["severity"] != cur:
            cur = f["severity"]
            lines += [f"## {SEV_GLYPH[cur]} {cur}", ""]
        where = f["url"] + (f" [{f['param']}]" if f["param"] else "")
        lines.append(f"- [ ] **{f['title']}** ({f['owasp']}) `{where}`")
        lines.append(f"      fix: {f['fix']}")
    path = os.path.join(out_dir, "CHECKLIST.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return path


def json_report(bot):
    return json.dumps({
        "tool": {"name": "redteam.py", "version": VERSION},
        "target": bot.t.base + bot.t.path,
        "scope": sorted(bot.t.allow),
        "started_utc": bot.started,
        "finished_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scenario": bot.args.scenario,
        "requests_used": bot.t.used,
        "budget": bot.t.max_requests,
        "stopped_early": bot.stopped,
        "score": bot.score(),
        "counts": bot.counts(),
        "recon": bot.recon,
        "notes": bot.notes,
        "findings": bot.findings,
        "endpoints": sorted(bot.endpoints),
        "js_assets": sorted(bot.js_assets),
        "checks_available": len(CHECKS),
        "checks_fired": sorted({f["check_id"] for f in bot.findings}),
    }, indent=2)
