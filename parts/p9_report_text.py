

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
    title = " RED TEAM REPORT  ·  placeholder_website self-assault "
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
    shown = sorted(bot.scored(), key=lambda f: (SEV_ORDER[f["severity"]],
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
    ev = bot.evidence_records()
    if ev:
        out.append("")
        out.append(colorize("  EVIDENCE RECORDS (not scored, not counted)",
                            "dim", c))
        for f in ev:
            out.append(colorize(f"   · {f['check_id']} [{f['param'] or ''}] "
                                f"{f['evidence'][:96]}", "dim", c))
    out.append("")
    out.extend(scan_quality_lines(bot, c))
    st = bot.auth_state.get("state", "not-checked")
    out.append("    auth  " + colorize(st, "green" if st == "verified"
                                       else "MEDIUM", c) + ": " +
               (bot.auth_state.get("reason") or "no auth verdict this run"))
    cov = coverage_statement(bot)
    out.append("    " + colorize(coverage_line(bot, cov), "dim", c))
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
    order = sorted(bot.scored(), key=lambda f: (SEV_ORDER[f["severity"]],
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


# R2 coverage accounting. NEVER_TESTED is static and deliberate: these
# vulnerability classes are out of scope for an automated pass, and saying
# so out loud is more honest than a green tick.
NEVER_TESTED = [
    {"class": "DoS and resource exhaustion",
     "reason": "no denial-of-service testing at all: a bot that hammers a "
               "host is indistinguishable from an attack"},
    {"class": "API6 sensitive business flows",
     "reason": "workflow logic (payments, refunds, limits, state machines) "
               "needs a human who knows the intended business rules"},
    {"class": "DOM and browser-only XSS",
     "reason": "no JavaScript engine here: DOM sinks, prototype pollution and "
               "client-side storage need a real browser session"},
    {"class": "request smuggling escalation",
     "reason": "only the detection half is in scope; storing a poisoned "
               "response or poisoning a response queue would mutate shared "
               "infrastructure and can affect other users"},
    {"class": "cross-account mutation",
     "reason": "proving cross-account access needs two owner-provided "
               "accounts, and the bot only ever has anonymous plus at most "
               "one --cookie identity"},
    {"class": "HTTP/2 CONTINUATION flood and Rapid Reset",
     "reason": "these are availability attacks by construction; active "
               "probing is refused, and http.client cannot speak HTTP/2"},
]
# checks that a scenario can nominally run but that can never fire on this
# target shape. Used as the reason string when coverage says not tested.
NOT_TESTED_CONDITION = {
    "no-tls": "only observable on an http:// target",
    "hdr-hsts": "only observable on an https:// target",
    "cookie-secure": "only observable on an https:// target",
    "cookie-plaintext": "only observable on an http:// target",
    "tls-legacy": "needs a TLS endpoint to downgrade",
    "tls-expiry": "needs a TLS endpoint",
    "tls-unverified": "needs a TLS endpoint",
    "mixed-content": "only observable on an https:// target",
    "subdomain-dangling": "only runs with --ct-log",
}


def coverage_statement(bot):
    """One row per check id in CHECKS: was it exercised this run, and if not,
    why not. Exercised means it fired, or its group is part of the scenario
    and therefore ran (and found nothing)."""
    fired = bot.fired_check_ids()
    if getattr(bot, "replayed", False):
        scope = set(PASSIVE_SCOPE)
    else:
        scope = set()
        for group in SCENARIOS.get(bot.args.scenario, []):
            scope.update(GROUPS.get(group, []))
    rows = []
    for cid in sorted(CHECKS):
        owasp, sev, title, _impact, _fix = CHECKS[cid]
        tested = cid in fired or cid in scope
        if tested:
            reason = ""
        elif cid in NOT_TESTED_CONDITION:
            reason = NOT_TESTED_CONDITION[cid]
        else:
            reason = (f"not exercised by scenario '{bot.args.scenario}'"
                      if not getattr(bot, "replayed", False)
                      else "not exercised: a passive replay only runs the "
                           "response-only checks")
        rows.append({"check_id": cid, "owasp": owasp, "severity": sev,
                     "title": title, "tested": tested, "reason": reason})
    return rows


def coverage_line(bot, rows):
    done = sum(1 for r in rows if r["tested"])
    return (f"coverage: {done}/{len(rows)} checks exercised, "
            f"{len(NEVER_TESTED)} classes never tested by design")


def scan_quality_lines(bot, use_color):
    """Terminal SCAN QUALITY block."""
    out = [colorize("  SCAN QUALITY", "bold", use_color)]
    if not bot.warnings:
        out.append("    " + colorize("ok  no scan-quality warnings",
                                     "green", use_color))
        return out
    for w in bot.warnings:
        out.append("    " + colorize("!", "MEDIUM", use_color) + " " +
                   f"{w['code']:<22} {w['message']}")
    return out


def json_report(bot):
    coverage = coverage_statement(bot)
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
        "calibration": bot.calibration.profile(),
        "auth_state": bot.auth_state,
        "passive": {"replay": bool(getattr(bot, "replayed", False)),
                    "requests_used": bot.t.used,
                    "zero_requests": bot.t.used == 0,
                    "responses_replayed": len(bot.pages) if
                    getattr(bot, "replayed", False) else 0},
        "warnings": bot.warnings,
        "degraded_checks": bot.degraded,
        "coverage": coverage,
        "coverage_summary": coverage_line(bot, coverage),
        "never_tested": NEVER_TESTED,
        "notes": bot.notes,
        "findings": bot.findings,
        "evidence_records": [{"id": f["id"], "check_id": f["check_id"],
                              "url": f["url"], "param": f["param"],
                              "evidence": f["evidence"]}
                             for f in bot.evidence_records()],
        "endpoints": sorted(bot.endpoints),
        "js_assets": sorted(bot.js_assets),
        "checks_available": len(CHECKS),
        "checks_fired": sorted(bot.fired_check_ids()),
        # Tier A + C output. Anomalies are review material, never findings,
        # so they are reported in their own key and counted in nothing.
        "anomalies": getattr(bot, "anomalies", []) or [],
        "anomaly_requests": getattr(bot, "anomaly_requests", 0),
        "anomaly_routes": getattr(bot, "anomaly_routes", []) or [],
        "tierc": getattr(bot, "tierc", []) or [],
        "tierb": dict(getattr(bot, "tierb", {}) or {}),
    }, indent=2)
