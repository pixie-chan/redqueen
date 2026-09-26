

RUNNERS = {
    "recon": [check_sectxt],
    "tls": [check_tls],
    "headers": [check_headers, check_host_header],
    "cors": [check_cors],
    "cookies": [check_cookies],
    "jwt": [check_jwt],
    "secrets": [check_secrets],
    "exposures": [check_exposures, check_stacktrace, check_graphql],
    "injection": [check_injection],
    "auth": [check_auth, check_ratelimit],
    "client": [check_client],
    "methods": [check_methods],
}


def build_parser():
    p = argparse.ArgumentParser(
        prog="redteam.py",
        description="Authorized red team simulator for a website YOU own. "
                    "Finds vulnerabilities, prints the exact fix.",
        epilog="Exit codes: 2 = critical findings, 1 = high findings, 0 = clean.")
    p.add_argument("--target", help="https://your-site.example")
    p.add_argument("--allow", action="append", default=[],
                   help="hostname in scope, repeatable or comma separated")
    p.add_argument("--i-own-this", action="store_true",
                   help="confirms you own the target; required for active checks")
    p.add_argument("--scenario", choices=sorted(SCENARIOS), default="full")
    p.add_argument("--rps", type=float, default=5.0, help="requests per second")
    p.add_argument("--max-requests", type=int, default=500, help="hard request budget")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--max-pages", type=int, default=25, help="crawl page cap")
    p.add_argument("--local", action="store_true",
                   help="permit 127.0.0.1/localhost targets")
    p.add_argument("--insecure", action="store_true", help="skip TLS verification")
    p.add_argument("--cookie", help="session cookie for authenticated checks")
    p.add_argument("--respect-robots", dest="respect_robots", action="store_true",
                   default=True)
    p.add_argument("--ignore-robots", dest="respect_robots", action="store_false")
    p.add_argument("--deep-traversal", action="store_true",
                   help="add /etc/passwd traversal probe (off by default)")
    p.add_argument("--traversal-canary",
                   help="filename you planted outside the web root to prove traversal")
    p.add_argument("--report-dir", help="output directory for report.html/.json")
    p.add_argument("--wayback", action="store_true",
                   help="recon historical URLs from the Wayback CDX API "
                        "(passive, one external read-only request)")
    p.add_argument("--ct-log", dest="ct_log", action="store_true",
                   help="subdomain takeover leads from crt.sh certificate "
                        "transparency + DNS only (passive)")
    p.add_argument("--quiet", action="store_true", help="suppress terminal findings")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--list-checks", action="store_true")
    return p


def list_checks():
    print(f"redteam.py v{VERSION}: {len(CHECKS)} checks\n")
    for group, ids in GROUPS.items():
        print(f"[{group}]")
        for cid in ids:
            owasp, sev, title, _impact, _fix = CHECKS[cid]
            print(f"  {cid:<22} {sev:<9} {owasp:<6} {title}")
    print("\nscenarios: " + ", ".join(
        f"{k} ({','.join(v)})" for k, v in SCENARIOS.items()))


def run(args):
    if args.list_checks:
        list_checks()
        return 0
    if not args.target:
        raise SystemExit("--target is required (or use --list-checks)")
    allow = [a for chunk in args.allow for a in str(chunk).replace(";", ",").split(",")]
    if not allow:
        raise SystemExit("--allow is required: name the host you own, "
                         "e.g. --allow yourdomain.example")
    mode = "active"
    if not args.i_own_this:
        mode = "passive"
        args.scenario = "recon"
    t = Transport(args.target, allow, args.rps, args.max_requests,
                  args.timeout, args.insecure, args.local)
    bot = Bot(t, args)
    bot.started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    bot.note(f"mode: {mode} (scenario {args.scenario})")
    if args.cookie:
        bot.note("authenticated checks enabled via --cookie")

    def guarded(fn):
        try:
            fn(bot)
        except BudgetExceeded as e:
            bot.stopped = str(e)
        except OutOfScope as e:
            bot.note(f"scope violation blocked: {e}")
        except Exception as e:
            bot.note(f"check degraded ({type(e).__name__}): {e}")

    guarded(lambda b: b.discover())
    if bot.stopped is None:
        for group in SCENARIOS[args.scenario]:
            for fn in RUNNERS[group]:
                if bot.stopped:
                    break
                guarded(fn)
    if bot.stopped is None:
        guarded(lambda b: b.verify_findings())
    else:
        # still try to verify what we already have, cheaply
        try:
            bot.verify_findings()
        except BudgetExceeded:
            pass

    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    out_dir = args.report_dir or f"rt-report-{ts}"
    os.makedirs(out_dir, exist_ok=True)
    html_path = os.path.join(out_dir, "report.html")
    json_path = os.path.join(out_dir, "report.json")
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html_report(bot))
    with open(json_path, "w", encoding="utf-8") as fh:
        fh.write(json_report(bot))
    list_path = write_checklist(bot, out_dir)

    if not args.quiet:
        use_color = sys.stdout.isatty() and not args.no_color
        print(terminal_report(bot, use_color))
        print(f"\n  report   {os.path.abspath(html_path)}")
        print(f"  json     {os.path.abspath(json_path)}")
        print(f"  checklist {os.path.abspath(list_path)}")
    counts = bot.counts()
    if counts["CRITICAL"]:
        return 2
    if counts["HIGH"]:
        return 1
    return 0


def main(argv=None):
    args = build_parser().parse_args(argv)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
