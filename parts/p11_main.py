

RUNNERS = {
    "recon": [check_sectxt],
    "tls": [check_tls],
    "headers": [check_headers, check_host_header],
    "cors": [check_cors],
    "cookies": [check_cookies],
    "jwt": [check_jwt],
    "secrets": [check_secrets],
    "sweep": [check_global_sweep],
    "exposures": [check_exposures, check_stacktrace, check_graphql],
    "injection": [check_injection],
    "auth": [check_auth, check_ratelimit],
    "client": [check_client],
    "methods": [check_methods],
    "anomaly": [check_anomaly],
    "tierc": [run_tierc],
"tierb": [check_desync_cells, check_unicode_oracles,
              check_delimiter_confusion, check_api_states],
}

# A passive replay can only judge what a stored response already contains,
# so it runs exactly these: header policy, cookie policy, sourcemap
# references, secrets, and the global sweep. Nothing here sends a request.
PER_RESPONSE_RUNNERS = [check_headers, check_cookies, check_client]
WHOLE_SET_RUNNERS = [check_secrets, check_global_sweep]
PASSIVE_SCOPE = frozenset(GROUPS["headers"] + GROUPS["cookies"] +
                          GROUPS["secrets"] + GROUPS["client"] +
                          ["exp-sourcemap", "global-secret-sweep"])


def run_passive_replay(bot):
    """M7: judge stored responses only. bot.t.used must stay 0 throughout."""
    files = getattr(bot.args, "passive_html", None) or []
    bot.load_passive_files(files)
    bot.enter_replay()
    bot.calibration.learn()          # reuses a stored response, sends nothing
    judged = 0
    try:
        for url, r in list(bot.pages.items()):
            if r is None:
                continue
            judged += 1
            bot.replay_base = url
            for fn in PER_RESPONSE_RUNNERS:
                try:
                    fn(bot)
                except BudgetExceeded:
                    raise
                except Exception as e:
                    bot.degrade(fn.__name__, f"{type(e).__name__}: {e}")
        bot.replay_base = None
        for fn in WHOLE_SET_RUNNERS:
            try:
                fn(bot)
            except BudgetExceeded:
                raise
            except Exception as e:
                bot.degrade(fn.__name__, f"{type(e).__name__}: {e}")
        # re-test inside the replay: a verify closure must never reach the
        # transport, it answers from the stored response
        try:
            bot.verify_findings()
        except BudgetExceeded:
            raise
        except Exception as e:
            bot.degrade("verify_findings", f"{type(e).__name__}: {e}")
    finally:
        bot.exit_replay()
    used = bot.t.used
    if used:
        bot.note(f"passive replay contract violated: {used} request(s) were "
                 f"sent, it must stay at 0")
    bot.add("global-secret-sweep", url=bot.t.base, param="passive-replay",
            internal=True, severity="INFO",
            evidence=f"passive replay judged {judged} stored response(s) with "
                     f"the response-only checks, requests sent: {used}")
    bot.recon.append(("passive replay", f"{judged} responses, {used} requests"))
    return used


def scan_quality(bot):
    """M20: turn this run's shape into explicit, machine-readable warnings."""
    statuses = bot.status_counts
    if bot.responses_seen and statuses and all(s in (401, 403) for s in statuses):
        bot.warn("all_unauthorized",
                 f"every one of the {bot.responses_seen} responses was 401 or "
                 f"403, so nothing was actually tested: fix the session or the "
                 f"credentials and re-run")
    soft, live = bot.soft404_audit()
    if soft and not live:
        bot.warn("everything_soft_404",
                 f"all {soft} captured responses match the learned not-found "
                 f"profile (HTTP {bot.calibration.status}): the crawl found no "
                 f"real content")
    live_pages = [u for u, r in bot.pages.items() if r.status < 400]
    if not live_pages:
        bot.warn("no_pages_crawled",
                 f"no response under HTTP 400 was captured out of "
                 f"{len(bot.pages)} attempted: the target may be down, "
                 f"misrouted, or entirely behind auth")
    if bot.stopped:
        bot.warn("budget_exhausted",
                 f"the request budget ran out before the run finished: "
                 f"{bot.stopped}")
    if bot.degraded:
        bot.warn("checks_degraded",
                 f"{len(bot.degraded)} check(s) hit the guarded() error path "
                 f"and did not finish: {'; '.join(bot.degraded[:3])}")


def build_parser():
    p = argparse.ArgumentParser(
        prog="redteam.py",
        description="Authorized red team simulator for a website YOU own. "
                    "Finds vulnerabilities, prints the exact fix.",
        epilog="Exit codes: 3 = internal error or a scan-quality warning "
               "under --strict-warnings, 2 = critical findings, "
               "1 = high findings, 0 = clean.")
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
    p.add_argument("--passive", action="store_true",
                   help="passive replay: judge stored responses and "
                        "--passive-html files, issue zero requests")
    p.add_argument("--passive-html", action="append", default=[],
                   metavar="FILE",
                   help="saved HTML to replay offline, repeatable")
    p.add_argument("--tierb", action="store_true",
                   help="also run the Tier B surface-hunting modules "
                        "(anomalies only, they never change the score)")
    p.add_argument("--desync-probe", action="store_true",
                   help="walk the CL/TE/0 length-interpretation cells with a "
                        "canary (Tier B; off by default, sends nothing)")
    p.add_argument("--allow-h2-probe", action="store_true",
                   help="relax reporting for the H2 desync cell; still sends "
                        "nothing, because http.client is HTTP/1.1 only")
    p.add_argument("--desync-path",
                   help="path for the desync cells (default: the target path)")
    p.add_argument("--delimiter-path",
                   help="path for the delimiter-confusion probes (default: "
                        "the first crawled GET path)")
    p.add_argument("--api-spec",
                   help="local JSON OpenAPI 3 document for the API state walk")
    p.add_argument("--allow-spec-post", action="store_true",
                   help="allow POST (never PUT/PATCH/DELETE) against spec "
                        "operations marked post, with dummy bodies only")
    p.add_argument("--anomaly", action="store_true",
                   help="run the Tier A anomaly engine regardless of scenario")
    p.add_argument("--anomaly-cap", type=int, default=5, metavar="N",
                   help="max anomalies reported per route (clamped to 20)")
    p.add_argument("--anomaly-keep-all", action="store_true",
                   help="skip the anomaly noise filter, for debugging")
    p.add_argument("--tierc-candidates", metavar="FILE",
                   help="tierc: JSON candidate file to document (never "
                        "executed)")
    p.add_argument("--tierc-dir", default="research", metavar="DIR",
                   help="tierc: directory for generated dossiers")
    p.add_argument("--tierc-from-anomalies", action="store_true",
                   help="tierc: run the anomaly engine first, then write one "
                        "dossier per anomaly")
    p.add_argument("--strict-warnings", action="store_true",
                   help="any scan-quality warning turns an otherwise clean "
                        "run into exit code 3")
    p.add_argument("--auth-verify-url",
                   help="URL fetched once to decide whether --cookie is really "
                        "authenticated (default: the target)")
    p.add_argument("--auth-marker",
                   help="string that only appears on a logged-in page, used by "
                        "the auth verify predicate")
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
    """M18 exit-code contract: 0 clean, 1 any HIGH, 2 any CRITICAL, 3 an
    internal error escaping the run (or any warning under --strict-warnings).
    SystemExit still propagates: those are operator errors, not scan results.
    """
    try:
        return _run(args)
    except SystemExit:
        raise
    except Exception as e:
        sys.stderr.write(f"internal error: {type(e).__name__}: {e}\n")
        return 3


def _run(args):
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
    if args.passive:
        mode = "passive-replay"
    elif args.scenario == "tierc":
        # Tier C is documentation-only: it needs no ownership flag because it
        # never sends a request, so it must not be demoted to passive recon.
        mode = "research"
    elif not args.i_own_this:
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
        who = getattr(fn, "__name__", "check")
        try:
            fn(bot)
        except BudgetExceeded as e:
            bot.stopped = str(e)
        except OutOfScope as e:
            bot.note(f"scope violation blocked: {e}")
            bot.degrade(who, "out-of-scope request blocked")
        except Exception as e:
            bot.note(f"check degraded ({type(e).__name__}): {e}")
            bot.degrade(who, f"{type(e).__name__}: {e}")

    # Tier C with a candidate file is documentation-only: discovery would
    # send requests to learn nothing the dossier uses. Every other scenario
    # discovers first, then runs its groups.
    tierc_docs_only = (args.scenario == "tierc"
                       and bool(getattr(args, "tierc_candidates", None)))
    if args.passive:
        run_passive_replay(bot)
    elif tierc_docs_only:
        bot.note("tier C: candidate file supplied, discovery skipped so the "
                 "whole run sends zero requests")
    else:
        guarded(lambda b: b.discover())
        guarded(lambda b: b.verify_auth())

    # A passive replay has already judged everything it can judge, inside the
    # replay sandbox. Running the scenario loop afterwards would put the full
    # check set back on a live transport, which is exactly what --passive
    # exists to prevent.
    if args.passive:
        pass
    elif not tierc_docs_only:
        groups = list(SCENARIOS[args.scenario])
        # --anomaly forces the Tier A engine on regardless of the scenario,
        # and never replaces the scenario's own groups
        if getattr(args, "anomaly", False) and "anomaly" not in groups:
            groups.append("anomaly")
        if getattr(args, "tierb", False) and "tierb" not in groups:
            groups.append("tierb")
        if bot.stopped is None:
            for group in groups:
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
    else:
        # documentation only: the dossier writer still has to run
        for fn in RUNNERS["tierc"]:
            guarded(fn)
    bot.downgrade_cookie_confidence()
    scan_quality(bot)

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
    if args.strict_warnings and bot.warnings:
        return 3
    return 0


def main(argv=None):
    args = build_parser().parse_args(argv)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
