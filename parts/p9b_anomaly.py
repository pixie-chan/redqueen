# Tier A anomaly engine (Red Queen v2.0).
#
# THE RULE: an anomaly is NOT a vulnerability. Every record this module builds
# goes into bot.anomalies and nowhere else. It never touches bot.findings, so
# counts(), score(), verify_findings() and the exit code cannot see it. The
# only thing an anomaly asks for is a human reading it.

ANOMALY_BANNER = "INTERESTING, NOT A VULNERABILITY: needs human review."
ANOMALY_NOISE_FLOOR = 0.15     # body match above this with no canary echo = noise
ANOMALY_PROBES_PER_ROUTE = 9  # hard cap, prompt 2 step 2
ANOMALY_REQUEST_BUDGET = 120   # hard cap for the whole engine, prompt 2 step 2
ANOMALY_CAP_MAX = 20           # --anomaly-cap ceiling, prompt 2 step 6
ANOMALY_CANARY_RE = re.compile(r"QX[a-f0-9]+")
ANOMALY_CANARY_TOK = "QXCANARY"
ANOMALY_HOST_SUFFIX = ".qx-probe.invalid"
ANOMALY_HEADERS = ("X-Forwarded-Host", "X-Original-URL", "X-Rewrite-URL")
ANOMALY_SUFFIXES = (".css", ".png", ".js")
ANOMALY_METHODS = ("HEAD", "OPTIONS")


def anomaly_norm(text):
    """Body normalization for fingerprinting and matching: canaries to one
    fixed token, then the shared norm() (digit runs of 3+ and whitespace runs
    collapsed). Runs before norm() so a random canary cannot inflate the
    distance on its own."""
    return norm(ANOMALY_CANARY_RE.sub(ANOMALY_CANARY_TOK, text or ""))


def anomaly_header_names(resp):
    """Response header names as a set. set-cookie-list is our own transport
    bookkeeping, not a header the server sent."""
    return {k for k in resp.headers if k != "set-cookie-list"}


def anomaly_not_found(bot, resp):
    """Is this response the site-wide not-found shape? Prefers the R2
    Calibration profile when that release is present, falls back to the v1.1.0
    soft-404 probe. Both mean the same thing here: a difference against this
    shape is routing noise, never a signal."""
    cal = getattr(bot, "calibration", None)
    if cal is not None and hasattr(cal, "is_not_found"):
        try:
            return bool(cal.is_not_found(resp))
        except BudgetExceeded:
            raise
        except Exception:
            pass
    try:
        return bool(is_soft404(bot, resp))
    except BudgetExceeded:
        raise
    except Exception:
        return False


def anomaly_routes(bot):
    """Crawled routes worth probing, target first, then crawl order, capped so
    that cap-per-route x routes stays inside the engine request budget."""
    base = bot.t.base + bot.t.path
    order = []
    if base in bot.pages:
        order.append(base)
    order += [u for u in bot.pages if u != base]
    room = max(1, ANOMALY_REQUEST_BUDGET // ANOMALY_PROBES_PER_ROUTE)
    return order[:room]


def anomaly_baseline(bot, route):
    """Per-route baseline record, taken from the response the crawl already
    holds, so building it costs zero requests."""
    r = bot.pages.get(route)
    if r is None:
        return None
    body = anomaly_norm(r.text)
    return {"route": route, "status": r.status, "length": len(r.body),
            "headers": sorted(anomaly_header_names(r)),
            "header_set": anomaly_header_names(r),
            "content_type": r.header("content-type"),
            "body_fp": hashlib.sha256(body.encode("utf-8", "replace")).hexdigest(),
            "body": body, "resp": r}


def anomaly_probes(route, canary, rotation=0, cap=ANOMALY_PROBES_PER_ROUTE):
    """Probe shapes for one route, in the five classes of the contract:
    header canary, path suffix, path delimiter, method variant, accept
    variant. GET-safe methods only (GET, HEAD, OPTIONS), never a body.

    Every probe carries the per-run canary so canary_reflected means something
    for all five classes: in the header value for class a, as a benign
    qxcanary query parameter for the rest (the path shape stays exactly as
    specified).

    A route may cost at most `cap` requests, and the five classes hold 13
    shapes, so the plan is class balanced: every class offers its first
    variant, then its second, and so on. The rotation shifts each class by the
    route index, so a crawl of several routes exercises all 13 shapes instead
    of starving the tail classes forever.
    """
    p = urllib.parse.urlsplit(route)
    path = p.path or "/"
    host = canary + ANOMALY_HOST_SUFFIX

    def build(new_path):
        q = p.query
        q = (q + "&" if q else "") + "qxcanary=" + canary
        return urllib.parse.urlunsplit((p.scheme, p.netloc, new_path, q, ""))

    def rot(items, n):
        n = n % len(items)
        return items[n:] + items[:n]

    header = [{"probe_class": "header-canary", "variant": h, "method": "GET",
               "url": build(path), "headers": {h: host}}
              for h in ANOMALY_HEADERS]
    suffix = [{"probe_class": "path-suffix", "variant": s, "method": "GET",
               "url": build(path + s), "headers": {}}
              for s in ANOMALY_SUFFIXES]
    # a bare "?" cannot be the last byte of a path (the request line would read
    # it as the query separator), so the trailing question mark goes out
    # percent-encoded and stays a real path byte.
    delimiter = [{"probe_class": "delimiter", "variant": label, "method": "GET",
                  "url": build(path + tail), "headers": {}}
                 for label, tail in (("trailing semicolon", ";"),
                                     ("trailing question mark", "%3f"),
                                     ("trailing dot", "."),
                                     ("percent-encoded dot segment", "/%2e"))]
    method = [{"probe_class": "method", "variant": m, "method": m,
               "url": build(path), "headers": {}}
              for m in ANOMALY_METHODS]
    accept = [{"probe_class": "accept", "variant": "text/plain", "method": "GET",
               "url": build(path), "headers": {"Accept": "text/plain"}}]
    groups = [rot(g, rotation) for g in (header, suffix, delimiter, method,
                                         accept)]
    plan, i = [], 0
    while len(plan) < cap:
        added = False
        for g in groups:
            if i < len(g):
                plan.append(g[i])
                added = True
                if len(plan) >= cap:
                    break
        if not added:
            break
        i += 1
    return plan


def anomaly_probe(bot, route, base, probe, canary, keep_all=False):
    """Run one probe and turn it into a record, or None when the filter says
    the response is noise."""
    r = bot.get(probe["url"], headers=probe["headers"] or None,
                method=probe["method"], follow=True)
    if r is None:
        return None
    if anomaly_not_found(bot, r):
        return None
    ratio = difflib.SequenceMatcher(None, anomaly_norm(r.text),
                                    base["body"]).ratio()
    distance = round(ratio, 3)
    names = anomaly_header_names(r)
    reflected = (canary in r.text
                 or any(canary in str(v) for v in r.headers.values()))
    added = sorted(names - base["header_set"])
    removed = sorted(base["header_set"] - names)
    delta = r.status - base["status"]
    bodyless = not r.body
    if not keep_all and not reflected:
        if distance > ANOMALY_NOISE_FLOOR:
            return None          # body still matches the baseline, nothing echoed
        if bodyless and delta == 0 and not added and not removed:
            # a HEAD (or empty) response has no body to match, so the only
            # remaining evidence is status and headers, and neither moved
            return None
    in_body = canary in r.text
    in_hdr = any(canary in str(v) for v in r.headers.values())
    echo = "body and headers" if (in_body and in_hdr) else \
        ("body" if in_body else "headers")
    match = ("no body to compare" if bodyless
             else f"body match {distance} against baseline")
    note = (f"{probe['variant']} probe: status {r.status} against baseline "
            f"{base['status']} (delta {delta:+d}), {match}, headers "
            f"+{len(added)}/-{len(removed)}, "
            + (f"canary echoed in {echo}" if reflected else "no canary echo")
            + f". {ANOMALY_BANNER}")
    return {"route": route, "probe_class": probe["probe_class"],
            "distance": distance, "status_delta": delta,
            "headers_added": added, "headers_removed": removed,
            "canary_reflected": reflected, "note": note,
            "confidence": "low", "text": ANOMALY_BANNER}


def check_anomaly(bot):
    """Tier A differential engine. One baseline per crawled route, a capped
    set of read-only probes per route, a body match plus header set difference
    per probe, then filter, rank and cap. Findings stay untouched."""
    cap = max(0, min(int(getattr(bot.args, "anomaly_cap", 5) or 0),
                     ANOMALY_CAP_MAX))
    keep_all = bool(getattr(bot.args, "anomaly_keep_all", False))
    canary = bot.canary
    start_used = bot.t.used

    def spent():
        return bot.t.used - start_used

    try:
        for n, route in enumerate(anomaly_routes(bot)):
            if spent() >= ANOMALY_REQUEST_BUDGET:
                bot.note(f"anomaly engine stopped at its {ANOMALY_REQUEST_BUDGET} "
                         f"request budget after {len(bot.anomaly_routes)} routes")
                break
            base = anomaly_baseline(bot, route)
            if base is None:
                continue
            recs, sent, dropped = [], 0, 0
            for probe in anomaly_probes(route, canary, n):
                if spent() >= ANOMALY_REQUEST_BUDGET:
                    bot.note(f"anomaly engine hit its {ANOMALY_REQUEST_BUDGET} "
                             f"request budget on {route}")
                    break
                sent += 1
                rec = anomaly_probe(bot, route, base, probe, canary, keep_all)
                if rec is None:
                    dropped += 1
                else:
                    recs.append(rec)
            # rank ascending by body match, so the responses that drifted
            # furthest from the baseline come first
            kept = sorted(recs, key=lambda r: (r["distance"], r["probe_class"]))[:cap]
            bot.anomalies.extend(kept)
            bot.anomaly_routes.append(
                {"route": route, "status": base["status"],
                 "length": base["length"], "headers": base["headers"],
                 "content_type": base["content_type"],
                 "body_fp": base["body_fp"], "probes": sent,
                 "filtered": dropped, "anomalies": len(kept)})
    finally:
        for rec in (bot.anomalies or []):
            rec.setdefault("tier", "A")
        bot.anomaly_requests = spent()
    bot.recon.append(("anomaly probes", f"{bot.anomaly_requests} requests, "
                        f"{len(bot.anomalies)} anomalies kept"))
    bot.note("anomaly engine: records are review material only, they are not "
             "findings and never move the score, the counts or the exit code")
