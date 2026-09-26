
# ---------- Tier B: empty-taxonomy surface hunting ----------
# CWE-444 has existed since 2008, so the novel part is never a new class
# name, it is a new MECHANISM. TE.0 exists because somebody asked "why is
# there no TE.0?" and then validated the answer against a live target.
# These four modules enumerate the cells nobody has tested instead of
# replaying the classic CL.TE probe.
#
# THE RULE: everything here emits ANOMALIES (bot.anomalies, tier "B"),
# never findings. The single exception is a confirmed desync
# cross-contamination, which IS a finding. Anomalies never touch
# counts(), the score or the exit code.

TIERB_DESYNC_CAP = 8          # hard cap for the whole desync module
TIERB_CHUNK_MAX = 64          # never send a chunked body larger than this
TIERB_BODY_DELTA = 0.15       # normalized body distance that counts as differs
TIERB_STATUS_TOLERANCE = 0    # a status is categorical: any change is a change
TIERB_UNICODE_CAP = 12
TIERB_DELIMITER_CAP = 10
TIERB_API_CAP = 30
DESYNC_CELLS = ("CL", "TE", "0", "H2")


def tierb_base(bot):
    return bot.t.base + (bot.t.path or "/")


def tierb_host_header(bot, url):
    p = urllib.parse.urlsplit(url)
    host = p.hostname or bot.t.host
    default = 443 if p.scheme == "https" else 80
    if p.port and p.port != default:
        return "%s:%d" % (host, p.port)
    return host


def tierb_message(method, target, host_header, headers=None, body=None):
    """Serialize one HTTP/1.1 request as bytes.

    The Tier B probes need byte-exact control of the request line and of
    the framing headers, so they cannot go through http.client: it
    computes its own Content-Length and drops a duplicate one, which is
    exactly the disagreement under test. body is the bytes that follow
    the blank line, never a length of its own.
    """
    lines = ["%s %s HTTP/1.1" % (method, target), "Host: " + host_header,
             "User-Agent: " + UA, "Accept: */*", "Connection: keep-alive"]
    for k, v in (headers or {}).items():
        lines.append("%s: %s" % (k, v))
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("iso-8859-1", "replace")
    if body is None:
        return head
    if isinstance(body, str):
        body = body.encode("utf-8", "replace")
    return head + body


def tierb_distance(a, b):
    """Normalized body distance in [0, 1]. 0 means identical once
    canaries, long digit runs and whitespace are normalized away."""
    return 1.0 - difflib.SequenceMatcher(None, norm(a), norm(b)).ratio()


def tierb_notfound(bot, spend):
    """The not-found profile every Tier B differential is measured against.

    R2 (prompt 1) replaces soft404() with a learned Calibration object.
    Until that lands this reuses the single probe soft404() already caches
    on the bot, so nothing is re-fetched and the two can never disagree
    about what "not found" means on this target."""
    if not hasattr(bot, "_soft404"):
        # R2 replaced the old soft404 cache with the learned Calibration
        # object. Callers unpack (status, text), so hand back that pair
        # from the calibration profile instead of the object itself.
        cal = bot.calibration
        if getattr(cal, "ready", False):
            return (getattr(cal, "status", 404) or 404,
                    getattr(cal, "body", "") or "")
        # nothing learned yet (replay or passive): synthesize from the
        # stored pages so the probe still has a comparison baseline
        for _u, _r in (getattr(bot, "pages", None) or {}).items():
            if _r is not None and _r.status >= 400:
                return _r.status, _r.text
        return 404, ""
    if bot._soft404 is None:
        spend()
    status, text = soft404(bot)
    return status, text


def tierb_send(bot, url, messages, label, method="GET"):
    """One raw keep-alive exchange, with the transport errors folded into
    engine notes instead of taking the module down. Every message sent is
    recorded in bot.tierb["methods"], so a QA gate can assert the verb set
    from the bot side as well as from the server side."""
    try:
        responses = bot.t.raw_exchange(url, messages)
    except BudgetExceeded:
        raise
    except OutOfScope as e:
        bot.note("blocked out-of-scope request: %s" % e)
        return []
    except Exception as e:
        bot.note("%s not sent: %s: %s" % (label, type(e).__name__, e))
        return []
    bot.tierb["methods"].extend([method] * len(messages))
    return responses


def tierb_header_delta(a, b):
    return (sorted(set(b.headers) - set(a.headers)),
            sorted(set(a.headers) - set(b.headers)))


# ---------- module 1: the four length-interpretation cells ----------
def tierb_cell_pair(cell, target, host, marker):
    """The two requests for one cell: a setup request whose body embeds the
    per-run canary, then a follow-up GET with a zero-length body.

    Every cell uses GET, never POST. A body-carrying GET is a perfectly
    good smuggling carrier and cannot mutate server state, which the
    safety rails forbid outright. Content-Length and Transfer-Encoding
    are never both attached to a real body, and the chunked body stays
    under TIERB_CHUNK_MAX bytes.
    """
    if cell == "CL":
        setup = tierb_message("GET", target, host, headers={
            "Content-Type": "application/octet-stream",
            "Content-Length": str(len(marker))}, body=marker)
    elif cell == "TE":
        if len(marker) > TIERB_CHUNK_MAX:
            return None, None
        chunked = "%x\r\n%s\r\n0\r\n\r\n" % (len(marker), marker)
        setup = tierb_message("GET", target, host, headers={
            "Content-Type": "application/octet-stream",
            "Transfer-Encoding": "chunked"}, body=chunked)
    elif cell == "0":
        # implicit zero: a Content-Length that promises bytes this request
        # never carries, so a hop that trusts CL and a hop that defaults
        # to zero disagree about where the message ends
        setup = tierb_message("GET", target, host, headers={
            "Content-Length": str(len(marker))})
    else:
        return None, None
    follow = tierb_message("GET", target, host,
                           headers={"Content-Length": "0"})
    return setup, follow


def check_desync_cells(bot):
    """Probe CL, TE, 0 and H2 in that order, one keep-alive connection per
    cell, at most two requests per cell, at most 8 requests in total.

    A canary that comes back in the follow-up is cross-contamination and
    is the one thing in Tier B that is a finding. Everything else is a
    differential worth a human's time and nothing more, so it is an
    anomaly.
    """
    if not getattr(bot.args, "desync_probe", False):
        bot.add_anomaly(
            "desync-cells", route=tierb_base(bot), probe_class="not-probed",
            note="desync cells were not probed: pass --desync-probe to walk "
                 "the CL, TE, 0 and H2 length-interpretation cells",
            detail="without the flag this module sends nothing at all")
        return

    used = [0]

    def spend():
        used[0] += 1

    def exhausted():
        return used[0] >= TIERB_DESYNC_CAP

    path = getattr(bot.args, "desync_path", None) or bot.t.path or "/"
    if not path.startswith("/"):
        path = "/" + path
    url = bot.t.base + path
    host = tierb_host_header(bot, url)
    marker = bot.canary + secrets.token_hex(3)      # unique per run, inert
    nf_status, nf_text = tierb_notfound(bot, spend)
    bot.tierb["desync_requests"] = used[0]

    # H2 is recorded first so the cell is accounted for even if the cap
    # stops the loop before it. http.client speaks HTTP/1.1 only, so this
    # cell is detection-only: it is never sent, with or without
    # --allow-h2-probe, which relaxes reporting and nothing else.
    relaxed = getattr(bot.args, "allow_h2_probe", False)
    bot.add_anomaly(
        "desync-cells", route=url, probe_class="H2",
        note="skipped: needs an HTTP/2 client" + (
            "; --allow-h2-probe relaxes reporting only, still nothing sent"
            if relaxed else "; nothing was sent for this cell"),
        detail="HTTP/2 gives the frame its own length, so it is a different "
               "mechanism than HTTP/1.1 framing. Test it with a real HTTP/2 "
               "client (nghttp2, h2load) rather than a desync probe here")

    for cell in ("CL", "TE", "0"):
        if exhausted():
            bot.note("desync module stopped at its %d request cap before "
                     "cell %s" % (TIERB_DESYNC_CAP, cell))
            break
        setup, follow = tierb_cell_pair(cell, path, host, marker)
        if setup is None:
            continue
        responses = tierb_send(bot, url, [setup, follow], "desync cell " + cell)
        used[0] += 2
        bot.tierb["desync_requests"] = used[0]
        if not responses:
            bot.note("desync cell %s: no response to the follow-up" % cell)
            continue
        head, tail = responses[0], responses[-1]
        reflected = marker in tail.text
        dist = tierb_distance(tail.text, nf_text)
        delta = tail.status - nf_status
        added, removed = tierb_header_delta(head, tail)
        if reflected:
            f = bot.add(
                "desync-confirmed", url=url,
                evidence="cell %s: the follow-up response carried the canary "
                         "planted by the setup request on the same connection "
                         "(%s). setup status %s, follow-up status %s, %dB"
                         % (cell, marker, head.status, tail.status,
                            len(tail.body)),
                detail="cross-contamination confirmed: one request was "
                       "answered with bytes queued by another. CWE-444, "
                       "https://cwe.mitre.org/data/definitions/444.html",
                verify=lambda: True)
            if f is not None:
                f["refs"].append(
                    "https://cwe.mitre.org/data/definitions/444.html")
            bot.note("desync confirmed in cell %s, remaining cells skipped"
                     % cell)
            return
        if dist > TIERB_BODY_DELTA or delta != 0:
            bot.add_anomaly(
                "desync-cells", route=url, probe_class=cell,
                distance=round(dist, 3), status_delta=delta,
                headers_added=added, headers_removed=removed,
                canary_reflected=False,
                note="cell %s: the follow-up answered status %s against a "
                     "calibrated not-found baseline of %s, body distance %.2f "
                     "from that profile" % (cell, tail.status, nf_status, dist),
                evidence="setup: %s framing carrying marker %s\n"
                         "follow-up: status %s, %dB, distance %.2f\n"
                         "head excerpt: %r\ntail excerpt: %r"
                         % (cell, marker, tail.status, len(tail.body), dist,
                            head.text[:200], tail.text[:200]))


# ---------- module 2: unicode normalization oracles ----------
# U+212A folds to 'K' and U+FF21 folds to 'A' under NFKC; a base letter
# plus U+0301 is the same grapheme as the precomposed character under NFC
# and a different byte string under NFD. A server that stores one form and
# compares against the other can be made to call two strings one identity.
UNICODE_PROBES = (
    ("U+212A", "\u212a"),
    ("U+FF21", "\uff21"),
    ("U+0301", "e\u0301"),
)


def tierb_codepoints(s):
    return " ".join("U+%04X" % ord(ch) for ch in s)


def tierb_codepoint_names(s):
    out = []
    for ch in s:
        try:
            name = unicodedata.name(ch)
        except ValueError:
            name = "<unnamed>"
        out.append("U+%04X %s" % (ord(ch), name))
    return ", ".join(out)


def tierb_folded_forms(value):
    """Every normalized shape of value that is not the value itself, in the
    order a server is most likely to have applied: NFKC, then the
    precomposed form, then the fully decomposed one."""
    forms = [("NFKC", unicodedata.normalize("NFKC", value))]
    forms.append(("NFC", unicodedata.normalize("NFC",
                                              unicodedata.normalize("NFD",
                                                                    value))))
    forms.append(("NFD", unicodedata.normalize("NFD", value)))
    out, seen = [], set()
    for how, form in forms:
        if form != value and form not in seen:
            seen.add(form)
            out.append((how, form))
    return out


def tierb_with_param(url, param, value):
    p = urllib.parse.urlsplit(url)
    q = dict(kv.split("=", 1) if "=" in kv else (kv, "")
             for kv in p.query.split("&") if kv)
    q[param] = value
    return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path,
                                    urllib.parse.urlencode(q, doseq=True),
                                    p.fragment))


def tierb_reflected_targets(bot, limit=4):
    """(url, param) pairs whose original value really is reflected in the
    crawled page.

    A parameter that is swallowed by the server cannot leak a
    normalization oracle, so probing it would spend the request cap for
    nothing. The reflected ones are also the only ones where a folded
    form is meaningful, because the baseline already contains the ASCII
    letter a fold would produce.
    """
    out = []
    for url in sorted(bot.params):
        page = bot.pages.get(url)
        if page is None:
            continue
        text = htmllib.unescape(page.text)
        p = urllib.parse.urlsplit(url)
        pairs = dict(kv.split("=", 1) if "=" in kv else (kv, "")
                     for kv in p.query.split("&") if kv)
        for name in bot.params[url]:
            value = urllib.parse.unquote_plus(pairs.get(name, ""))
            if not value or value not in text:
                continue
            out.append((url, name))
            if len(out) >= limit:
                return out
    return out


def check_unicode_oracles(bot):
    """Send three confusable values to every reflected query parameter and
    compare what came back against what was sent.

    The oracle is not "is the value reflected", it is "is the stored form
    the same as the sent form". A folded form is only interesting where
    the page did not already contain it, so each candidate is checked
    against the crawled baseline for that URL. Every value is inert and
    sent once. Cap: 12 requests.
    """
    targets = tierb_reflected_targets(bot)
    if not targets:
        bot.add_anomaly(
            "unicode-oracle", route=tierb_base(bot), probe_class="no-params",
            note="no reflected query parameter was discovered, so no "
                 "normalization oracle could be tested",
            detail="crawl a page that reflects a query value (a search page "
                   "will do) and re-run with --tierb")
        return
    sent = 0
    for url, param in targets:
        cached = bot.pages.get(url)
        baseline = htmllib.unescape(cached.text) if cached is not None else None
        if baseline is None:
            neutral = tierb_with_param(url, param, "qxprobe")
            base_r = bot.get(neutral)
            sent += 1
            bot.tierb["unicode_requests"] = sent
            baseline = htmllib.unescape(base_r.text) if base_r else ""
        for label, value in UNICODE_PROBES:
            if sent >= TIERB_UNICODE_CAP:
                bot.note("unicode oracle probes stopped at the %d request cap"
                         % TIERB_UNICODE_CAP)
                return
            r = bot.get(tierb_with_param(url, param, value))
            sent += 1
            bot.tierb["unicode_requests"] = sent
            if r is None:
                continue
            text = htmllib.unescape(r.text)
            if value in text:
                continue                      # stored exactly as sent
            for how, form in tierb_folded_forms(value):
                if form in baseline:
                    continue                  # the page already had it
                if form not in text:
                    continue
                bot.add_anomaly(
                    "unicode-oracle", route=url, param=param,
                    probe_class="%s/%s" % (label, how), canary_reflected=True,
                    note="the server returned the %s form of the value "
                         "instead of the bytes that were sent: sent %s, "
                         "stored %s" % (how, tierb_codepoints(value),
                                       tierb_codepoints(form)),
                    detail="an identity comparison between the two forms "
                           "would not match. sent: %s. stored: %s"
                           % (tierb_codepoint_names(value),
                              tierb_codepoint_names(form)),
                    evidence="value=%r returned form=%r" % (value, form))
                break


# ---------- module 3: delimiter confusion ----------
# ; . and %2e are the three a cache and an origin most often normalize
# differently, and the fragment is the one that never belongs on the wire
# at all. A status change is loud; two hops returning different bytes for
# the same status is the cache-poisoning precondition. Cap: 10 requests.
DELIMITER_VARIANTS = (
    ("semicolon", ";"),
    ("query", "?"),
    ("fragment", "#"),
    ("trailing-dot", "."),
    ("encoded-dot", "%2e"),
)


def tierb_delimiter_baseline(bot):
    forced = getattr(bot.args, "delimiter_path", None)
    if forced:
        path = forced if forced.startswith("/") else "/" + forced
        url = bot.t.base + path
        r = bot.pages.get(url) or bot.get(url)
        return (url, urlsplit_path(url), r) if r is not None else (None, None, None)
    for cand in sorted(bot.pages):
        path = urlsplit_path(cand)
        page = bot.pages.get(cand)
        if path and "?" not in path and page is not None and page.status == 200:
            return cand, path, page
    url = tierb_base(bot)
    r = bot.pages.get(url) or bot.get(url)
    return (url, urlsplit_path(url), r) if r is not None else (None, None, None)


def check_delimiter_confusion(bot):
    """Append five delimiter variants to one crawled GET path and see
    whether anything downstream still agrees on what the path is.

    The delimiter goes on the wire exactly as written: a fragment quietly
    stripped by the client library would test nothing at all.
    """
    url, path, base = tierb_delimiter_baseline(bot)
    if not url or base is None:
        bot.add_anomaly(
            "delimiter-confusion", route=tierb_base(bot),
            probe_class="no-baseline",
            note="no crawled GET path had a baseline response, so no "
                 "delimiter variant could be compared",
            detail="crawl at least one 200 page first, or pass "
                   "--delimiter-path PATH")
        return
    host = tierb_host_header(bot, url)
    sent = 0
    for name, delim in DELIMITER_VARIANTS:
        if sent >= TIERB_DELIMITER_CAP:
            bot.note("delimiter probes stopped at the %d request cap"
                     % TIERB_DELIMITER_CAP)
            break
        raw = path + delim
        responses = tierb_send(bot, url, [tierb_message("GET", raw, host)],
                               "delimiter variant " + name)
        sent += 1
        bot.tierb["delimiter_requests"] = sent
        if not responses:
            continue
        r = responses[0]
        dist = tierb_distance(r.text, base.text)
        same_status = r.status == base.status
        if same_status and dist <= TIERB_BODY_DELTA:
            continue
        added, removed = tierb_header_delta(base, r)
        bot.add_anomaly(
            "delimiter-confusion", route=url, probe_class=name,
            distance=round(dist, 3), status_delta=r.status - base.status,
            headers_added=added, headers_removed=removed,
            note=("%s: %r returned status %s against a baseline of %s, body "
                  "distance %.2f" % (
                      "cache and origin may disagree on the path"
                      if same_status else
                      "status changed for a delimited variant",
                      raw, r.status, base.status, dist)),
            evidence="baseline %r status %s %dB\nvariant %r status %s %dB"
                     % (path, base.status, len(base.body), raw, r.status,
                        len(r.body)))


# ---------- module 4: documented API state walk ----------
API_SPEC_PATHS = ("/openapi.json", "/swagger.json", "/api-docs",
                  "/v3/api-docs", "/api/openapi.json")
API_NEVER_SEND = ("delete", "put", "patch")


def tierb_spec_paths(text):
    try:
        doc = json.loads(text)
    except Exception:
        return {}
    if not isinstance(doc, dict):
        return {}
    paths = doc.get("paths")
    return paths if isinstance(paths, dict) else {}


def tierb_api_doc(bot, spend):
    """The OpenAPI document: --api-spec first, then whatever exp-api-docs
    already found this run, then the usual public locations."""
    src = getattr(bot.args, "api_spec", None)
    if src:
        try:
            with open(src, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as e:
            bot.note("--api-spec %s unreadable: %s" % (src, e))
        else:
            if tierb_spec_paths(text):
                return text, "file:" + src
            bot.note("--api-spec %s parsed but declares no paths" % src)
    for url, text in sorted(bot.api_docs.items()):
        if tierb_spec_paths(text):
            return text, "discovered:" + url
    for path in API_SPEC_PATHS:
        spend()
        r = bot.get(bot.t.base + path)
        if r is not None and r.status == 200 and tierb_spec_paths(r.text):
            return r.text, "fetched:" + path
    return None, ""


def tierb_iter_params(path_item, operation):
    """Declared parameters for a path template, path level first."""
    out = []
    for src in (path_item if isinstance(path_item, dict) else {},):
        if isinstance(src.get("parameters"), list):
            out.extend(p for p in src["parameters"] if isinstance(p, dict))
    op = (path_item or {}).get(operation) or {}
    if isinstance(op.get("parameters"), list):
        out.extend(p for p in op["parameters"] if isinstance(p, dict))
    return out


def tierb_inert_value(bot, path_item, operation):
    """Exactly ONE inert value per documented path.

    The candidates are ordered by how likely they are to name an object
    that really exists, because a differential only shows up when one
    does: 0 for an unconstrained integer, 1 when the spec sets a minimum
    above 0, and an inert canary string for anything non-numeric.
    """
    schema = {}
    for p in tierb_iter_params(path_item, operation):
        if isinstance(p.get("schema"), dict):
            schema = p["schema"]
            break
    if str(schema.get("type", "")).lower() in ("integer", "number"):
        try:
            if float(schema.get("minimum", 0)) >= 1:
                return "1"
        except (TypeError, ValueError):
            pass
        return "0"
    return bot.canary + "z"


def tierb_fill(tpl, value):
    return re.sub(r"\{[^}]+\}",
                  lambda _m: urllib.parse.quote(value, safe=""), tpl)


def tierb_dummy_body(path_item, operation):
    """Scanner-owned dummy values only: never anything lifted from the
    target, never anything that could create a real record."""
    op = (path_item or {}).get(operation) or {}
    content = ((op.get("requestBody") or {}).get("content") or {})
    for _ct, media in content.items():
        schema = ((media or {}).get("schema") or {})
        props = schema.get("properties")
        if isinstance(props, dict):
            return {name: "QX-probe-dummy" for name in list(props)[:10]}
        return {"probe": "QX-probe-dummy"}
    return {"probe": "QX-probe-dummy"}


def check_api_states(bot):
    """Walk the documented object paths the way an unauthenticated caller
    would and report any authorization differential as an anomaly.

    One inert value per path, never DELETE, PUT or PATCH, and POST only
    when the spec marks the operation and --allow-spec-post was given,
    with a body of scanner-owned dummy values. A single anonymous read
    that differs from the collection baseline is NOT a proven BOLA:
    confirming it needs a second owner-provided account, so it stays an
    anomaly at medium confidence. Cap: 30 requests.
    """
    used = [0]

    def spend():
        used[0] += 1

    text, source = tierb_api_doc(bot, spend)
    bot.tierb["api_spec_source"] = source
    bot.tierb["api_state_requests"] = used[0]
    paths = tierb_spec_paths(text or "")
    templates = sorted(p for p in paths
                       if isinstance(p, str) and "{" in p and "}" in p)
    if not templates:
        bot.add_anomaly(
            "api-state-authz", route=tierb_base(bot), probe_class="no-spec",
            note="no OpenAPI document declaring {param} paths was available, "
                 "so no authorization differential could be tested",
            detail="spec source: %s. pass --api-spec FILE, or publish the "
                   "document (an exposed spec is itself the finding "
                   "exp-api-docs)" % (source or "none"))
        return

    baselines = {}

    def collection(tpl):
        coll = re.sub(r"\{[^}]+\}", "", tpl).rstrip("/") or "/"
        if coll not in baselines:
            url = bot.t.base + coll
            r = bot.pages.get(url)
            if r is None:
                spend()
                r = bot.get(url)
            baselines[coll] = r
        return baselines[coll]

    for tpl in templates:
        if used[0] >= TIERB_API_CAP:
            bot.note("api state walk stopped at the %d request cap"
                     % TIERB_API_CAP)
            break
        item = paths[tpl] if isinstance(paths[tpl], dict) else {}
        ops = [k for k in item
               if isinstance(k, str) and k.lower() not in API_NEVER_SEND
               and k.lower() not in ("parameters", "$ref", "summary",
                                     "description", "servers")]
        plans = ["get"] if "get" in [o.lower() for o in ops] else []
        if ("post" in [o.lower() for o in ops]
                and getattr(bot.args, "allow_spec_post", False)):
            plans.append("post")
        for operation in plans:
            if used[0] >= TIERB_API_CAP:
                break
            method = operation.upper()
            if method not in ("GET", "POST"):
                continue                  # belt and braces: nothing else ships
            value = tierb_inert_value(bot, item, operation)
            item_path = tierb_fill(tpl, value)
            url = bot.t.base + item_path
            host = tierb_host_header(bot, url)
            headers = {"Accept": "application/json"}
            body = None
            if method == "POST":
                headers["Content-Type"] = "application/json"
                headers["Content-Length"] = str(
                    len(json.dumps(tierb_dummy_body(item, operation))))
                body = json.dumps(tierb_dummy_body(item, operation))
            responses = tierb_send(
                bot, url, [tierb_message(method, item_path, host, headers,
                                         body)], "api state " + method,
                method)
            used[0] += 1
            bot.tierb["api_state_requests"] = used[0]
            if not responses:
                continue
            r = responses[0]
            # a refusal is a refusal, not a leak: 401/403/404, a redirect
            # to a login page, or a server error tells us nothing either way
            if r.status in (401, 403, 404) or r.status >= 300:
                continue
            base = collection(tpl)
            bot.tierb["api_state_requests"] = used[0]
            base_status = base.status if base is not None else 0
            base_text = base.text if base is not None else ""
            dist = tierb_distance(r.text, base_text)
            if r.status == base_status and dist <= TIERB_BODY_DELTA:
                continue
            if not r.body.strip() or r.body.strip() in (b"[]", b"{}"):
                continue                  # an empty collection, not an object
            bot.add_anomaly(
                "api-state-authz", route=url, param=value, confidence="medium",
                probe_class="%s %s" % (method, tpl),
                distance=round(dist, 3),
                status_delta=r.status - base_status,
                canary_reflected=True,
                note="an unauthenticated %s of one object answered %s with "
                     "%dB while the anonymous collection baseline answered "
                     "%s (body distance %.2f); not a proven BOLA, needs a "
                     "second owner-provided account to confirm"
                     % (method, r.status, len(r.body), base_status, dist),
                detail="the differential is against %s, the collection path "
                       "for %s. A single anonymous read cannot separate "
                       "'public by design' from 'someone else's object', so "
                       "this stays an anomaly until a second owner-provided "
                       "account is in the test plan" % (urlsplit_path(
                           re.sub(r"\{[^}]+\}", "", tpl).rstrip("/") or "/"),
                           tpl),
                evidence="value=%r status=%s %dB\n%s"
                         % (value, r.status, len(r.body), r.text[:400]))
