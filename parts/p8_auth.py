

ADMIN_PATHS = ["/admin", "/administrator", "/admin/login", "/wp-admin/",
               "/manage", "/dashboard", "/console/login", "/cpanel",
               "/backend", "/staff", "/internal",
               "/account", "/profile", "/orders", "/settings", "/wallet",
               "/user/profile", "/api/user/me", "/api/v1/account"]


SECRET_RES = [
    ("AWS access key ID", re.compile(r"AKIA[0-9A-Z]{16}"), "CRITICAL"),
    ("Stripe live secret", re.compile(r"sk_live_[0-9A-Za-z]{16,}"), "CRITICAL"),
    ("GitHub token", re.compile(r"ghp_[A-Za-z0-9]{36}"), "CRITICAL"),
    ("OpenAI-style secret key", re.compile(r"(?<![\w-])sk-[A-Za-z0-9]{32,}"),
     "CRITICAL"),
    ("Embedded private key",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "CRITICAL"),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "HIGH"),
    ("Bearer credential",
     re.compile(r"(?i)bearer[\"'\s:=]{1,4}[A-Za-z0-9._\-]{25,}"), "HIGH"),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_-]{35}"), "MEDIUM"),
]


def mask_token(raw):
    if len(raw) <= 12:
        return "***"
    return raw[:6] + "*" * (len(raw) - 10) + raw[-4:]


def secret_hash(value, url):
    """Stable dedupe key for one secret value seen on one URL."""
    return hashlib.sha256((value + "\n" + url).encode("utf-8", "replace")
                          ).hexdigest()[:16]


def make_secret_vfy(bot, url, rx):
    def v():
        rr = bot.get(url)
        return rr is not None and rx.search(rr.text) is not None
    return v


def header_blob(resp):
    """Every header the server sent, as one searchable string."""
    out = []
    for k, v in resp.headers.items():
        if k == "set-cookie-list":
            out.extend(str(x) for x in (v or []))
        else:
            out.append(f"{k}: {v}")
    return "\n".join(out)


def check_secrets(bot):
    sources = [(u, r.text) for u, r in bot.pages.items()] + \
              [(u, t) for u, t in bot.js_assets.items()]
    for src_url, text in sources:
        if not text or len(text) > 2_000_000:
            continue
        for name, rx, sev in SECRET_RES:
            m = rx.search(text)
            if not m:
                continue
            raw = m.group(0)
            f = bot.add("secret-leak", url=src_url, severity=sev, param=name,
                        confidence="medium" if name == "Google API key"
                        else "high",
                        evidence=f"{name} in served content: "
                                 f"{mask_token(raw)} (value redacted)",
                        detail="client-visible secret: treat as compromised, "
                               "rotate it and move it server-side",
                        verify=make_secret_vfy(bot, src_url, rx))
            if f is not None:
                f["secret_hash"] = secret_hash(raw, src_url)


# M8 global matcher sweep: run once over every captured response, body AND
# headers, with the secret patterns plus the stack-trace signatures. Same
# secret on the same URL is reported once, no matter which check found it.
SWEEP_RES = [
    ("Embedded private key",
     re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "CRITICAL"),
    ("AWS access key ID", re.compile(r"AKIA[0-9A-Z]{16}"), "HIGH"),
    ("Stripe live secret", re.compile(r"sk_live_[0-9A-Za-z]{10,}"), "HIGH"),
    ("GitHub token", re.compile(r"ghp_[A-Za-z0-9]{20,}"), "HIGH"),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "HIGH"),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_-]{35}"), "HIGH"),
    ("OpenAI-style secret key", re.compile(r"(?<![\w-])sk-[A-Za-z0-9]{32,}"),
     "HIGH"),
    ("Bearer credential",
     re.compile(r"(?i)bearer[\"'\s:=]{1,4}[A-Za-z0-9._\-]{25,}"), "HIGH"),
] + [("Stack trace: " + label, re.compile(rx), "HIGH")
     for rx, label in STACK_SIGS]


def sweep_family(name):
    """One stack trace per page is a finding; the rest is noise. Every secret
    pattern keeps its own family so a page carrying two different keys still
    reports both."""
    return "stack-trace" if name.startswith("Stack trace: ") else name


def make_sweep_vfy(bot, url, rx, where):
    def v():
        rr = bot.get(url)
        if rr is None:
            return False
        if where == "body":
            return rx.search(rr.text) is not None
        return rx.search(header_blob(rr)) is not None
    return v


def check_global_sweep(bot):
    reported = {f["secret_hash"] for f in bot.findings
                if f["check_id"] == "secret-leak" and f.get("secret_hash")}
    swept = matched = dupes = collapsed = 0
    seen_family = set()
    for url, r in bot.pages.items():
        for where, text in (("body", r.text), ("header", header_blob(r))):
            if not text or len(text) > 2_000_000:
                continue
            swept += 1
            for name, rx, sev in SWEEP_RES:
                m = rx.search(text)
                if not m:
                    continue
                matched += 1
                fam = (url, sweep_family(name))
                if fam in seen_family:
                    collapsed += 1
                    continue
                seen_family.add(fam)
                raw = m.group(0)
                h = secret_hash(raw, url)
                if h in reported:
                    dupes += 1
                    bot.add("global-secret-sweep", url=url, param=f"dedupe:{name}",
                            internal=True, severity="INFO",
                            evidence=f"{name} on {url} was already reported as "
                                     f"secret-leak (hash {h}); suppressed here so "
                                     f"one secret counts once")
                    continue
                reported.add(h)
                f = bot.add("global-secret-sweep", url=url, param=name,
                            severity=sev,
                            evidence=f"{name} matched in the {where} of this "
                                     f"response: {mask_token(raw)} "
                                     f"(value redacted)",
                            detail="found by the global matcher sweep across "
                                   "every captured response, not only where an "
                                   "exposure probe happened to land",
                            verify=make_sweep_vfy(bot, url, rx, where))
                if f is not None:
                    f["secret_hash"] = h
    bot.add("global-secret-sweep", url=bot.t.base, param="sweep-evidence",
            internal=True, severity="INFO",
            evidence=f"global sweep read {swept} captured response halves "
                     f"({len(bot.pages)} responses, bodies and headers): "
                     f"{matched} pattern matches, {dupes} already reported by "
                     f"secret-leak, {collapsed} more signatures of an already "
                     f"reported class on the same page")


def check_auth(bot):
    # force browsing to obvious privileged surfaces, unauthenticated
    for path in ADMIN_PATHS:
        url = bot.t.base + path
        r = bot.get(url, follow=False)
        if r is None:
            continue
        if r.status in (301, 302, 303, 307, 308):
            loc = r.header("location")
            if not re.search(r"(login|signin|auth|sso)", loc, re.I):
                bot.note(f"{path} redirects to {loc} (check manually)")
            continue
        if r.status == 200:
            body = r.text[:20000]
            if LOGIN_RE.search(body):
                continue
            if re.search(r"(?i)<(html|body)", body) and len(body) > 250:
                def vfy(u=url):
                    rr = bot.get(u, follow=False)
                    return rr is not None and rr.status == 200 and \
                        not LOGIN_RE.search(rr.text[:20000])
                bot.add("admin-force-browse", url=url,
                        evidence=f"HTTP 200, {len(body)}B, no login form "
                                 f"(title: {title_of(body)!r})", verify=vfy)

    # CSRF posture of state-changing forms
    for form in bot.forms:
        if form["method"] != "post":
            continue
        names = [i["name"] for i in form["inputs"]]
        has_token = any(TOKEN_RE.match(n or "") for n in names)
        action = urllib.parse.urljoin(base_page(bot), form["action"] or "")
        if not has_token:
            bot.add("csrf-token-missing", url=action,
                    param=",".join(n for n in names if n)[:80],
                    confidence="medium", negative=True,
                    evidence=f"POST form with fields: {', '.join(names)[:160]} "
                             f"and no hidden CSRF token",
                    detail="confirm by replaying from a cross-origin page on a "
                           "dry-run endpoint")
        samesite = any("samesite" in c.lower()
                       for p in bot.pages.values()
                       for c in p.headers.get("set-cookie-list", []))
        if not has_token and not samesite and form["inputs"]:
            bot.note(f"{action}: no CSRF token and no SameSite cookie attribute")


def check_ratelimit(bot):
    login_form = None
    for form in bot.forms:
        types = [i["type"] for i in form["inputs"]]
        if "password" in types:
            login_form = form
            break
    if login_form is None:
        for path in ("/login", "/signin", "/sign-in", "/auth/login", "/account/login"):
            r = bot.get(bot.t.base + path, follow=False)
            if r is not None and r.status == 200 and "password" in r.text.lower():
                login_form = {"action": path, "method": "post",
                              "inputs": [{"name": "username", "type": "text"},
                                         {"name": "password", "type": "password"}]}
                break
    if login_form is None:
        bot.note("no login form discovered, rate-limit test skipped")
        return
    action = urllib.parse.urljoin(base_page(bot), login_form["action"] or "")
    fields = {i["name"]: ("qx_nouser@invalid" if i["type"] != "password"
                          else "DefinitelyNotARealPass!1")
              for i in login_form["inputs"] if i["name"]}
    if not fields:
        return
    statuses, limited = [], False
    for _ in range(10):
        r = bot.get(action, method="POST",
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    body=urllib.parse.urlencode(fields), follow=False)
        if r is None:
            return
        statuses.append(r.status)
        if r.status in (429, 423, 403) or r.header("retry-after"):
            limited = True
            break
        if bot.stopped:
            return
    if not limited:
        bot.add("ratelimit-login", url=action,
                evidence=f"10 rapid failed logins, statuses: {statuses}",
                detail="no 429/lockout observed in a gentle N=10 burst; "
                       "manual review recommended before concluding")


def check_sectxt(bot):
    for path in ("/.well-known/security.txt", "/security.txt"):
        r = bot.get(bot.t.base + path)
        if r is not None and r.status == 200 and "contact:" in r.text.lower():
            bot.recon.append(("security.txt", path))
            return
    bot.add("sec-txt-missing", url=bot.t.base + "/.well-known/security.txt",
            evidence="no RFC 9116 security.txt found", negative=True)


def check_client(bot):
    for url, r in list(bot.pages.items())[:20]:
        if "html" not in r.header("content-type") and "<html" not in r.text[:600].lower():
            continue
        body = r.text
        try:
            p = PageParser()
            p.feed(body)
        except Exception:
            continue
        for src, integrity, _co in p.scripts:
            absu = urllib.parse.urljoin(url, src)
            sp = urllib.parse.urlsplit(absu)
            if sp.scheme in ("http", "https") and sp.netloc and \
                    sp.netloc != urllib.parse.urlsplit(bot.t.base).netloc and \
                    not integrity:
                bot.add("sri-missing", url=url, param=src[:120],
                        evidence=f"<script src=\"{src}\"> without integrity",
                        verify=lambda u=url: True)
                break
        if bot.t.scheme == "https":
            m = re.search(r"(?:src|href)=[\"'](http://[^\"']+)[\"']", body)
            if m:
                bot.add("mixed-content", url=url, evidence=f"mixed resource: {m.group(1)}",
                        verify=lambda: True)
        # source maps
        for m in re.finditer(r"sourceMappingURL=([^\s\"'<>)\\]+)", body):
            map_url = urllib.parse.urljoin(url, m.group(1))
            if not bot.t.in_scope(map_url):
                continue
            mr = bot.get(map_url)
            if mr is not None and mr.status == 200 and b'"sources"' in mr.body[:200000]:
                bot.add("exp-sourcemap", url=map_url,
                        evidence=f"source map served ({len(mr.body)}B)",
                        verify=lambda u=map_url: True)
