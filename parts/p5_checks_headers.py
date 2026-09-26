

def urlsplit_path(url):
    return urllib.parse.urlsplit(url).path


def title_of(body):
    m = re.search(r"<title>(.*?)</title>", body, re.I | re.S)
    return (m.group(1).strip() if m else "")[:80] or body[:80]


def base_page(bot):
    return bot.t.base + bot.t.path


def check_headers(bot):
    url = base_page(bot)
    r = bot.pages.get(url) or bot.get(url)
    if r is None:
        return
    h = r.headers
    is_html = "html" in r.header("content-type") or "<html" in r.text[:600].lower()
    def vfy():
        rr = bot.get(url)
        return rr is not None
    if bot.t.scheme == "https":
        if "strict-transport-security" not in h:
            bot.add("hdr-hsts", url=url, evidence="header absent", verify=vfy)
        else:
            m = re.search(r"max-age=(\d+)", h["strict-transport-security"])
            if m and int(m.group(1)) < 86400:
                bot.add("hdr-hsts", url=url, severity="MEDIUM",
                        evidence=h["strict-transport-security"],
                        detail="max-age below one day is too short to protect users")
    if is_html:
        csp = h.get("content-security-policy", "")
        if not csp:
            bot.add("hdr-csp-missing", url=url, evidence="header absent", verify=vfy)
        elif re.search(r"script-src[^;]*'unsafe-inline'", csp) or \
                re.search(r"default-src[^;]*'unsafe-inline'", csp) or \
                re.search(r"'unsafe-eval'", csp):
            bot.add("hdr-csp-unsafe", url=url, evidence=csp[:300], verify=vfy)
        if "x-frame-options" not in h and "frame-ancestors" not in csp:
            bot.add("clickjack", url=url, evidence="no XFO and no frame-ancestors",
                    verify=vfy)
        if "referrer-policy" not in h:
            bot.add("hdr-referrer", url=url, evidence="header absent")
        if "permissions-policy" not in h:
            bot.add("hdr-permissions", url=url, evidence="header absent")
        if "cross-origin-opener-policy" not in h:
            bot.add("hdr-coop", url=url, evidence="header absent")
        if "cross-origin-resource-policy" not in h:
            bot.add("hdr-corp", url=url, evidence="header absent")
        if "x-content-type-options" not in h:
            bot.add("hdr-nosniff", url=url, evidence="header absent", verify=vfy)
    for purl, pr in list(bot.pages.items())[:12]:
        if re.search(r"(login|signin|account|dashboard|admin|settings|profile|checkout)",
                     purl, re.I) and "cache-control" not in pr.headers:
            bot.add("hdr-cache-sensitive", url=purl,
                    evidence="no Cache-Control on a sensitive page")
            break
    xss = h.get("x-xss-protection", "")
    if xss and xss.strip() not in ("0", "0; mode=block"):
        bot.add("hdr-xss-legacy", url=url, evidence=f"X-XSS-Protection: {xss}")
    for dead in ("expect-ct", "public-key-pins"):
        if dead in h:
            bot.add("hdr-obsolete", url=url, evidence=f"{dead}: {h[dead][:80]}")
    xp = h.get("x-powered-by", "")
    if xp:
        bot.add("hdr-x-powered", url=url, evidence=f"X-Powered-By: {xp}")
    srv = h.get("server", "")
    if re.search(r"/\d+\.\d+", srv):
        bot.add("hdr-banner", url=url, evidence=f"Server: {srv}", verify=vfy)
        bot.recon.append(("server version", srv))


def check_cors(bot):
    url = base_page(bot)
    evil1 = "https://qx-canary.invalid"
    r = bot.get(url, headers={"Origin": evil1})
    if r is None:
        return
    acao = r.header("access-control-allow-origin")
    acac = r.header("access-control-allow-credentials").lower()
    if not acao:
        return
    if acao == "null":
        bot.add("cors-null", url=url, evidence="Access-Control-Allow-Origin: null",
                detail="the null origin is trusted")
        return
    if acao == "*":
        bot.add("cors-star", url=url, evidence="Access-Control-Allow-Origin: *",
                detail="wildcard origin on this endpoint")
        return
    if acao == evil1:
        evil2 = "https://evil-qx-canary.invalid"
        r2 = bot.get(url, headers={"Origin": evil2})
        reflected2 = r2 is not None and r2.header("access-control-allow-origin") == evil2
        if reflected2:
            sev = "HIGH" if acac == "true" else "MEDIUM"
            def vfy():
                rr = bot.get(url, headers={"Origin": evil1})
                return rr is not None and rr.header(
                    "access-control-allow-origin") == evil1
            bot.add("cors-reflect", url=url, severity=sev, verify=vfy,
                    evidence=f"ACAO: {acao} | ACAC: {acac or 'absent'}",
                    detail="two different attacker origins were both echoed back")
        else:
            bot.note("CORS echoed one origin only, not confirmed arbitrary")


def check_cookies(bot):
    url = base_page(bot)
    r = bot.pages.get(url) or bot.get(url)
    cookies = list((r.headers.get("set-cookie-list", []) if r else []))
    for page, pr in bot.pages.items():
        for c in pr.headers.get("set-cookie-list", []):
            if c not in cookies:
                cookies.append(c)
    for raw in cookies:
        parts = raw.split(";")
        name_val = parts[0].strip()
        name = name_val.split("=", 1)[0]
        attrs = " ".join(p.strip().lower() for p in parts[1:])
        sessionish = bool(re.search(
            r"(session|sess|sid|token|auth|jwt|phpsess|jsession|connect\.sid)",
            name, re.I))
        low = raw.lower()
        if "max-age=" in attrs or "expires=" in attrs:
            ma = re.search(r"max-age=(\d+)", attrs)
            days = int(ma.group(1)) / 86400 if ma else 0
            if days > 365:
                bot.add("cookie-long-life", url=url, param=name,
                        evidence=f"{name} lives {int(days)} days")
        if bot.t.scheme == "https" and "secure" not in attrs:
            bot.add("cookie-secure" if sessionish else "cookie-secure",
                    url=url, param=name, severity="MEDIUM" if sessionish else "LOW",
                    evidence=f"{name}={name_val.split('=',1)[1][:12]}... flags: "
                             f"{attrs or 'none'}")
        if sessionish and "httponly" not in attrs:
            bot.add("cookie-httponly", url=url, param=name,
                    evidence=f"Set-Cookie: {name}=... without HttpOnly")
        if sessionish and "samesite" not in attrs:
            bot.add("cookie-samesite", url=url, param=name,
                    evidence=f"Set-Cookie: {name}=... without SameSite")
        if "samesite=none" in attrs and "secure" not in attrs:
            bot.add("cookie-samesite-none", url=url, param=name,
                    evidence=f"Set-Cookie: {name}=... SameSite=None without "
                             f"Secure")
        if bot.t.scheme == "http" and sessionish:
            bot.add("cookie-plaintext", url=url, param=name,
                    evidence=f"session cookie {name} issued over plain HTTP")


def check_host_header(bot):
    url = base_page(bot)
    canary = "qx-host-canary.invalid"
    r = bot.get(url, headers={"X-Forwarded-Host": canary,
                              "Forwarded": f"host={canary}"})
    if r is None:
        return
    loc = r.header("location")
    where = "body" if canary in r.text else ("Location: " + loc if canary in loc
                                             else "")
    if where:
        def vfy():
            rr = bot.get(url, headers={"X-Forwarded-Host": canary})
            return rr is not None and canary in rr.text
        bot.add("host-header", url=url, evidence=f"X-Forwarded-Host {canary} "
                f"reflected in {where[:120]}", verify=vfy)


def b64url_json(segment):
    pad = "=" * (-len(segment) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(segment + pad))
    except Exception:
        return None


def iter_jwt(bot):
    seen = set()
    for page in bot.pages.values():
        for raw in page.headers.get("set-cookie-list", []):
            val = raw.split(";", 1)[0].split("=", 1)[-1].strip()
            if val.count(".") == 2 and val.startswith("eyJ"):
                if val not in seen:
                    seen.add(val)
                    yield val


def check_jwt(bot):
    weak_secrets = ["secret", "password", "changeme", "qwerty", "123456",
                    "quantiq", "quant-iq", "jwtsecret", "mysecret", "key",
                    bot.t.host, bot.t.host.split(".")[0]]
    for tok in iter_jwt(bot):
        parts = tok.split(".")
        head, pay = b64url_json(parts[0]), b64url_json(parts[1])
        if not isinstance(head, dict) or not isinstance(pay, dict):
            continue
        alg = str(head.get("alg", ""))
        loc = f"cookie on {base_page(bot)}"
        if alg.lower() == "none":
            f = bot.add("jwt-alg-none", url=base_page(bot), param="jwt",
                        confidence="medium", evidence=f"header alg={alg}",
                        detail="server issued an unsigned JWT; acceptance test "
                               "of a forged token left as a manual step")
        if alg.upper() in ("HS256", "HS384", "HS512") and len(parts) == 3:
            signing = (parts[0] + "." + parts[1]).encode()
            sig = base64.urlsafe_b64decode(parts[2] + "=" * (-len(parts[2]) % 4))
            for cand in weak_secrets:
                dig = hmac.new(cand.encode(), signing, hashlib.sha256).digest()
                if hmac.compare_digest(dig, sig[:len(dig)]):
                    bot.add("jwt-weak-secret", url=base_page(bot), param="jwt",
                            evidence=f"signature validates with candidate secret "
                                     f"'{cand}' (offline check)",
                            detail="verified offline, no requests to the target")
                    break
        if "exp" not in pay:
            bot.add("jwt-no-exp", url=base_page(bot), param="jwt",
                    evidence=f"claims present: {', '.join(sorted(pay)[:8])}")
        else:
            try:
                left = int(pay["exp"]) - int(time.time())
                if left > 90 * 86400:
                    bot.add("jwt-long-life", url=base_page(bot), param="jwt",
                            evidence=f"exp is {left // 86400} days away")
            except Exception:
                pass
