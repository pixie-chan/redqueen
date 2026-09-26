

def check_methods(bot):
    url = bot.t.base + bot.t.path
    r = bot.get(url, method="OPTIONS")
    if r is not None:
        allow = r.header("allow")
        if re.search(r"\b(PUT|DELETE|PATCH)\b", allow):
            bot.add("method-put", url=url, evidence=f"Allow: {allow}", verify=lambda: True)
    r = bot.get(url, method="TRACE")
    if r is not None and r.status == 200 and re.search(
            r"(?i)^\s*trace\s+/|user-agent", r.text[:400]):
        bot.add("method-trace", url=url, evidence=r.text[:200].replace("\r", ""),
                verify=lambda: True)


STACK_SIGS = [
    (r"Traceback \(most recent call last\)", "Python traceback"),
    (r"File \"[^\"]+\", line \d+", "Python file/line leak"),
    (r"(?i)werkzeug debugger|Debugger.*PIN", "Werkzeug interactive debugger"),
    (r"(?i)django.*Version|Exception Value|Using the URLconf", "Django debug page"),
    (r"(?i)SQLSTATE\[[0-9A-Z]+\]", "PDO/SQL error"),
    (r"(?i)PDOException|mysqli_sql_exception", "PHP SQL exception"),
    (r"(?i)java\.lang\.\w+Exception|at [\w.$]+\([\w.]+:\d+\)", "Java stack trace"),
    (r"(?i)System\.(ArgumentException|NullReferenceException)|Stack trace:", ".NET stack trace"),
    (r"(?i)ORA-\d{5}|Oracle error", "Oracle error"),
    (r"(?i)Whoops!|Symfony\\\\Component", "Symfony error page"),
    (r"(?i)fatal error:", "PHP fatal error"),
    (r"(?i)stack trace:|call stack:", "generic stack trace"),
]


def check_stacktrace(bot):
    probes = [bot.t.base + "/" + "qx-err-" + secrets.token_hex(4),
              bot.t.base + bot.t.path + ("&" if "?" in bot.t.path else "?") + "qx=%%27"]
    for url in probes:
        r = bot.get(url)
        if r is None:
            continue
        text = r.text[:200000]
        for sig, label in STACK_SIGS:
            m = re.search(sig, text)
            if m:
                start = max(0, m.start() - 80)
                ev = text[start:m.end() + 120].replace("\r", " ")
                def vfy(u=url, s=sig):
                    rr = bot.get(u)
                    return rr is not None and re.search(s, rr.text[:200000]) is not None
                bot.add("err-stacktrace", url=url, evidence=ev[:400], verify=vfy)
                break
        if r.status >= 500:
            pass


SQL_SIGS = [r"(?i)you have an error in your sql syntax",
            r"(?i)mysql_fetch|mysqli?_",
            r"(?i)syntax error at or near",
            r"(?i)pg_query\(|unterminated quoted string",
            r"(?i)SQLITE_ERROR|SQLite/3",
            r"(?i)Unclosed quotation mark after the character string",
            r"(?i)Microsoft OLE DB Provider for SQL Server",
            r"(?i)ORA-\d{5}|quoted string not properly terminated",
            r"(?i)SQLSTATE\[[0-9A-Z]{5}\]"]
CMD_ECHO = re.compile(r"([;&|]\s*echo\s+)(QX[A-Za-z0-9]{4,})", re.I)
FILENAME_PARAM = re.compile(r"(?i)^(file|filename|path|dir|document|doc|template|"
                            r"page|download|include|resource|name)$")
REDIR_PARAM = re.compile(r"(?i)^(url|to|redirect|redir|next|return|returnto|return_url|"
                         r"continue|dest|destination|goto|target|callback|goto_url|u)$")


def norm(text):
    t = re.sub(r"(?i)[0-9a-f]{12,}", "#", text or "")
    t = re.sub(r"\d{3,}", "#", t)
    return re.sub(r"\s+", " ", t)[:20000]


def check_injection(bot):
    budget_urls = [u for u, ps in bot.params.items() if ps][:5]
    for url in budget_urls:
        if bot.t.used > bot.t.max_requests * 0.8:
            bot.note("injection probes stopped at 80% of request budget")
            break
        parts = urllib.parse.urlsplit(url)
        q = dict(kv.split("=", 1) if "=" in kv else (kv, "")
                 for kv in parts.query.split("&") if kv)
        for param in list(bot.params[url])[:4]:
            def build(value, url=url, parts=parts, q=q, param=param):
                nq = dict(q)
                nq[param] = value
                return urllib.parse.urlunsplit(
                    (parts.scheme, parts.netloc, parts.path,
                     urllib.parse.urlencode(nq, doseq=True), parts.fragment))
            orig = q.get(param, "")
            base_r = bot.get(build(orig or "qx"))
            if base_r is None:
                continue
            base_txt = base_r.text
            # reflected XSS: plain canary then hostile characters
            tok = bot.canary + secrets.token_hex(3)
            r1 = bot.get(build(tok))
            if r1 is not None and tok in r1.text and tok not in base_txt:
                hostile = f"<\">'{tok}"
                r2 = bot.get(build(hostile))
                if r2 is not None and hostile in r2.text:
                    def vfy(u=build(hostile), h=hostile):
                        rr = bot.get(u)
                        return rr is not None and h in rr.text
                    bot.add("xss-reflected", url=url, param=param,
                            evidence=f"raw echo of {hostile!r} in response body",
                            verify=vfy)
                else:
                    bot.note(f"{param} reflects input but appears escaped "
                             f"(no XSS found)")
            # SQL error based, then boolean differential fallback
            probe = (orig or "") + "'"
            r3 = bot.get(build(probe))
            found_sqli = False
            if r3 is not None and (
                    r3.status != base_r.status or (
                        any(re.search(s, r3.text) for s in SQL_SIGS)
                        and not any(re.search(s, base_txt) for s in SQL_SIGS))):
                for s in SQL_SIGS:
                    m = re.search(s, r3.text)
                    if m:
                        def vfy(u=build(probe), s=s):
                            rr = bot.get(u)
                            return rr is not None and re.search(s, rr.text) is not None
                        bot.add("sqli-error", url=url, param=param,
                                evidence=r3.text[max(0, m.start() - 60):m.end() + 80]
                                         .replace("\r", " ")[:300], verify=vfy)
                        found_sqli = True
                        break
                if not found_sqli:
                    bot.add("sqli-boolean", url=url, param=param,
                            confidence="medium",
                            evidence=f"status {base_r.status} -> {r3.status} on "
                                     f"quote injection",
                            detail="differential observed without a DB error "
                                   "string; confirm manually")
                    found_sqli = True
            if not found_sqli:
                bv = orig or "1"
                rt_ = bot.get(build(bv + " AND 1=1"))
                rf_ = bot.get(build(bv + " AND 1=2"))
                if rt_ is not None and rf_ is not None and \
                        rt_.status == rf_.status == 200:
                    a = norm(rt_.text)
                    b = norm(rf_.text)
                    base_n = norm(base_txt)
                    r_true_base = difflib.SequenceMatcher(None, a, base_n).ratio()
                    r_true_false = difflib.SequenceMatcher(None, a, b).ratio()
                    if r_true_base >= 0.97 and r_true_false <= 0.95:
                        def vfy(u=build(bv + " AND 1=2"), ref=a):
                            rr = bot.get(u)
                            return rr is not None and difflib.SequenceMatcher(
                                None, norm(rr.text), ref).ratio() <= 0.95
                        bot.add("sqli-boolean", url=url, param=param,
                                confidence="medium",
                                evidence=f"AND 1=1 matches baseline "
                                         f"({r_true_base:.2f}) while AND 1=2 "
                                         f"diverges ({r_true_false:.2f})",
                                detail="boolean differential is a strong signal; "
                                       "confirm manually before calling it SQLi",
                                verify=vfy)
            # command injection echo marker (benign only)
            for sep in ("; echo ", " | echo ", " && echo "):
                tok2 = "QX" + secrets.token_hex(5)
                payload = (orig or "qx") + sep + tok2
                r4 = bot.get(build(payload))
                visible = htmllib.unescape(r4.text) if r4 is not None else ""
                if r4 is not None and tok2 in visible and payload not in visible \
                        and tok2 not in base_txt:
                    def vfy(u=build(payload), t=tok2):
                        rr = bot.get(u)
                        return rr is not None and t in rr.text
                    bot.add("cmdi-echo", url=url, param=param,
                            evidence=f"server echoed injected marker {tok2} "
                                     f"without the command text (separator "
                                     f"{sep.strip()!r})", verify=vfy)
                    break
            # open redirect
            if REDIR_PARAM.match(param):
                target = "//qx-canary.invalid/landing"
                rd = bot.get(build(target), follow=False)
                loc = rd.header("location") if rd else ""
                if loc.startswith("//qx-canary.invalid") or loc.startswith(
                        "https://qx-canary.invalid"):
                    bot.add("redirect-open", url=url, param=param,
                            evidence=f"Location: {loc}", verify=lambda: True)
            # path traversal (planted canary or explicit deep mode)
            if FILENAME_PARAM.match(param):
                if bot.args.traversal_canary:
                    payload = "../../../../" + bot.args.traversal_canary.lstrip("/")
                    rt = bot.get(build(payload))
                    if rt is not None and bot.args.traversal_canary in rt.text:
                        bot.add("traversal", url=url, param=param,
                                evidence=f"planted canary "
                                         f"{bot.args.traversal_canary} returned",
                                verify=lambda: True)
                elif bot.args.deep_traversal:
                    rt = bot.get(build("../../../../etc/passwd"))
                    if rt is not None and re.search(r"(?m)^root:x?:0:0:", rt.text):
                        bot.add("traversal", url=url, param=param,
                                evidence="/etc/passwd contents returned",
                                verify=lambda: True)
