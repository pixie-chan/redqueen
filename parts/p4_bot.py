

class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.forms, self.scripts, self.titles = [], [], [], ""
        self._form, self._intitle = None, False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("a", "link", "area") and a.get("href"):
            self.links.append(a["href"])
        elif tag in ("script", "img", "iframe", "source") and a.get("src"):
            self.links.append(a["src"])
            self.scripts.append((a.get("src", ""), a.get("integrity", ""),
                                 a.get("crossorigin", "")))
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method":
                          (a.get("method") or "get").lower(), "inputs": []}
        elif tag == "input" and self._form is not None:
            self._form["inputs"].append(
                {"name": a.get("name", ""), "type": (a.get("type") or
                 "text").lower(), "value": a.get("value", "")})
        elif tag == "title":
            self._intitle = True

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None
        elif tag == "title":
            self._intitle = False

    def handle_data(self, data):
        if self._intitle:
            self.titles += data


TOKEN_RE = re.compile(r"^(csrf|xsrf|_?token|authenticity|nonce|anti[_-]?forgery)",
                      re.I)
LOGIN_RE = re.compile(r"(type=[\"']password[\"']|name=[\"']password[\"']"
                      r"|sign[\s-]?in|log[\s-]?in|forgot[\s-]?password)", re.I)


JS_EP_RES = [
    re.compile(r"""["'`](/api/[A-Za-z0-9_\-/{}.$]{1,80})["'`]"""),
    re.compile(r"""fetch\(\s*["'`]([A-Za-z0-9_\-/{}.$?=&]{2,120})["'`]"""),
    re.compile(r"""\.(?:get|post|put|delete|patch)\(\s*["'`](/[A-Za-z0-9_\-/{}.$?=&]{2,120})["'`]"""),
    re.compile(r"""["'`](https?://[A-Za-z0-9.\-]+(/[A-Za-z0-9_\-/{}.$?=&]{2,120})?)["'`]"""),
]


class Bot:
    def __init__(self, transport, args):
        self.t = transport
        self.args = args
        self.findings = []
        self._keys = set()
        self._verify = {}
        self.notes = []
        self.recon = []
        self.pages = {}
        self.urls = set()
        self.forms = []
        self.params = {}          # url -> [param names]
        self.stopped = None
        self.canary = "QX" + secrets.token_hex(5)
        self._soft404 = None
        self.js_assets = {}
        self.endpoints = set()
        self.script_urls = set()
        self._seen = set()

    # ---------- plumbing ----------
    def get(self, url, headers=None, method="GET", body=None, follow=True):
        hdrs = dict(headers or {})
        if self.args.cookie and "Cookie" not in hdrs:
            hdrs["Cookie"] = self.args.cookie
        try:
            return self.t.request(method, url, headers=hdrs, body=body,
                                  follow=follow)
        except BudgetExceeded as e:
            self.stopped = str(e)
            raise
        except OutOfScope:
            self.notes.append(f"blocked out-of-scope request: {url}")
            return None
        except RuntimeError as e:
            self.notes.append(f"request error {url}: {e}")
            return None

    def note(self, msg):
        if msg not in self.notes:
            self.notes.append(msg)

    def add(self, check_id, url="", param=None, severity=None, evidence="",
            fix=None, confidence="high", detail=None, verify=None):
        spec = CHECKS.get(check_id)
        if spec is None:
            raise KeyError(check_id)
        owasp, dsev, title, impact, dfix = spec
        key = (check_id, url.split("?")[0], param or "")
        if key in self._keys:
            return None
        self._keys.add(key)
        ev = SECRET_RE.sub(lambda m: m.group(1) + "=***REDACTED***",
                           evidence or "")
        ev = ev[:600]
        f = {"id": f"F{len(self.findings) + 1:03d}", "check_id": check_id,
             "title": title, "severity": severity or dsev, "owasp": owasp,
             "confidence": confidence, "verified": False, "url": url,
             "param": param, "evidence": ev, "fix": fix or dfix,
             "impact": impact, "detail": detail or "",
             "refs": [OWASP_URL.get(owasp, CHEATSHEET + "Reporting_Cheat_Sheet.html")]}
        self.findings.append(f)
        if verify is not None:
            self._verify[f["id"]] = verify
        return f

    def verify_findings(self):
        for f in list(self.findings):
            if f["severity"] not in ("CRITICAL", "HIGH"):
                continue
            fn = self._verify.get(f["id"])
            if fn is None:
                continue
            try:
                ok = fn()
            except BudgetExceeded:
                raise
            except Exception:
                ok = False
            f["verified"] = bool(ok)
            if not ok:
                order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
                f["severity"] = order[min(order.index(f["severity"]) + 1, 4)]
                f["confidence"] = "low"
                f["detail"] = (f["detail"] + " Not reproduced on re-test; "
                               "treat as candidate.").strip()

    def score(self):
        total = 100.0
        for f in self.findings:
            w = {"CRITICAL": 25, "HIGH": 12, "MEDIUM": 5, "LOW": 2,
                 "INFO": 0}[f["severity"]]
            if not f["verified"] and f["severity"] in ("CRITICAL", "HIGH"):
                w /= 2
            total -= w
        return max(0.0, round(total, 1))

    def counts(self):
        c = {k: 0 for k in SEV_ORDER}
        for f in self.findings:
            c[f["severity"]] += 1
        return c

    # ---------- discovery ----------
    def fetch(self, url):
        r = self.get(url)
        if r is not None:
            self.pages[url] = r
        return r

    def discover(self):
        base = self.t.base + self.t.path
        r = self.fetch(base)
        if r is None:
            raise SystemExit("target unreachable or out of scope")
        self.recon.append(("target", base))
        self.recon.append(("status", str(r.status)))
        srv = r.header("server")
        if srv:
            self.recon.append(("server", srv))
        ip = socket.gethostbyname(self.t.host) if self.t.host not in (
            "127.0.0.1", "localhost") else self.t.host
        self.recon.append(("ip", ip))
        self.recon.append(("requests budget", f"{self.t.used}/{self.t.max_requests}"))

        rb = self.get(self.t.base + "/robots.txt")
        if rb and rb.status == 200:
            txt = rb.text
            self.recon.append(("robots.txt", f"{len(txt.splitlines())} lines"))
            for line in txt.splitlines():
                if line.lower().startswith("disallow"):
                    path = line.split(":", 1)[-1].strip()
                    if path and re.search(
                            r"(admin|backup|private|staging|debug|\.git|env)",
                            path, re.I):
                        self.add("robots-disclosure", url=self.t.base +
                                 "/robots.txt", evidence=line)
            m = re.search(r"(?im)^sitemap:\s*(\S+)", txt)
            if m:
                self._queue(m.group(1))
        sm = self.get(self.t.base + "/sitemap.xml")
        if sm and sm.status == 200 and "xml" in sm.header("content-type") + sm.text[:200]:
            for loc in re.findall(r"<loc>(.*?)</loc>", sm.text):
                self._queue(loc.strip())
            self.recon.append(("sitemap.xml", "parsed"))

        # pass 1: BFS crawl
        self._queue(base)
        self._crawl()
        # pass 2: same-origin JS assets -> endpoint + secret extraction
        js_candidates = [s for s in sorted(self.script_urls)
                         if re.search(r"\.m?js($|\?)", s, re.I)]
        for su in js_candidates[:10]:
            r = self.get(su)
            if r is not None and r.body:
                self.js_assets[su] = r.text
                self._ingest_js(su, r.text)
        if self.js_assets:
            self.recon.append(("js assets scanned", str(len(self.js_assets))))
        if self.endpoints:
            self.recon.append(("endpoints mined from js",
                               str(len(self.endpoints))))
            self._crawl()   # pass 3: probe the mined API routes
        # passive historical / certificate sources (opt-in flags)
        if self.args.wayback:
            self._wayback()
            self._crawl()
        else:
            self.recon.append(("wayback", "off (add --wayback)"))
        if self.args.ct_log:
            self._ct_log()
        else:
            self.recon.append(("ct-log", "off (add --ct-log)"))

    def _crawl(self):
        queue = [u for u in sorted(self.urls)]
        pages = 0
        robots_paths = self._robots_disallow()
        while queue and pages < self.args.max_pages:
            url = queue.pop(0)
            if url in self._seen:
                continue
            self._seen.add(url)
            if self.args.respect_robots and any(
                    urlsplit_path(url).startswith(d) for d in robots_paths
                    if d and d != "/"):
                continue
            r = self.pages.get(url) or self.fetch(url)
            qy = urllib.parse.urlsplit(url).query
            if qy:
                names = [kv.split("=")[0] for kv in qy.split("&") if kv]
                self.params.setdefault(url, [])
                for n in names:
                    if n not in self.params[url]:
                        self.params[url].append(n)
            if r is None or r.status >= 400:
                continue
            pages += 1
            body = r.text
            if "exposures" in SCENARIOS.get(self.args.scenario, []) and (
                    "index of /" in body.lower()
                    or "directory listing for" in body.lower()):
                self.add("dir-listing", url=url, evidence=title_of(body))
            try:
                parser = PageParser()
                parser.feed(body)
            except Exception:
                continue
            if r.header("content-type").startswith("text/html") or \
               "<html" in body[:500].lower():
                if parser.titles:
                    self.recon.append(
                        ("page", f"{url} :: {parser.titles.strip()[:60]}"))
                for form in parser.forms:
                    self.forms.append({**form, "page": url})
                for link in parser.links:
                    absu = urllib.parse.urljoin(url, link)
                    if self.t.in_scope(absu):
                        self._queue(absu, queue)
                for sc, _i, _c in parser.scripts:
                    if not sc:
                        continue
                    a = urllib.parse.urljoin(url, sc).split("#")[0]
                    if self.t.in_scope(a) and re.search(r"\.m?js($|\?)", a, re.I):
                        self.script_urls.add(a)

    def _ingest_js(self, base_url, text):
        for rx in JS_EP_RES:
            for m in rx.finditer(text):
                if len(self.endpoints) >= 60:
                    return
                cand = m.group(1)
                absu = urllib.parse.urljoin(base_url, cand).split("#")[0]
                if not self.t.in_scope(absu):
                    continue
                pu = urllib.parse.urlsplit(absu)
                if re.search(r"\.(css|png|jpe?g|svg|woff2?|ico|gif|map)$",
                             pu.path, re.I):
                    continue
                self.endpoints.add(absu)
                self._queue(absu)
                if pu.query:
                    names = [kv.split("=")[0] for kv in pu.query.split("&") if kv]
                    self.params.setdefault(absu, [])
                    for n in names:
                        if n not in self.params[absu]:
                            self.params[absu].append(n)

    def _wayback(self):
        cdx = ("https://web.archive.org/cdx/search/cdx?url=" + self.t.host +
               "/*&output=json&fl=original&collapse=urlkey&limit=1000"
               "&filter=statuscode:200")
        try:
            status, body = self.t.request_external(cdx)
        except BudgetExceeded:
            raise
        except Exception as e:
            self.note(f"wayback lookup failed: {e}")
            return
        if status != 200:
            self.note(f"wayback CDX returned {status}")
            return
        try:
            rows = json.loads(body.decode("utf-8", "replace"))
        except Exception:
            self.note("wayback CDX response unparseable")
            return
        if not rows:
            self.recon.append(("wayback historical urls",
                               "0 archived snapshots for this host"))
            return
        hdr = rows[0]
        idx = hdr.index("original") if "original" in hdr else 0
        added = 0
        for row in rows[1:]:
            if not row:
                continue
            u = str(row[idx])
            if self.t.in_scope(u):
                before = len(self.urls)
                self._queue(u)
                added += len(self.urls) - before
        self.recon.append(("wayback historical urls",
                           f"{added} in-scope of {len(rows) - 1} archived"))
        self.note("wayback source: web.archive.org CDX (passive, read-only)")

    def _ct_log(self):
        parts = self.t.host.split(".")
        # shared public suffixes (github.io, netlify.app, ...) must not be
        # treated as the registrable domain: anchor on the full host instead
        dom = self.t.host if len(parts) >= 3 else ".".join(parts[-2:])
        url = "https://crt.sh/?q=" + urllib.parse.quote("%." + dom) +               "&output=json"
        names = set()
        errors = []
        # source 1: crt.sh (flaky by design; retried inside request_external)
        try:
            status, body = self.t.request_external(
                "https://crt.sh/?q=" + urllib.parse.quote("%." + dom) +
                "&output=json", cap=4_000_000)
            rows = json.loads(body.decode("utf-8", "replace"))
            for row in rows if isinstance(rows, list) else []:
                if isinstance(row, dict):
                    for nm in str(row.get("name_value", "")).split("\n"):
                        nm = nm.strip().lower().lstrip("*.")
                        if nm.endswith("." + dom) and nm != dom:
                            names.add(nm)
        except BudgetExceeded:
            raise
        except Exception as e:
            errors.append(f"crt.sh: {e}")
        # source 2: certspotter (verified reachable when crt.sh 502s)
        if not names:
            try:
                status, body = self.t.request_external(
                    "https://api.certspotter.com/v1/issuances?domain=" + dom +
                    "&include_subdomains=true&expand=dns_names", cap=2_000_000)
                rows = json.loads(body.decode("utf-8", "replace"))
                for row in rows if isinstance(rows, list) else []:
                    if isinstance(row, dict):
                        for nm in row.get("dns_names", []):
                            nm = str(nm).strip().lower().lstrip("*.")
                            if nm.endswith("." + dom) and nm != dom:
                                names.add(nm)
            except BudgetExceeded:
                raise
            except Exception as e:
                errors.append(f"certspotter: {e}")
        for msg in errors:
            self.note(f"ct source: {msg}")
        names = sorted(names)[:40]
        dead = 0
        for nm in names:
            try:
                socket.getaddrinfo(nm, None)
            except socket.gaierror:
                dead += 1
                self.add("subdomain-dangling", url="https://" + nm,
                         confidence="low",
                         evidence=f"in CT log for {dom} but no longer resolves",
                         detail="manual takeover claim-test required; this bot "
                                "only reports, never claims")
        self.recon.append(("ct-log subdomains",
                           f"{len(names)} names checked, {dead} unresolved"))
        self.note("ct-log source: crt.sh certificate transparency (passive)")

    def _queue(self, url, queue=None):
        u = url.split("#")[0]
        if self.t.in_scope(u):
            self.urls.add(u)
            if queue is not None:
                queue.append(u)

    def _robots_disallow(self):
        out = []
        rb = self.get(self.t.base + "/robots.txt")
        if rb and rb.status == 200:
            for line in rb.text.splitlines():
                if line.lower().startswith("disallow"):
                    p = line.split(":", 1)[-1].strip()
                    if p:
                        out.append(p)
        return out

    def scripts_of(self, page_url, body):
        return
